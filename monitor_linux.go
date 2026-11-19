package tun

import (
	"errors"
	"os"
	"runtime"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"

	"golang.org/x/sys/unix"
)

const (
	netlinkGroups = unix.RTMGRP_LINK |
		unix.RTMGRP_IPV4_IFADDR |
		unix.RTMGRP_IPV6_IFADDR |
		unix.RTMGRP_IPV4_ROUTE |
		unix.RTMGRP_IPV6_ROUTE
	netlinkReceiveBufferSize = 1 << 20
)

type networkUpdateMonitor struct {
	socket       *os.File
	socketAccess sync.Mutex
	socketClosed bool
	update       chan struct{}
	close        chan struct{}
	closeOnce    sync.Once

	// beforeInstallSocket is a test hook. It runs on the recovery goroutine after a replacement
	// socket was opened and before it is installed, so a test can run Close inside that window.
	beforeInstallSocket func(*os.File)

	access    sync.Mutex
	callbacks list.List[NetworkUpdateCallback]
	logger    logger.Logger
}

var ErrNetlinkBanned = E.New(
	"netlink socket in Android is banned by Google, " +
		"use the root or system (ADB) user to run sing-box, " +
		"or switch to the sing-box Android graphical interface client",
)

func NewNetworkUpdateMonitor(logger logger.Logger) (NetworkUpdateMonitor, error) {
	monitor := &networkUpdateMonitor{
		update: make(chan struct{}, 1),
		close:  make(chan struct{}),
		logger: logger,
	}
	// check is netlink banned by google
	if runtime.GOOS == "android" {
		netlinkSocket, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM, unix.NETLINK_ROUTE)
		if err != nil {
			return nil, ErrNetlinkBanned
		}
		err = unix.Bind(netlinkSocket, &unix.SockaddrNetlink{
			Family: unix.AF_NETLINK,
		})
		unix.Close(netlinkSocket)
		if err != nil {
			return nil, ErrNetlinkBanned
		}
	}
	return monitor, nil
}

func (m *networkUpdateMonitor) Start() error {
	socket, err := m.openSocket()
	if err != nil {
		return err
	}
	if socket == nil {
		return nil
	}
	if !m.setSocket(socket) {
		return nil
	}
	go m.loopRead()
	go m.loopUpdate(time.Second)
	return nil
}

// openSocket creates and binds the subscription. A nil socket with a nil error means the platform
// refuses these netlink groups (gVisor does), which is a working monitor with nothing to report rather
// than a failure.
func (m *networkUpdateMonitor) openSocket() (*os.File, error) {
	netlinkSocket, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, E.Cause(err, "create netlink socket")
	}
	groups := uint32(netlinkGroups)
	if runtime.GOOS == "android" {
		groups |= unix.RTMGRP_IPV4_RULE | 1<<(unix.RTNLGRP_IPV6_RULE-1)
	}
	err = unix.Bind(netlinkSocket, &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: groups,
	})
	if err != nil {
		unix.Close(netlinkSocket)
		// gVisor rejects these netlink groups with EOPNOTSUPP, or EACCES in releases before 2025-11
		if E.IsMulti(err, unix.EOPNOTSUPP, unix.EACCES) {
			return nil, nil
		}
		return nil, E.Cause(err, "subscribe netlink groups")
	}
	err = unix.SetsockoptInt(netlinkSocket, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, netlinkReceiveBufferSize)
	if err != nil {
		unix.SetsockoptInt(netlinkSocket, unix.SOL_SOCKET, unix.SO_RCVBUF, netlinkReceiveBufferSize)
	}
	return os.NewFile(uintptr(netlinkSocket), "netlink"), nil
}

// setSocket installs a newly opened subscription unless the monitor is already closed. It reports
// whether the monitor now owns the socket. An installation that loses the race against Close closes
// the socket itself: the Close that won has already taken (and closed) whatever was installed, so
// this socket would otherwise be left open with no owner and no reader.
func (m *networkUpdateMonitor) setSocket(socket *os.File) bool {
	m.socketAccess.Lock()
	if m.socketClosed {
		m.socketAccess.Unlock()
		_ = socket.Close()
		return false
	}
	m.socket = socket
	m.socketAccess.Unlock()
	return true
}

func (m *networkUpdateMonitor) socketFile() *os.File {
	m.socketAccess.Lock()
	defer m.socketAccess.Unlock()
	return m.socket
}

func (m *networkUpdateMonitor) loopRead() {
	buffer := make([]byte, unix.Getpagesize())
	backoff := time.Second
	for {
		socket := m.socketFile()
		if socket == nil {
			return
		}
		_, err := socket.Read(buffer)
		if err == nil || errors.Is(err, unix.ENOBUFS) {
			backoff = time.Second
			select {
			case m.update <- struct{}{}:
			default:
			}
			continue
		}
		select {
		case <-m.close:
			return
		default:
		}
		// The subscription is gone: the kernel closed it, the socket was closed under us, or the read
		// failed unrecoverably. Returning here is what left the process with a monitor that never
		// reported anything again (upstream sing-tun #110, which this fork had traded for silence).
		m.logger.Error("read netlink socket: ", err)
		_ = socket.Close()
		recovered := false
		for !recovered {
			select {
			case <-m.close:
				return
			case <-time.After(backoff):
			}
			reopened, reopenErr := m.openSocket()
			if reopenErr != nil {
				m.logger.Error("reopen netlink socket: ", reopenErr)
			} else if reopened == nil {
				// The platform refuses the groups altogether; there is nothing to recover into.
				return
			} else {
				if m.beforeInstallSocket != nil {
					m.beforeInstallSocket(reopened)
				}
				if !m.setSocket(reopened) {
					// Close won the window between opening the replacement and installing it. The
					// socket is already closed by setSocket; nothing may resume reading.
					return
				}
				recovered = true
				continue
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
		}
		backoff = time.Second
		// One event after recovery, so the upper layer re-reads interfaces and routes that changed
		// while the subscription was dead.
		select {
		case <-m.close:
			return
		default:
		}
		select {
		case m.update <- struct{}{}:
		default:
		}
	}
}

func (m *networkUpdateMonitor) loopUpdate(minDuration time.Duration) {
	timer := time.NewTimer(minDuration)
	timer.Stop()
	defer timer.Stop()
	var (
		timerC  <-chan time.Time
		pending bool
	)
	for {
		select {
		case <-m.close:
			return
		case <-m.update:
		case <-timerC:
			if pending {
				m.emit()
				pending = false
				timer.Reset(minDuration)
				continue
			}
			timerC = nil
			continue
		}
		if timerC != nil {
			pending = true
			continue
		}
		m.emit()
		timer.Reset(minDuration)
		timerC = timer.C
	}
}

func (m *networkUpdateMonitor) Close() error {
	closedNow := false
	var closeErr error
	m.closeOnce.Do(func() {
		closedNow = true
		close(m.close)
		m.socketAccess.Lock()
		// Set before taking the socket: a recovery that installs concurrently must observe this and
		// close the socket it opened instead of leaving it installed on a closed monitor.
		m.socketClosed = true
		socket := m.socket
		m.socket = nil
		m.socketAccess.Unlock()
		if socket != nil {
			closeErr = socket.Close()
		}
	})
	if !closedNow {
		return os.ErrClosed
	}
	return closeErr
}
