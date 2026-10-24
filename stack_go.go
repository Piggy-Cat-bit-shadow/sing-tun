package tun

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

type Go struct {
	ctx                    context.Context
	tun                    Tun
	mtu                    int
	handler                Handler
	logger                 logger.Logger
	broadcastAddr          netip.Addr
	inet4LoopbackAddress   []netip.Addr
	inet6LoopbackAddress   []netip.Addr
	icmpTimeout            time.Duration
	udpNATOptions          UDPNatOptions
	memoryPressure         func() MemoryPressure
	udpNats                []*UDPNat
	fragmentIdentification atomic.Uint32
	dispatcher             *ForwardDispatcher
	directory              goFlowDirectory
	congestion             *goCongestionOps
	queueFactory           func(stack *Go) ([]goPlatformIO, error)
	// access is the publish lock: Start, Close, ResetNetwork and selectEngine take it. It guards
	// started and every resource Start publishes, so a reader that holds it sees either nothing or a
	// complete publish.
	access sync.Mutex
	// started records that Start published successfully. Start owns it: it is written only by Start,
	// only while access is held, and only after the resources are published and the engines are
	// running. closed is the opposite bit and is owned by Close; when both are set, closed wins.
	started          bool
	engines          []*goEngine
	closed           atomic.Bool
	validateChecksum bool
}

func NewGo(options StackOptions) (*Go, error) {
	congestion, err := goLookupCongestionControl(options.TCPCongestionControl)
	if err != nil {
		return nil, err
	}
	stack := &Go{
		congestion:           congestion,
		queueFactory:         newGoPlatformQueues,
		ctx:                  options.Context,
		tun:                  options.Tun,
		mtu:                  int(options.TunOptions.MTU),
		handler:              options.Handler,
		logger:               options.Logger,
		broadcastAddr:        BroadcastAddr(options.TunOptions.Inet4Address),
		inet4LoopbackAddress: options.TunOptions.Inet4LoopbackAddress,
		inet6LoopbackAddress: options.TunOptions.Inet6LoopbackAddress,
		icmpTimeout:          options.ICMPTimeout,
		udpNATOptions: UDPNatOptions{
			Timeout:         options.UDPTimeout,
			Mapping:         options.UDPMapping,
			Filtering:       options.UDPFiltering,
			MaxSize:         options.UDPNATMax,
			InterfaceFinder: options.InterfaceFinder,
		},
		memoryPressure: options.MemoryPressure,
		directory: goFlowDirectory{
			flows:      make(map[flowKey]*GoConn),
			udpSockets: make(map[netip.AddrPort]*GoUDPConn),
			listeners:  make(map[netip.AddrPort]*GoListener),
			tcpLocals:  make(map[netip.AddrPort]uint32),
			reserved:   make(map[goPortKey]struct{}),
		},
	}
	memoryTun, isMemoryTun := options.Tun.(*MemoryTun)
	if isMemoryTun {
		stack.validateChecksum = true
		stack.queueFactory = func(current *Go) ([]goPlatformIO, error) {
			return []goPlatformIO{&goMemoryIO{stack: current, tun: memoryTun, handed: make([]*buf.Buffer, 0, goReadBatch), blocked: make(map[*OutboundQueue]*goBlockedWriters)}}, nil
		}
	}
	return stack, nil
}

// Ownership
//
// Two things are owned here, and they have different owners.
//
// The started resources - s.udpNats, s.dispatcher, s.engines and the directory map Start sizes - are
// owned by Start. It is the only writer. It publishes them while holding s.access, and it publishes
// all of them before it creates any engine goroutine, so every goroutine Start creates observes the
// complete published state without further synchronisation. The slice is filled in before it is
// reachable from anywhere else; publishing it half-built would let a concurrent reader dereference a
// nil engine.
//
// The started state is owned by Close. s.closed is its decision bit, and Close sets it while holding
// s.access, before it reads or tears down anything.
//
// Start and Close meet on s.access, and that is what makes Close win. Start checks s.closed in the
// same critical section in which it would publish, so a Start that loses the race publishes nothing
// and a Start that was refused cannot leave a resource behind. Close sets s.closed and takes its
// snapshot of the published resources in one critical section, so that snapshot is either empty
// (Start never published, and its own check now refuses to) or complete (Start published, and
// everything it published is torn down by this Close call). There is no window in which Start can
// publish after Close has decided to stop.
//
// Close releases s.access before it waits for the engines to exit. It must: the wait is on the
// engine goroutines, and holding the publish lock through a shutdown would block ResetNetwork and
// any later Start behind it. The wait itself is on the state Close already took, so nothing can
// change under it - a second Close returns early on the CAS, and Start cannot publish again.
//
// The deadlock rule for s.access: a holder may only wait on something that does not itself wait on
// s.access. Start holds it while it builds the queues and launches the engines, and nothing else
// waits on Start. Close holds it only while it snapshots and posts a close message, and postMessage
// never takes s.access (a lock-free push, a non-blocking wake, and for an already-exited engine a
// drain under the per-connection locks); it drops the lock before it waits for an engine to exit. So
// Close never waits on an engine while holding the lock, Start never waits on Close, and there is no
// path where each holds what the other needs.
func (s *Go) Start() error {
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed.Load() {
		// Close won. Refuse before the queue factory runs, so a refused Start creates nothing that
		// would then have to be undone, and nothing can come back to life after Close returned.
		return os.ErrClosed
	}
	if s.started {
		// A duplicate Start. The stack is already up, so this is a no-op rather than a second
		// publish that would leak the first set of engines.
		return nil
	}
	queues, err := s.queueFactory(s)
	if err != nil {
		return err
	}
	for index, queue := range queues {
		err = queue.start()
		if err == nil {
			continue
		}
		if index > 0 && errors.Is(err, errGoQueueUnavailable) {
			queues = queues[:index]
			break
		}
		return E.Errors(err, goCloseQueues(queues[:index]))
	}
	natCount := uint32(1)
	var udpNats []*UDPNat
	if s.handler != nil {
		udpNATOptions := s.udpNATOptions
		udpNATOptions.Handler = s.handler
		udpNATOptions.Prepare = s.prepareUDPConnection
		maxSize := udpNATOptions.MaxSize
		if maxSize == 0 {
			if runtime.GOOS == "ios" {
				maxSize = 4096
			} else {
				maxSize = 16384
			}
		}
		if udpNATOptions.Mapping == NATMappingAddressAndPortDependent {
			natCount = min(uint32(len(queues)), maxSize)
		}
		udpNats = make([]*UDPNat, natCount)
		for index := range udpNats {
			udpNATOptions.Shared = index+int(natCount) < len(queues)
			udpNATOptions.MaxSize = maxSize / natCount
			if uint32(index) < maxSize%natCount {
				udpNATOptions.MaxSize++
			}
			udpNat := NewUDPNat(udpNATOptions)
			err = udpNat.Start()
			if err != nil {
				udpNat.Close()
				for _, started := range udpNats[:index] {
					started.Close()
				}
				return E.Errors(err, goCloseQueues(queues))
			}
			udpNats[index] = udpNat
		}
		s.dispatcher = NewForwardDispatcher(s.handler, &goWriteback{platformIO: queues[0]}, s.logger, s.udpNATOptions, s.icmpTimeout)
	}
	s.udpNats = udpNats
	if natCount > 1 {
		s.directory.udpFlows = make(map[udpNatSessionKey]*GoPacketConn)
	}
	s.engines = make([]*goEngine, len(queues))
	for index, queue := range queues {
		s.engines[index] = newGoEngine(s, queue, len(queues))
		if udpNats != nil {
			s.engines[index].udpNat = udpNats[index%int(natCount)]
		}
	}
	for _, engine := range s.engines {
		go engine.run()
	}
	s.started = true
	return nil
}

func goCloseQueues(queues []goPlatformIO) error {
	var err error
	for _, queue := range queues {
		err = E.Errors(err, queue.close())
	}
	return err
}

func (s *Go) HasEndpoint(protocol uint8, local, remote netip.AddrPort) bool {
	if s.closed.Load() || !local.IsValid() || !remote.IsValid() {
		return false
	}
	local = netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	if local.Addr().Is4() != remote.Addr().Is4() {
		return false
	}
	s.directory.access.RLock()
	defer s.directory.access.RUnlock()
	switch protocol {
	case uint8(header.TCPProtocolNumber):
		return s.directory.flows[flowKey{protocol: protocol, source: remote, destination: local}] != nil || s.directory.listeners[local] != nil
	case uint8(header.UDPProtocolNumber):
		socket := s.directory.udpSockets[local]
		return socket != nil && (!socket.connected || socket.remote == remote)
	default:
		return false
	}
}

type goPortKey struct {
	protocol uint8
	local    netip.AddrPort
}

type goFlowDirectory struct {
	access     sync.RWMutex
	flows      map[flowKey]*GoConn
	udpFlows   map[udpNatSessionKey]*GoPacketConn
	udpSockets map[netip.AddrPort]*GoUDPConn
	listeners  map[netip.AddrPort]*GoListener
	tcpLocals  map[netip.AddrPort]uint32
	reserved   map[goPortKey]struct{}
}

func (d *goFlowDirectory) reservedLocked(protocol uint8, local netip.AddrPort) bool {
	_, reserved := d.reserved[goPortKey{protocol: protocol, local: local}]
	return reserved
}

func (d *goFlowDirectory) insertListenerLocked(listener *GoListener) {
	if len(listener.engine.stack.engines) > 1 {
		listener.engine.tcpListeners[listener.local] = listener
	}
	d.listeners[listener.local] = listener
}

func (d *goFlowDirectory) removeListener(listener *GoListener) {
	d.access.Lock()
	if len(listener.engine.stack.engines) > 1 && listener.engine.tcpListeners[listener.local] == listener {
		delete(listener.engine.tcpListeners, listener.local)
	}
	if d.listeners[listener.local] == listener {
		delete(d.listeners, listener.local)
	}
	d.access.Unlock()
}

func (d *goFlowDirectory) lookupListener(local netip.AddrPort) *GoListener {
	d.access.RLock()
	listener := d.listeners[local]
	d.access.RUnlock()
	return listener
}

func (d *goFlowDirectory) insertUDPSocketLocked(socket *GoUDPConn) {
	if len(socket.engine.stack.engines) > 1 {
		socket.engine.udpSockets[socket.local] = socket
	}
	d.udpSockets[socket.local] = socket
}

func (d *goFlowDirectory) removeUDPSocket(socket *GoUDPConn) {
	d.access.Lock()
	if len(socket.engine.stack.engines) > 1 && socket.engine.udpSockets[socket.local] == socket {
		delete(socket.engine.udpSockets, socket.local)
	}
	if d.udpSockets[socket.local] == socket {
		delete(d.udpSockets, socket.local)
	}
	d.access.Unlock()
}

func (d *goFlowDirectory) lookupUDPSocket(local netip.AddrPort) *GoUDPConn {
	d.access.RLock()
	socket := d.udpSockets[local]
	d.access.RUnlock()
	return socket
}

func (d *goFlowDirectory) insert(key flowKey, conn *GoConn) {
	d.access.Lock()
	d.insertLocked(key, conn)
	d.access.Unlock()
}

func (d *goFlowDirectory) insertLocked(key flowKey, conn *GoConn) {
	if len(conn.engine.stack.engines) > 1 {
		conn.engine.flows[key] = conn
	}
	_, exists := d.flows[key]
	if !exists {
		d.tcpLocals[key.destination]++
	}
	d.flows[key] = conn
}

func (d *goFlowDirectory) remove(key flowKey, conn *GoConn) {
	d.access.Lock()
	if len(conn.engine.stack.engines) > 1 && conn.engine.flows[key] == conn {
		delete(conn.engine.flows, key)
	}
	if d.flows[key] == conn {
		delete(d.flows, key)
		if d.tcpLocals[key.destination] > 1 {
			d.tcpLocals[key.destination]--
		} else {
			delete(d.tcpLocals, key.destination)
		}
	}
	d.access.Unlock()
}

func (d *goFlowDirectory) lookup(key flowKey) *GoConn {
	d.access.RLock()
	conn := d.flows[key]
	d.access.RUnlock()
	return conn
}

func (s *Go) ReserveSelector(protocol uint8, address netip.AddrPort) bool {
	directory := &s.directory
	directory.access.Lock()
	defer directory.access.Unlock()
	switch protocol {
	case uint8(header.UDPProtocolNumber):
		if directory.udpSockets[address] != nil {
			return false
		}
	case uint8(header.TCPProtocolNumber):
		if directory.listeners[address] != nil || directory.tcpLocals[address] > 0 {
			return false
		}
	default:
		return true
	}
	directory.reserved[goPortKey{protocol: protocol, local: address}] = struct{}{}
	return true
}

func (s *Go) ReleaseSelector(protocol uint8, address netip.AddrPort) {
	s.directory.access.Lock()
	delete(s.directory.reserved, goPortKey{protocol: protocol, local: address})
	s.directory.access.Unlock()
}

func (s *Go) ResetNetwork() {
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed.Load() {
		return
	}
	for _, udpNat := range s.udpNats {
		udpNat.Purge()
	}
	s.dispatcher.ResetNetwork()
	for _, engine := range s.engines {
		engine.postMessage(&engine.resetMessage)
	}
}

func (s *Go) Close() error {
	s.access.Lock()
	if !s.closed.CompareAndSwap(false, true) {
		s.access.Unlock()
		return nil
	}
	// Snapshot under the lock Start publishes under, and not before: the CAS above is the decision
	// that Start can no longer publish, so what is read here is final. Reading the fields again after
	// the unlock is what raced with a late Start, and reading a half-built engine slice is what
	// panicked.
	engines := s.engines
	udpNats := s.udpNats
	dispatcher := s.dispatcher
	for _, engine := range engines {
		engine.postMessage(&engine.closeMessage)
	}
	s.access.Unlock()
	// From here on work from the snapshot. s.access is released so the wait below cannot block the
	// publish lock, and the snapshot is what this Close owns: a refused Start never writes these
	// fields, so there is no state left to observe.
	for _, engine := range engines {
		<-engine.exitSignal
	}
	if dispatcher != nil {
		dispatcher.Close()
	}
	for _, udpNat := range udpNats {
		udpNat.Close()
	}
	var err error
	for _, engine := range engines {
		err = E.Errors(err, engine.platformIO.close())
	}
	return err
}
