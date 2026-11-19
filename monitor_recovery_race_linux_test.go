package tun

// The review found a window the recovery patch left open: loopRead opens a replacement socket, and
// before it installs it Close can run. setSocket then stores a socket on a monitor that has already
// closed its channel and taken its last socket, so nothing owns the new descriptor and the read loop
// resumes on a monitor the caller believes is closed.
//
// The test forces that interleaving instead of hoping for it: the recovery goroutine pauses in the
// hook after openSocket and before setSocket, the test runs Close in that window, and the install
// that follows must be refused. Assertions: nothing is installed after Close, the opened socket was
// closed by the losing recovery, and no update is emitted afterwards.
//
// It needs root and Linux (netlink), like the recovery test:
//   wsl -u root go test -run TestNetworkUpdateMonitorDoesNotInstallASocketAfterClose -v .

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	"github.com/stretchr/testify/require"
)

func TestNetworkUpdateMonitorDoesNotInstallASocketAfterClose(t *testing.T) {
	if os.Getuid() != 0 {
		t.SkipNow()
	}
	monitor, err := NewNetworkUpdateMonitor(logger.NOP())
	require.NoError(t, err)
	m := monitor.(*networkUpdateMonitor)

	updates := make(chan struct{}, 16)
	m.RegisterCallback(func() {
		select {
		case updates <- struct{}{}:
		default:
		}
	})

	opened := make(chan *os.File, 1)
	release := make(chan struct{})
	m.beforeInstallSocket = func(socket *os.File) {
		opened <- socket
		<-release
	}

	require.NoError(t, m.Start())
	defer func() { _ = m.Close() }()
	drainUpdates(updates, 500*time.Millisecond)

	// Kill the subscription the way an unrecoverable read error does, then wait until the recovery
	// goroutine has opened a replacement and is holding it in the hook before installation.
	require.NoError(t, m.socketFile().Close())
	var replacement *os.File
	select {
	case replacement = <-opened:
	case <-time.After(10 * time.Second):
		t.Fatal("the recovery loop never opened a replacement socket")
	}

	closeErr := m.Close()
	require.True(t, closeErr == nil || errors.Is(closeErr, os.ErrClosed),
		"Close returned an unexpected error: %v", closeErr)
	close(release)

	require.Eventually(t, func() bool {
		_, err := replacement.Read(make([]byte, 1))
		return errors.Is(err, os.ErrClosed)
	}, 2*time.Second, 10*time.Millisecond, "the replacement socket was not closed by the losing install")

	require.Nil(t, m.socketFile(), "a socket was installed after Close returned")

	select {
	case <-updates:
		t.Fatal("an update was emitted after Close")
	case <-time.After(1500 * time.Millisecond):
	}
}
