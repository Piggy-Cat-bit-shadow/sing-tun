package tun

// The batch's F1: sing-tun's netlink monitor goes quiet when its subscription dies.
//
// `loopRead` tolerates ENOBUFS, but for any other read error it logs once and returns; `Start` binds
// once and nothing reopens the socket, so after that no network-change event is ever reported again -
// the process keeps running with a monitor that is silently dead. Upstream #110 records the opposite
// symptom (a 100% CPU spin after the subscription closes); this fork traded the spin for silence, and
// neither satisfies "the event source must recover".
//
// The test kills the subscription the way an unrecoverable read error does - closing the socket from
// another goroutine - then makes a link change and requires an update. Run it against the pinned
// revision (no update: the monitor never reopens) and against the patched one.
//
// It needs root and Linux (netlink): `wsl -u root go test -run TestNetworkUpdateMonitorRecovers -v .`

import (
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing/common/logger"
	"github.com/stretchr/testify/require"
)

func drainUpdates(updates <-chan struct{}, wait time.Duration) {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		select {
		case <-updates:
		case <-timer.C:
			return
		}
	}
}

func TestNetworkUpdateMonitorRecoversAfterTheSubscriptionDies(t *testing.T) {
	if os.Getuid() != 0 {
		t.SkipNow()
	}
	monitor, err := NewNetworkUpdateMonitor(logger.NOP())
	require.NoError(t, err)
	updates := make(chan struct{}, 16)
	monitor.RegisterCallback(func() {
		select {
		case updates <- struct{}{}:
		default:
		}
	})
	require.NoError(t, monitor.Start())
	defer monitor.Close()
	drainUpdates(updates, 500*time.Millisecond)

	// Kill the subscription: every later read fails, which is the state an unrecoverable netlink error
	// leaves behind.
	require.NoError(t, monitor.(*networkUpdateMonitor).socket.Close())

	// Give a recovery loop time to reopen (the patched revision backs off about a second). On the
	// pinned revision nothing happens here, and the link change below is never seen.
	time.Sleep(2500 * time.Millisecond)
	drainUpdates(updates, 500*time.Millisecond)

	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "tunmonrec" + strconv.Itoa(os.Getpid())}}
	require.NoError(t, netlink.LinkAdd(link))
	defer netlink.LinkDel(link)

	select {
	case <-updates:
	case <-time.After(4 * time.Second):
		t.Fatal("no update after the subscription died: the monitor never reopened its netlink socket, " +
			"so every later network change is invisible until the process restarts")
	}
}
