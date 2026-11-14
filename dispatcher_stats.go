package tun

import "sync/atomic"

// DispatcherStats is the read-only view of the TUN packet dispatchers.
//
// # Why these counters exist
//
// The three resource layers of this process are not the same budget. This one counts LOGICAL
// dispatches: every TCP flow the tunnel hands to the handler, and how many of those are still being
// handled. It deliberately says nothing about sockets, TLS sessions or QUIC streams - those belong
// to the physical-creation and steady-state layers, and conflating them was what made "connection
// count" an unreliable proxy for memory.
//
// TCPAccepted is cumulative; TCPActive is the number of handler calls currently in flight. The
// counters are package-wide because a process runs one TUN stack; a second instance would be an
// embedding decision, not a hidden multiplier.
type DispatcherStats struct {
	TCPAccepted uint64
	TCPActive   int64
}

var (
	tcpDispatched atomic.Uint64
	tcpActive     atomic.Int64
)

// TCPDispatcherStats reports the dispatcher counters. Reading them takes no lock and allocates
// nothing, so a diagnostics path can call it without perturbing the flow it is observing.
func TCPDispatcherStats() DispatcherStats {
	return DispatcherStats{
		TCPAccepted: tcpDispatched.Load(),
		TCPActive:   tcpActive.Load(),
	}
}

// goDispatch runs one handler call as the dispatcher always has - in its own goroutine - and keeps
// the counters honest: accepted is incremented before the goroutine starts, active is decremented
// when the handler returns.
//
// The decrement lives in the handler call, not around connection creation: a handler that returns
// immediately after handing the connection to another goroutine would make "active" mean "not yet
// dispatched", which is a different (and misleading) quantity.
func goDispatch(dispatch func()) {
	tcpDispatched.Add(1)
	tcpActive.Add(1)
	go func() {
		defer tcpActive.Add(-1)
		dispatch()
	}()
}
