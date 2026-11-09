package tun

import (
	"context"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// The device diagnostic that started this work showed roughly two hundred UDP NAT flows in one
// burst, and the question it left open was whether that number is bounded by the NAT's own limits
// and whether the resources it creates actually go away again. Neither question needs a device: the
// NAT takes its handler and its upstream writer as arguments, so a test can drive thousands of flows
// through the real session table and count what it creates and what it closes.
//
// # What is injected, and what is real
//
// Real: the session table, its LRU bound, the lifetime, the eviction and close paths, the per-flow
// goroutine the NAT starts, and the packet queue.
//
// Injected: the upstream side. `Prepare` stands in for "open a transport to this destination" and
// returns a writer that discards; the handler stands in for "route this packet connection", so the
// test owns the read loop and can count it. This is the smallest fake that exercises the lifecycle
// the device runs.
//
// # Why the counts need barriers
//
// The handler runs on a goroutine the NAT starts from the cache-add path, and the drop counter is
// updated by the enqueue/close paths. A test that reads those counters the instant the last packet
// was written is therefore observing a MOMENT, not the settled state: the audit's unstable result
// (`Prepare` = 2000 while the handler had counted 1999) is exactly that race, not a lost flow. The
// burst test below separates the four properties explicitly:
//
//   - a creation barrier (wait for the handler to see every flow) before asserting anything about
//     handler counts;
//   - the session table itself (`nat.cache.Len()`) for the capacity bound, sampled during the burst,
//     because live handler goroutines are an eventually-consistent view and may exceed the bound
//     transiently while evicted sessions are still unwinding;
//   - every started handler ending (created == closed, live == 0) as the exit witness;
//   - packet accounting: each flow sends exactly one datagram, and the handler's reads plus the
//     NAT's drop counter must add up to the flows, so a silently stranded datagram fails the test.

type natStressHandler struct {
	access      sync.Mutex
	connections int
	live        atomic.Int64
	closed      atomic.Int64
	packets     atomic.Int64
}

func (h *natStressHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.access.Lock()
	h.connections++
	h.access.Unlock()
	h.live.Add(1)
	// Mirror what a real handler does with the connection: read until it ends, then report the
	// close. The NAT must make that happen for every flow it created, otherwise the goroutine and
	// the session leak together.
	go func() {
		defer func() {
			h.live.Add(-1)
			h.closed.Add(1)
			if onClose != nil {
				onClose(nil)
			}
		}()
		buffer := buf.NewSize(1024)
		defer buffer.Release()
		for {
			_, err := conn.ReadPacket(buffer)
			if err != nil {
				return
			}
			h.packets.Add(1)
			buffer.Reset()
		}
	}()
}

func (h *natStressHandler) created() int {
	h.access.Lock()
	defer h.access.Unlock()
	return h.connections
}

type natStressUpstream struct {
	written atomic.Int64
	closed  atomic.Int64
}

func (u *natStressUpstream) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	u.written.Add(int64(buffer.Len()))
	buffer.Release()
	return nil
}

func (u *natStressUpstream) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, io.ErrNoProgress
}

func (u *natStressUpstream) Close() error {
	u.closed.Add(1)
	return nil
}

func (u *natStressUpstream) SetDeadline(time.Time) error { return nil }

// newStressNAT builds a NAT whose upstream is fake and whose bound is small enough that a few
// thousand flows force eviction. The iOS bound is a build-time default chosen by GOOS, so the test
// sets it explicitly and asserts the eviction path rather than one platform's number.
func newStressNAT(t *testing.T, maxSize uint32, handler N.UDPConnectionHandlerEx) (*UDPNat, *natStressUpstream, *atomic.Uint64) {
	t.Helper()
	upstream := &natStressUpstream{}
	var prepared atomic.Uint64
	nat := NewUDPNat(UDPNatOptions{
		Handler: handler,
		Prepare: func(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			prepared.Add(1)
			return true, context.Background(), upstream, func(error) {}
		},
		Timeout:   time.Minute,
		Mapping:   NATMappingEndpointIndependent,
		Filtering: NATFilteringEndpointIndependent,
		MaxSize:   maxSize,
	})
	if err := nat.Start(); err != nil {
		t.Fatalf("start the NAT: %v", err)
	}
	t.Cleanup(func() { _ = nat.Close() })
	return nat, upstream, &prepared
}

// waitForStress fails the test rather than hanging when a property never becomes true. It is named
// apart from the package's other waitFor because this file must not shadow it.
func waitForStress(t *testing.T, condition func() bool, what string) {
	t.Helper()
	waitForStressWithin(t, 5*time.Second, condition, what)
}

func waitForStressWithin(t *testing.T, budget time.Duration, condition func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func packetTo(nat *UDPNat, sourcePort uint16, destination string) {
	payload := []byte("stress")
	source := M.SocksaddrFrom(netip.MustParseAddr("192.0.2.10"), sourcePort)
	nat.NewPacket([][]byte{payload}, source, M.ParseSocksaddr(destination), nil)
}

// TestUDPNatBurstKeepsTheSessionTableBounded drives more flows than the table can hold and asserts
// the property the device diagnostic needed: the number of LIVE sessions never exceeds the bound,
// however many arrive.
func TestUDPNatBurstKeepsTheSessionTableBounded(t *testing.T) {
	const (
		maxSize = 256
		flows   = 2000
	)
	handler := &natStressHandler{}
	nat, upstream, prepared := newStressNAT(t, maxSize, handler)
	droppedBefore := UDPNatDroppedPackets()

	// Capacity is a property of the TABLE, so it is sampled from the table: handler goroutines are
	// started and ended asynchronously and can transiently outnumber the bound while evicted
	// sessions unwind, which is why the audit saw 259 of a 256 bound.
	var peakTable int
	var peakHandlers int64
	for flow := 0; flow < flows; flow++ {
		packetTo(nat, uint16(10000+flow), "203.0.113.1:443")
		if table := nat.cache.Len(); table > peakTable {
			peakTable = table
		}
		if live := handler.live.Load(); live > peakHandlers {
			peakHandlers = live
		}
		if table := nat.cache.Len(); table > maxSize {
			t.Fatalf("the session table held %d sessions at flow %d, above its %d bound", table, flow, maxSize)
		}
	}
	t.Logf("peak session table: %d (bound %d); peak handler goroutines: %d (asynchronous view)",
		peakTable, maxSize, peakHandlers)

	if got := int(prepared.Load()); got != flows {
		t.Fatalf("prepare was called %d times for %d flows", got, flows)
	}
	// Creation barrier: the NAT starts the handler on its own goroutine, so the count is only
	// meaningful once every flow has been seen. Waiting here is what distinguishes "the handler
	// had not been called yet" from "a flow never reached the handler".
	waitForStress(t, func() bool { return handler.created() == flows },
		"every flow to reach the handler")
	// The bound is about sessions, not about goroutines: wait for the evicted sessions' handlers to
	// observe their closed connections before asserting the live count.
	waitForStress(t, func() bool { return handler.live.Load() <= maxSize },
		"evicted sessions' handlers to unwind")

	// Every handler that started is either still reading (a live session) or has ended (an evicted
	// one). Before Close, the live ones cannot have ended, so the exit witness below is taken after
	// the NAT close; here the invariant is that no handler is missing from that accounting.
	if created, closed, live := handler.created(), int(handler.closed.Load()), int(handler.live.Load()); created != closed+live {
		t.Fatalf("%d handlers started but %d ended and %d are live: a handler is missing", created, closed, live)
	}
	// Over the bound, eviction must close sessions, not merely forget them.
	if evicted := handler.closed.Load(); evicted == 0 {
		t.Fatalf("no session was evicted after %d flows with a bound of %d", flows, maxSize)
	}
	if live := handler.live.Load(); live > maxSize {
		t.Fatalf("%d sessions still live after the burst, above the bound", live)
	}
	if upstream.closed.Load() == 0 {
		t.Fatal("the evicted sessions never closed their upstream")
	}

	// Packet accounting: one datagram per flow arrived from the "TUN". Each one is either read by
	// its handler or counted as dropped by the NAT (queue full or teardown). A datagram that is
	// neither is a silent strand, which the close path used to leave uncounted.
	waitForStress(t, func() bool {
		return int(handler.packets.Load())+int(UDPNatDroppedPackets()-droppedBefore) >= flows
	}, "every datagram to be delivered or counted as dropped")
	delivered := int(handler.packets.Load())
	dropped := int(UDPNatDroppedPackets() - droppedBefore)
	if delivered+dropped != flows {
		t.Fatalf("packet accounting: %d delivered + %d dropped != %d flows", delivered, dropped, flows)
	}
	t.Logf("datagrams: %d delivered, %d dropped (of %d)", delivered, dropped, flows)

	// Closing the NAT must end every flow it still holds: no goroutine, no session, no upstream
	// left behind. The wait is bounded because a leak would otherwise hang the suite instead of
	// failing it.
	start := time.Now()
	if err := nat.Close(); err != nil {
		t.Fatalf("close the NAT: %v", err)
	}
	waitForStress(t, func() bool { return handler.live.Load() == 0 }, "every handler to exit")
	if created, closed := handler.created(), int(handler.closed.Load()); created != closed {
		t.Fatalf("%d handlers started but only %d ended after Close", created, closed)
	}
	if live := handler.live.Load(); live != 0 {
		t.Fatalf("%d packet connections outlived the NAT that created them", live)
	}
	t.Logf("closed %d sessions (%d flows, bound %d) in %s",
		handler.closed.Load(), flows, maxSize, time.Since(start).Round(time.Millisecond))
}

// TestUDPNatTwoHundredFlowsLeaveNothingBehind is the diagnostic's own number, with the stronger
// assertion the burst test cannot make: every session is closed explicitly, and the count returns to
// zero without relying on eviction.
func TestUDPNatTwoHundredFlowsLeaveNothingBehind(t *testing.T) {
	const flows = 200
	handler := &natStressHandler{}
	nat, _, prepared := newStressNAT(t, 4096, handler)

	for flow := 0; flow < flows; flow++ {
		packetTo(nat, uint16(20000+flow), "203.0.113.2:3478")
	}
	if got := int(prepared.Load()); got != flows {
		t.Fatalf("prepare was called %d times for %d flows", got, flows)
	}

	nat.Purge()

	waitForStress(t, func() bool { return handler.live.Load() == 0 }, "every flow to close")
	waitForStress(t, func() bool { return int(handler.closed.Load()) == flows }, "every closed flow to be counted")
	if live := handler.live.Load(); live != 0 {
		t.Fatalf("%d of %d flows survived Purge", live, flows)
	}
	if closed := int(handler.closed.Load()); closed != flows {
		t.Fatalf("%d sessions reported closed, want %d", closed, flows)
	}
}

// TestUDPNatLifetimeReclaimsIdleFlows proves the other half of "bounded": a flow nobody touches is
// reclaimed by its lifetime, not only by the size bound.
func TestUDPNatLifetimeReclaimsIdleFlows(t *testing.T) {
	handler := &natStressHandler{}
	upstream := &natStressUpstream{}
	nat := NewUDPNat(UDPNatOptions{
		Handler: handler,
		Prepare: func(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return true, context.Background(), upstream, func(error) {}
		},
		Timeout:   300 * time.Millisecond,
		Mapping:   NATMappingEndpointIndependent,
		Filtering: NATFilteringEndpointIndependent,
		MaxSize:   64,
	})
	if err := nat.Start(); err != nil {
		t.Fatalf("start the NAT: %v", err)
	}
	defer nat.Close()

	for flow := 0; flow < 8; flow++ {
		packetTo(nat, uint16(30000+flow), "203.0.113.3:443")
	}
	// The handler runs on its own goroutine, so the last flow may not have entered it yet. Wait for
	// the count to reach 8 rather than asserting the moment the last packet was written.
	waitForStress(t, func() bool { return handler.live.Load() == 8 }, "8 flows to reach the handler")

	time.Sleep(400 * time.Millisecond)
	nat.PurgeExpired()

	waitForStress(t, func() bool { return handler.live.Load() == 0 }, "every idle flow to expire")
	if live := handler.live.Load(); live != 0 {
		t.Fatalf("%d idle flows survived their lifetime", live)
	}
}
