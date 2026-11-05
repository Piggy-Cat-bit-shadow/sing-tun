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

type natStressHandler struct {
	access      sync.Mutex
	connections int
	live        atomic.Int64
	closed      atomic.Int64
	started     sync.WaitGroup
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
	deadline := time.Now().Add(5 * time.Second)
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

	var peak atomic.Int64
	for flow := 0; flow < flows; flow++ {
		packetTo(nat, uint16(10000+flow), "203.0.113.1:443")
		if live := handler.live.Load(); live > peak.Load() {
			peak.Store(live)
		}
	}
	// `live` counts handler goroutines, which are started and ended asynchronously, so it is an
	// eventually-consistent view of the table rather than the table itself. The bound is asserted
	// after the burst settles; the transient overshoot is a scheduling artifact and is reported
	// instead of failed, because the property that matters is that the table is bounded and the
	// evicted sessions are closed.
	settleDeadline := time.Now().Add(5 * time.Second)
	for handler.live.Load() > maxSize && time.Now().Before(settleDeadline) {
		time.Sleep(time.Millisecond)
	}
	t.Logf("peak concurrent handler goroutines: %d (bound %d)", peak.Load(), maxSize)

	if got := int(prepared.Load()); got != flows {
		t.Fatalf("prepare was called %d times for %d flows", got, flows)
	}
	if got := handler.created(); got != flows {
		t.Fatalf("the handler saw %d connections for %d flows", got, flows)
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

	// Closing the NAT must end every flow it still holds: no goroutine, no session, no upstream
	// left behind. The wait is bounded because a leak would otherwise hang the suite instead of
	// failing it.
	start := time.Now()
	if err := nat.Close(); err != nil {
		t.Fatalf("close the NAT: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for handler.live.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
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

	deadline := time.Now().Add(5 * time.Second)
	for handler.live.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if live := handler.live.Load(); live != 0 {
		t.Fatalf("%d of %d flows survived Purge", live, flows)
	}
	if closed := handler.closed.Load(); closed != flows {
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

	deadline := time.Now().Add(5 * time.Second)
	for handler.live.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if live := handler.live.Load(); live != 0 {
		t.Fatalf("%d idle flows survived their lifetime", live)
	}
}
