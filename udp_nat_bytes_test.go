package tun

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// The UDP NAT queue's BYTE budget.
//
// The per-session queue has always been bounded by packet COUNT (64), which at the 64 KiB
// maximum datagram is 4 MiB of retained datagrams for ONE session; the number of sessions
// is bounded by MaxSize. Bytes are the resource that matters, so both a per-session and a
// NAT-wide byte cap are reserved before a datagram is accepted, and the reservation is
// returned when the datagram is read or discarded. The drop counters carry packets AND
// bytes, which is what makes the accounting an identity:
//
//	accepted == delivered + dropped + queued
//
// A gated handler keeps the queue still while the assertions read it: the caps are only
// meaningful against a consumer that is not draining.

// gatedNatHandler starts one reader per session but holds it until release, so queued
// datagrams stay queued.
type gatedNatHandler struct {
	release   chan struct{}
	started   atomic.Int64
	delivered atomic.Int64
}

func (h *gatedNatHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.started.Add(1)
	go func() {
		defer func() {
			if onClose != nil {
				onClose(nil)
			}
		}()
		<-h.release
		buffer := buf.NewSize(64 * 1024)
		defer buffer.Release()
		for {
			_, err := conn.ReadPacket(buffer)
			if err != nil {
				return
			}
			h.delivered.Add(1)
			buffer.Reset()
		}
	}()
}

// newByteBudgetNAT builds a NAT with the byte caps under test and a prepare function that
// accepts every destination.
func newByteBudgetNAT(t *testing.T, perSession, shared int, handler N.UDPConnectionHandlerEx) *UDPNat {
	t.Helper()
	upstream := &natStressUpstream{}
	nat := NewUDPNat(UDPNatOptions{
		Handler: handler,
		Prepare: func(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return true, context.Background(), upstream, func(error) {}
		},
		Timeout:            time.Minute,
		Mapping:            NATMappingEndpointIndependent,
		Filtering:          NATFilteringEndpointIndependent,
		MaxSize:            64,
		MaxBytesPerSession: perSession,
		MaxBytes:           shared,
	})
	if err := nat.Start(); err != nil {
		t.Fatalf("start the NAT: %v", err)
	}
	t.Cleanup(func() { _ = nat.Close() })
	return nat
}

// sendSizedPacket routes one datagram of size bytes from the given source port.
func sendSizedPacket(nat *UDPNat, sourcePort uint16, destination string, size int) {
	payload := make([]byte, size)
	source := M.SocksaddrFrom(netip.MustParseAddr("192.0.2.10"), sourcePort)
	nat.NewPacket([][]byte{payload}, source, M.ParseSocksaddr(destination), nil)
}

func waitForBytes(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestUDPNatSessionByteCapDropsAndConserves pins the per-session cap: 4 KiB datagrams
// stop being accepted at the byte cap even though the 64-packet channel has room, and the
// accepted/delivered/dropped/queued identity closes before and after the consumer drains.
func TestUDPNatSessionByteCapDropsAndConserves(t *testing.T) {
	handler := &gatedNatHandler{release: make(chan struct{})}
	nat := newByteBudgetNAT(t, 16*1024, 1<<20, handler)
	droppedBytesBefore := UDPNatDroppedBytes()
	droppedPacketsBefore := UDPNatDroppedPackets()

	const datagram = 4 * 1024
	const accepted = 4 // 16 KiB cap
	for index := 0; index < 8; index++ {
		sendSizedPacket(nat, 41000, "203.0.113.10:443", datagram)
	}
	waitForBytes(t, "the handler to start", func() bool { return handler.started.Load() == 1 })

	queued := nat.QueuedBytes()
	if queued != accepted*datagram {
		t.Fatalf("queued bytes %d, want %d", queued, accepted*datagram)
	}
	if got := UDPNatDroppedBytes() - droppedBytesBefore; got != uint64((8-accepted)*datagram) {
		t.Fatalf("dropped bytes %d, want %d", got, (8-accepted)*datagram)
	}
	if got := UDPNatDroppedPackets() - droppedPacketsBefore; got != 8-accepted {
		t.Fatalf("dropped packets %d, want %d", got, 8-accepted)
	}

	// Drain: every accepted datagram is delivered and the queue charge returns to zero.
	close(handler.release)
	waitForBytes(t, "the queue to drain", func() bool { return nat.QueuedBytes() == 0 })
	if delivered := handler.delivered.Load(); delivered != accepted {
		t.Fatalf("delivered %d datagrams, want %d", delivered, accepted)
	}
	// Conservation over the whole experiment: 8 accepted, 4 delivered, 4 dropped.
	if got := nat.QueuedBytes(); got != 0 {
		t.Fatalf("queued %d after draining", got)
	}
	if delivered, dropped := handler.delivered.Load(), int64(UDPNatDroppedPackets()-droppedPacketsBefore); delivered+dropped != 8 {
		t.Fatalf("delivered %d + dropped %d != 8 datagrams", delivered, dropped)
	}
}

// TestUDPNatSharedByteCapAcrossSessions pins the NAT-wide cap: three sessions of 8 KiB
// against a 16 KiB shared budget accept exactly two and drop the third, even though each
// is far below its per-session cap and the packet channel has room.
func TestUDPNatSharedByteCapAcrossSessions(t *testing.T) {
	handler := &gatedNatHandler{release: make(chan struct{})}
	nat := newByteBudgetNAT(t, 64*1024, 16*1024, handler)
	droppedBytesBefore := UDPNatDroppedBytes()

	const datagram = 8 * 1024
	sendSizedPacket(nat, 42001, "203.0.113.11:443", datagram)
	sendSizedPacket(nat, 42002, "203.0.113.11:443", datagram)
	sendSizedPacket(nat, 42003, "203.0.113.11:443", datagram)
	waitForBytes(t, "both sessions to start", func() bool { return handler.started.Load() == 3 })

	if got := nat.QueuedBytes(); got != 16*1024 {
		t.Fatalf("shared queued bytes %d, want 16384", got)
	}
	if got := UDPNatDroppedBytes() - droppedBytesBefore; got != datagram {
		t.Fatalf("dropped bytes %d, want the third datagram %d", got, datagram)
	}
	if got := nat.MaxQueuedBytes(); got != 16*1024 {
		t.Fatalf("reported shared cap %d, want 16384", got)
	}

	close(handler.release)
	waitForBytes(t, "the shared budget to drain", func() bool { return nat.QueuedBytes() == 0 })
	if delivered := handler.delivered.Load(); delivered != 2 {
		t.Fatalf("delivered %d datagrams, want 2", delivered)
	}
}

// TestUDPNatCloseReleasesQueuedBytes pins the teardown path: datagrams still queued when
// the NAT closes are counted as dropped bytes AND returned to the shared budget, so a
// closed NAT leaves no charge behind.
func TestUDPNatCloseReleasesQueuedBytes(t *testing.T) {
	handler := &gatedNatHandler{release: make(chan struct{})}
	nat := newByteBudgetNAT(t, 64*1024, 1<<20, handler)
	droppedBytesBefore := UDPNatDroppedBytes()

	const datagram = 4 * 1024
	for index := 0; index < 4; index++ {
		sendSizedPacket(nat, uint16(43000+index), "203.0.113.12:443", datagram)
	}
	waitForBytes(t, "the queue to fill", func() bool { return nat.QueuedBytes() == 4*datagram })

	if err := nat.Close(); err != nil {
		t.Fatalf("close the NAT: %v", err)
	}
	if got := nat.QueuedBytes(); got != 0 {
		t.Fatalf("queued bytes %d after Close, want 0", got)
	}
	if got := UDPNatDroppedBytes() - droppedBytesBefore; got != 4*datagram {
		t.Fatalf("dropped bytes %d after Close, want %d", got, 4*datagram)
	}
	// Closing again must not double-release or panic.
	if err := nat.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if got := nat.QueuedBytes(); got != 0 {
		t.Fatalf("queued bytes %d after the second Close", got)
	}
}

// TestUDPNatByteCapsAreOptional pins backward compatibility: a bare conn (no caps) keeps
// the packet-count behaviour, and a NAT built with the defaults applies the production
// byte caps.
func TestUDPNatByteCapsAreOptional(t *testing.T) {
	bare := &UDPNatConn{packetChan: make(chan *N.PacketBuffer, 2), doneChan: make(chan struct{})}
	bare.enqueue(buf.NewSize(16), M.Socksaddr{})
	if got := bare.QueuedBytes(); got != 0 {
		t.Fatalf("a conn without caps accounted %d bytes", got)
	}
	nat := newByteBudgetNAT(t, 0, 0, &gatedNatHandler{release: make(chan struct{})})
	if got := nat.MaxQueuedBytes(); got != DefaultUDPNatMaxBytes {
		t.Fatalf("default shared cap %d, want %d", got, DefaultUDPNatMaxBytes)
	}
	// The per-session default is applied to newly created sessions.
	conn, _ := nat.cache.Peek(udpNatSessionKey{})
	_ = conn
	sendSizedPacket(nat, 44000, "203.0.113.13:443", 1)
	waitForBytes(t, "a session", func() bool { return nat.QueuedBytes() == 1 })
}
