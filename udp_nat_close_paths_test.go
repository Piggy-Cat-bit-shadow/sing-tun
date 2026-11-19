package tun

// Three independent close paths for a UDP NAT entry, each asserted on its own after the audit pointed out
// that the first test (the idle sweep) did not cover them:
//
//	testTimeoutSweep   - the cleanup queue's timeout closes the entry
//	testExplicitClose  - the caller closes the connection directly
//	testCapacityEvict  - the LRU evicts the oldest entry when MaxSize is exceeded
//
// In every case the handler's context, derived from the entry by the patch, must be cancelled.

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

type discardingWriter struct{}

func (discardingWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	buffer.Release()
	return nil
}

// udpNatRecordingHandler gives each handler invocation its own done channel, in arrival order.
type udpNatRecordingHandler struct {
	index   atomic.Int32
	started chan struct{}
	dones   []chan struct{}
}

func newUDPNatRecordingHandler(count int) *udpNatRecordingHandler {
	handler := &udpNatRecordingHandler{started: make(chan struct{})}
	for index := 0; index < count; index++ {
		handler.dones = append(handler.dones, make(chan struct{}))
	}
	return handler
}

func (h *udpNatRecordingHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	index := int(h.index.Add(1)) - 1
	if index == 0 {
		close(h.started)
	}
	<-ctx.Done()
	if index < len(h.dones) {
		close(h.dones[index])
	}
	_ = conn.Close()
}

func (h *udpNatRecordingHandler) waitDone(t *testing.T, index int, message string) {
	t.Helper()
	select {
	case <-h.dones[index]:
	case <-time.After(2 * time.Second):
		t.Fatal(message)
	}
}

func newTestNAT(t *testing.T, handler *udpNatRecordingHandler, timeout time.Duration, maxSize uint32) *UDPNat {
	t.Helper()
	nat := NewUDPNat(UDPNatOptions{
		Handler: handler,
		Timeout: timeout,
		MaxSize: maxSize,
		Prepare: func(source, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return true, context.Background(), discardingWriter{}, nil
		},
	})
	if err := nat.Start(); err != nil {
		t.Fatal("start: ", err)
	}
	t.Cleanup(func() { _ = nat.Close() })
	return nat
}

func testFlow(port uint16) (M.Socksaddr, M.Socksaddr) {
	return M.SocksaddrFrom(netip.MustParseAddr("10.0.0.2"), port),
		M.SocksaddrFrom(netip.MustParseAddr("203.0.113.9"), 443)
}

// TestAnEvictedEntryCancelsTheDialItLaunched is the timeout-sweep path (the original evidence).
func TestAnEvictedEntryCancelsTheDialItLaunched(t *testing.T) {
	handler := newUDPNatRecordingHandler(1)
	nat := newTestNAT(t, handler, 50*time.Millisecond, 8)
	source, destination := testFlow(12345)
	nat.NewPacket([][]byte{[]byte("hello")}, source, destination, nil)
	<-handler.started
	time.Sleep(200 * time.Millisecond)
	nat.PurgeExpired()
	handler.waitDone(t, 0, "the timeout sweep did not cancel the handler's context")
}

// TestAnExplicitCloseCancelsTheDialItLaunched is the caller-driven path: the connection is closed
// directly, without waiting for any timer.
func TestAnExplicitCloseCancelsTheDialItLaunched(t *testing.T) {
	handler := newUDPNatRecordingHandler(1)
	nat := newTestNAT(t, handler, time.Hour, 8)
	source, destination := testFlow(12346)
	conn, ok := nat.getOrCreate(nat.sessionKey(source, destination), source, destination, nil, nil)
	if !ok {
		t.Fatal("the entry was not created")
	}
	<-handler.started
	if err := conn.Close(); err != nil {
		t.Fatal("close: ", err)
	}
	handler.waitDone(t, 0, "closing the entry did not cancel the handler's context")
}

// TestACapacityEvictionCancelsTheDialItLaunched is the third path: MaxSize is exceeded, the LRU evicts
// the oldest entry, and that entry's creation must end too.
func TestACapacityEvictionCancelsTheDialItLaunched(t *testing.T) {
	handler := newUDPNatRecordingHandler(2)
	nat := newTestNAT(t, handler, time.Hour, 1)
	firstSource, firstDestination := testFlow(12347)
	nat.NewPacket([][]byte{[]byte("first")}, firstSource, firstDestination, nil)
	<-handler.started

	// A second five-tuple with MaxSize 1 evicts the first entry.
	secondSource, secondDestination := testFlow(12348)
	nat.NewPacket([][]byte{[]byte("second")}, secondSource, secondDestination, nil)

	handler.waitDone(t, 0, "the capacity eviction did not cancel the evicted entry's context")
}
