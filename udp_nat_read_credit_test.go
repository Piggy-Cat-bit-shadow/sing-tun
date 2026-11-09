package tun

// 1A red test: the UDP NAT's FAST read paths (the single-packet waiter and the batch
// continuation) dequeue datagrams without returning their byte reservation, so a session
// and the NAT keep charging bytes that are no longer queued: the next datagram is dropped
// against a phantom charge and the NAT never returns to zero after the session closes.
//
// The ordinary ReadPacket path returns the reservation (it is the path the earlier byte
// tests exercised); these tests cover the two paths that pick the waiter instead.

import (
	"context"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// recordingNatHandler records the session conn and holds its reader until released, so the
// queue stays still while the test reads from the fast paths explicitly.
type recordingNatHandler struct {
	started chan struct{}
	release chan struct{}
	conn    *UDPNatConn
}

func newRecordingNatHandler() *recordingNatHandler {
	return &recordingNatHandler{started: make(chan struct{}), release: make(chan struct{})}
}

func (h *recordingNatHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	select {
	case <-h.started:
	default:
		if session, loaded := conn.(*UDPNatConn); loaded {
			h.conn = session
		}
		close(h.started)
	}
	<-h.release
}

// TestUDPNatWaiterReturnsTheQueuedBytes is the single-packet waiter path.
func TestUDPNatWaiterReturnsTheQueuedBytes(t *testing.T) {
	handler := newRecordingNatHandler()
	nat := newByteBudgetNAT(t, 2000, 4000, handler)
	droppedBefore := UDPNatDroppedPackets()

	sendSizedPacket(nat, 45001, "203.0.113.21:443", 1000)
	sendSizedPacket(nat, 45001, "203.0.113.21:443", 1000)
	waitForBytes(t, "two datagrams queued", func() bool { return nat.QueuedBytes() == 2000 })
	select {
	case <-handler.started:
	case <-time.After(2 * time.Second):
		t.Fatal("the session handler never started")
	}
	session := handler.conn
	if session == nil {
		t.Fatal("the handler recorded no session conn")
	}

	buffer, destination, err := session.WaitReadPacket()
	if err != nil {
		t.Fatalf("WaitReadPacket: %v", err)
	}
	if buffer.Len() != 1000 {
		t.Fatalf("read %d bytes, want 1000", buffer.Len())
	}
	if destination.String() != "203.0.113.21:443" {
		t.Fatalf("destination %s, want 203.0.113.21:443", destination)
	}
	buffer.Release()

	if got := nat.QueuedBytes(); got != 1000 {
		t.Fatalf("after one waiter read the NAT still holds %d bytes, want 1000: the waiter path did not return its reservation", got)
	}
	if got := session.QueuedBytes(); got != 1000 {
		t.Fatalf("the session holds %d bytes after the waiter read, want 1000", got)
	}

	// With the phantom charge removed the next datagram fits; with it still charged this
	// datagram is dropped.
	sendSizedPacket(nat, 45001, "203.0.113.21:443", 1000)
	waitForBytes(t, "the third datagram accepted", func() bool { return nat.QueuedBytes() == 2000 })
	if got := UDPNatDroppedPackets() - droppedBefore; got != 0 {
		t.Fatalf("%d datagrams dropped although the queue had room", got)
	}

	// Close returns the remaining queue to zero on both ledgers.
	_ = session.Close()
	waitForBytes(t, "close returns the queue", func() bool { return nat.QueuedBytes() == 0 })
	close(handler.release)
}

// TestUDPNatBatchContinuationReturnsTheQueuedBytes is the batch continuation path: the
// first packet comes from waitReadPacket and the rest from the loop that drains the queue.
func TestUDPNatBatchContinuationReturnsTheQueuedBytes(t *testing.T) {
	handler := newRecordingNatHandler()
	nat := newByteBudgetNAT(t, 2000, 4000, handler)

	sendSizedPacket(nat, 45002, "203.0.113.22:443", 1000)
	sendSizedPacket(nat, 45002, "203.0.113.22:443", 1000)
	waitForBytes(t, "two datagrams queued", func() bool { return nat.QueuedBytes() == 2000 })
	select {
	case <-handler.started:
	case <-time.After(2 * time.Second):
		t.Fatal("the session handler never started")
	}
	session := handler.conn
	if session == nil {
		t.Fatal("the handler recorded no session conn")
	}
	// A front-headroom request forces the copy branch of ReadWaitOptions.Copy as well.
	session.InitializeReadWaiter(N.ReadWaitOptions{BatchSize: 2, FrontHeadroom: 64})
	buffers, destinations, err := session.WaitReadPackets()
	if err != nil {
		t.Fatalf("WaitReadPackets: %v", err)
	}
	if len(buffers) != 2 {
		t.Fatalf("batch read %d packets, want 2", len(buffers))
	}
	for _, buffer := range buffers {
		if buffer.Len() != 1000 {
			t.Fatalf("batch packet length %d, want 1000", buffer.Len())
		}
		buffer.Release()
	}
	if destinations[0].String() != "203.0.113.22:443" {
		t.Fatalf("batch destination %s, want 203.0.113.22:443", destinations[0])
	}
	if got := nat.QueuedBytes(); got != 0 {
		t.Fatalf("after a full batch read the NAT holds %d bytes, want 0: the batch continuation did not return its reservations", got)
	}

	// The same NAT must keep accepting datagrams, and closing must not leave a residue.
	sendSizedPacket(nat, 45002, "203.0.113.22:443", 1000)
	waitForBytes(t, "a fresh datagram after the batch", func() bool { return nat.QueuedBytes() == 1000 })
	_ = session.Close()
	waitForBytes(t, "the session closed cleanly", func() bool { return nat.QueuedBytes() == 0 })
	close(handler.release)
}

// TestUDPNatBatchStopsAtTheQueuedPackets pins that a batch read may return fewer packets
// than BatchSize without waiting, and still settles every dequeued byte.
func TestUDPNatBatchStopsAtTheQueuedPackets(t *testing.T) {
	handler := newRecordingNatHandler()
	nat := newByteBudgetNAT(t, 4000, 4000, handler)
	sendSizedPacket(nat, 45003, "203.0.113.23:443", 1000)
	waitForBytes(t, "one datagram queued", func() bool { return nat.QueuedBytes() == 1000 })
	select {
	case <-handler.started:
	case <-time.After(2 * time.Second):
		t.Fatal("the session handler never started")
	}
	session := handler.conn
	if session == nil {
		t.Fatal("the handler recorded no session conn")
	}
	session.InitializeReadWaiter(N.ReadWaitOptions{BatchSize: 8})
	buffers, _, err := session.WaitReadPackets()
	if err != nil {
		t.Fatalf("WaitReadPackets: %v", err)
	}
	if len(buffers) != 1 {
		t.Fatalf("batch read %d packets, want the single queued one", len(buffers))
	}
	buffers[0].Release()
	if got := nat.QueuedBytes(); got != 0 {
		t.Fatalf("the batch left %d bytes charged", got)
	}
	_ = session.Close()
	close(handler.release)
}
