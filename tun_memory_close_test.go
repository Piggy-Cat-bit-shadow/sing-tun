package tun

// 1C: the device Close must not zero the total while a caller-owned queue still holds a
// datagram; the queue's own Close is what returns the reservation.

import (
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
)

// TestMemoryTunCloseKeepsTheCallerQueueAccounting is 1C: closing the device must not zero
// the total while a caller-owned queue still holds a datagram. The extra queue's own Close
// is what returns its reservation.
func TestMemoryTunCloseKeepsTheCallerQueueAccounting(t *testing.T) {
	handler := newBlockingOutboundHandler()
	memoryTun := NewMemoryTun(MemoryTunOptions{
		MTU:            1500,
		BatchSize:      8,
		MaxQueuedBytes: 1 << 20,
		Outbound:       handler.handle,
	})
	memoryTun.attached.Store(true)
	queue := memoryTun.NewOutboundQueue(handler.handle)

	// Block the handler with a filler, then leave one datagram in the queue's ring.
	if err := queue.enqueue(buf.NewSize(500), nil, goOutboundDatagram, nil, 0); err != nil {
		t.Fatalf("filler enqueue: %v", err)
	}
	select {
	case <-handler.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the outbound handler never entered")
	}
	waitForBytes(t, "the filler to leave the rings", func() bool { return queue.QueuedBytes() == 0 })
	if err := queue.enqueue(buf.NewSize(1000), nil, goOutboundDatagram, nil, 0); err != nil {
		t.Fatalf("ring enqueue: %v", err)
	}
	waitForBytes(t, "one datagram held by the caller queue", func() bool { return memoryTun.QueuedBytes() == 1000 })

	if err := memoryTun.Close(); err != nil {
		t.Fatalf("device Close: %v", err)
	}
	// The device is closed, but the caller queue still owns its datagram: the total must
	// say so instead of pretending everything was released.
	if got := memoryTun.QueuedBytes(); got != 1000 {
		t.Fatalf("device total %d after Close while the caller queue holds 1000 bytes, want 1000", got)
	}
	close(handler.release)
	if err := queue.Close(); err != nil {
		t.Fatalf("queue Close: %v", err)
	}
	if got := memoryTun.QueuedBytes(); got != 0 {
		t.Fatalf("device total %d after the caller queue closed, want 0", got)
	}
}
