package tun

// 1B red test: when an OUTBOUND queue returns device bytes, an inbound writer parked on
// the device byte budget is never notified, so it stays in inboundWritable.Wait until the
// device is closed even though the budget is free again.
//
// 1C red test: the device Close zeroes the total instead of releasing what the queues
// actually hold, so an extra caller-owned queue can still hold a datagram while the device
// reports zero.

import (
	"errors"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
)

// blockingOutboundHandler takes one batch, signals entry, then holds it until release.
type blockingOutboundHandler struct {
	entered chan struct{}
	release chan struct{}
}

func newBlockingOutboundHandler() *blockingOutboundHandler {
	return &blockingOutboundHandler{entered: make(chan struct{}), release: make(chan struct{})}
}

func (h *blockingOutboundHandler) handle(packets []*buf.Buffer) {
	select {
	case <-h.entered:
	default:
		close(h.entered)
	}
	<-h.release
	buf.ReleaseMulti(packets)
}

// TestMemoryTunOutboundReleaseWakesInboundByteWaiter is 1B: four 1 KiB datagrams sit in a
// caller-owned outbound queue (device budget full), an inbound 1 KiB WaitWritePackets
// parks, and releasing the outbound queue must wake the inbound writer.
func TestMemoryTunOutboundReleaseWakesInboundByteWaiter(t *testing.T) {
	handler := newBlockingOutboundHandler()
	memoryTun := NewMemoryTun(MemoryTunOptions{
		MTU:            1500,
		BatchSize:      8,
		MaxQueuedBytes: 4096,
		Outbound:       handler.handle,
	})
	memoryTun.attached.Store(true)
	t.Cleanup(func() { _ = memoryTun.Close() })
	queue := memoryTun.NewOutboundQueue(handler.handle)
	t.Cleanup(func() { _ = queue.Close() })

	// Get the handler blocked with one filler, so the next four stay in the rings.
	if err := queue.enqueue(buf.NewSize(500), nil, goOutboundDatagram, nil, 0); err != nil {
		t.Fatalf("filler enqueue: %v", err)
	}
	select {
	case <-handler.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the outbound handler never entered")
	}
	waitForBytes(t, "the filler to leave the rings", func() bool { return queue.QueuedBytes() == 0 })
	for index := range 4 {
		if err := queue.enqueue(buf.NewSize(1000), nil, goOutboundDatagram, nil, 0); err != nil {
			t.Fatalf("queue enqueue %d: %v", index, err)
		}
	}
	waitForBytes(t, "the device budget full", func() bool { return memoryTun.QueuedBytes() == 4000 })

	// The inbound writer parks: no ring space in the inbound ring and no byte room.
	packet := make([]byte, 1000)
	packet[0] = 0x45
	done := make(chan error, 1)
	go func() { done <- memoryTun.WaitWritePackets([][]byte{packet}) }()
	select {
	case err := <-done:
		t.Fatalf("WaitWritePackets returned %v while the device budget was full", err)
	case <-time.After(100 * time.Millisecond):
	}

	// Releasing the outbound queue returns 4 KiB to the shared budget. The inbound writer
	// must observe it.
	close(handler.release)
	// The queue's own ledger must drain; the device total then belongs to the inbound
	// frame the woken writer claims (asserted below), not to the outbound queue.
	waitForBytes(t, "the outbound queue to drain", func() bool { return queue.QueuedBytes() == 0 })
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the woken inbound writer returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("an outbound release did not wake the inbound byte waiter: device bytes %d, inbound ring %d",
			memoryTun.QueuedBytes(), memoryTun.inbound.count)
	}
	// The woken frame must actually be queued, not merely reported as written.
	memoryTun.inboundAccess.Lock()
	queued := memoryTun.inbound.count
	memoryTun.inboundAccess.Unlock()
	if queued != 1 {
		t.Fatalf("the woken writer left %d inbound frames, want 1", queued)
	}
	if got := memoryTun.QueuedBytes(); got != 1000 {
		t.Fatalf("device total %d after the wake, want the inbound frame's 1000", got)
	}
}

// TestMemoryTunInboundReleaseLetsOutboundProgress is the reverse direction: with the
// device budget held by inbound frames, an outbound enqueue is refused; after the inbound
// reader returns the reservations, the same enqueue succeeds.
func TestMemoryTunInboundReleaseLetsOutboundProgress(t *testing.T) {
	memoryTun := NewMemoryTun(MemoryTunOptions{
		MTU:            1500,
		BatchSize:      8,
		MaxQueuedBytes: 4096,
		Outbound:       func([]*buf.Buffer) {},
	})
	memoryTun.attached.Store(true)
	t.Cleanup(func() { _ = memoryTun.Close() })
	queue := memoryTun.NewOutboundQueue(func([]*buf.Buffer) {})
	t.Cleanup(func() { _ = queue.Close() })

	packet := make([]byte, 4000)
	packet[0] = 0x45
	accepted, err := memoryTun.WritePackets([][]byte{packet})
	if err != nil || accepted != 1 {
		t.Fatalf("inbound WritePackets = (%d, %v), want (1, nil)", accepted, err)
	}
	if err := queue.enqueue(buf.NewSize(500), nil, goOutboundDatagram, nil, 0); !errors.Is(err, errGoFrameDropped) {
		t.Fatalf("an enqueue with the device budget held by inbound frames returned %v, want errGoFrameDropped", err)
	}

	popInboundFrame(memoryTun)
	waitForBytes(t, "the inbound reservation returned", func() bool { return memoryTun.QueuedBytes() == 0 })
	if err := queue.enqueue(buf.NewSize(500), nil, goOutboundDatagram, nil, 0); err != nil {
		t.Fatalf("the enqueue after the inbound release: %v", err)
	}
}

// TestMemoryTunWaitWritePacketsRejectsAFrameLargerThanTheBudget pins the defined result
// for a frame that cannot ever fit: the blocking writer must return an error instead of
// parking forever.
func TestMemoryTunWaitWritePacketsRejectsAFrameLargerThanTheBudget(t *testing.T) {
	memoryTun := NewMemoryTun(MemoryTunOptions{MTU: 1500, BatchSize: 8, MaxQueuedBytes: 4096, Outbound: func([]*buf.Buffer) {}})
	memoryTun.attached.Store(true)
	t.Cleanup(func() { _ = memoryTun.Close() })

	packet := make([]byte, 5000)
	packet[0] = 0x45
	done := make(chan error, 1)
	go func() { done <- memoryTun.WaitWritePackets([][]byte{packet}) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("an oversized frame was accepted into a 4096-byte budget")
		}
		if !errors.Is(err, errFrameExceedsByteBudget) {
			t.Fatalf("oversized frame returned %v, want errFrameExceedsByteBudget", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WaitWritePackets parked forever on a frame larger than the whole budget")
	}
}
