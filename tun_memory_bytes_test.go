package tun

import (
	"errors"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
)

// The memory TUN's device-wide BYTE budget.
//
// The packet rings are bounded by COUNT (4 x batch inbound, 2 x batch per outbound ring),
// which at the 64 KiB maximum packet is tens of MiB for one device; and the outbound
// queues of a busy stack multiply it. The byte budget bounds what the packets represent,
// is reserved before a frame is accepted, and is returned when the frame leaves the queue
// (read by the stack, handed to the outbound handler, or dropped by Close).

func newByteBudgetMemoryTun(t *testing.T, maxQueuedBytes int, outbound func([]*buf.Buffer)) *MemoryTun {
	t.Helper()
	memoryTun := NewMemoryTun(MemoryTunOptions{
		MTU:            1500,
		BatchSize:      8,
		MaxQueuedBytes: maxQueuedBytes,
		Outbound:       outbound,
	})
	memoryTun.attached.Store(true)
	t.Cleanup(func() { memoryTun.Close() })
	return memoryTun
}

// popInboundFrame frees one inbound frame the way goMemoryIO.readBurst does: pop,
// release the byte reservation, wake the writers. Test-only helper, so the popped buffer's
// bookkeeping is explicit.
func popInboundFrame(memoryTun *MemoryTun) {
	memoryTun.inboundAccess.Lock()
	if !memoryTun.inbound.empty() {
		frame, _, _ := memoryTun.inbound.pop()
		memoryTun.releaseQueuedBytesLocked(int64(frame.Cap()))
		frame.Release()
		memoryTun.inboundWritable.Broadcast()
	}
	memoryTun.inboundAccess.Unlock()
}

// TestMemoryTunInboundByteCapDropsAndParks pins the inbound half: a 4 KiB budget accepts
// four 1000-byte frames even though the packet ring has room, drops the next, and parks a
// waiting writer until a frame leaves.
func TestMemoryTunInboundByteCapDropsAndParks(t *testing.T) {
	memoryTun := newByteBudgetMemoryTun(t, 4096, func([]*buf.Buffer) {})
	packet := make([]byte, 1000)
	packet[0] = 0x45

	accepted := 0
	for range 16 {
		count, err := memoryTun.WritePackets([][]byte{packet})
		if err != nil {
			t.Fatalf("WritePackets: %v", err)
		}
		accepted += count
	}
	if accepted != 4 {
		t.Fatalf("the byte budget accepted %d frames, want 4", accepted)
	}
	if got := memoryTun.QueuedBytes(); got != 4000 {
		t.Fatalf("queued bytes %d, want 4000", got)
	}
	if got := memoryTun.MaxQueuedBytes(); got != 4096 {
		t.Fatalf("reported cap %d, want 4096", got)
	}

	// A waiting writer parks until a frame is read out.
	done := make(chan error, 1)
	go func() { done <- memoryTun.WaitWritePackets([][]byte{packet}) }()
	select {
	case err := <-done:
		t.Fatalf("WaitWritePackets returned %v while the byte budget was full", err)
	case <-time.After(100 * time.Millisecond):
	}
	popInboundFrame(memoryTun)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the woken writer returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("freeing a frame did not wake the byte-budget waiter")
	}
	if got := memoryTun.QueuedBytes(); got != 4000 {
		t.Fatalf("queued bytes %d after the wake, want the budget held at 4 frames", got)
	}
}

// TestMemoryTunOutboundByteCapDrops pins the outbound half: a queue whose handler has
// stopped draining cannot accept more than the device budget, and every refusal is the
// documented drop error rather than a silent overrun.
func TestMemoryTunOutboundByteCapDrops(t *testing.T) {
	entered := make(chan struct{})
	hold := make(chan struct{})
	handler := func(packets []*buf.Buffer) {
		select {
		case <-entered:
		default:
			close(entered)
		}
		<-hold
		buf.ReleaseMulti(packets)
	}
	memoryTun := newByteBudgetMemoryTun(t, 4096, handler)
	queue := memoryTun.NewOutboundQueue(handler)
	defer queue.Close()

	// One filler drives the handler's loop into the blocked handler call. The loop takes
	// whatever is queued when it wakes, so a single filler guarantees the rings are empty
	// (and the whole 4 KiB budget free) once the handler is entered.
	if err := queue.enqueue(buf.NewSize(500), nil, goOutboundDatagram, nil, 0); err != nil {
		t.Fatalf("filler enqueue: %v", err)
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the outbound handler never started")
	}
	waitForBytes(t, "the handler's batch to leave the rings", func() bool { return queue.QueuedBytes() == 0 })

	accepted, refused := 0, 0
	for range 8 {
		err := queue.enqueue(buf.NewSize(1000), nil, goOutboundDatagram, nil, 0)
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, errGoFrameDropped):
			refused++
		default:
			t.Fatalf("unexpected enqueue error: %v", err)
		}
	}
	if accepted != 4 || refused != 4 {
		t.Fatalf("enqueue accepted %d and refused %d, want 4 and 4 under a 4 KiB budget", accepted, refused)
	}
	if got := queue.QueuedBytes(); got != 4000 {
		t.Fatalf("queue bytes %d, want 4000", got)
	}
	if got := memoryTun.QueuedBytes(); got != 4000 {
		t.Fatalf("device bytes %d, want the queue's 4000", got)
	}

	close(hold)
	waitForBytes(t, "the queue to drain", func() bool {
		return queue.QueuedBytes() == 0 && memoryTun.QueuedBytes() == 0
	})
}

// TestMemoryTunQueuedBytesReturnToZeroOnClose pins the teardown: whatever the device still
// holds is released on Close, so the budget does not leak across a restart.
func TestMemoryTunQueuedBytesReturnToZeroOnClose(t *testing.T) {
	hold := make(chan struct{})
	handler := func(packets []*buf.Buffer) {
		<-hold
		buf.ReleaseMulti(packets)
	}
	memoryTun := NewMemoryTun(MemoryTunOptions{MTU: 1500, BatchSize: 8, MaxQueuedBytes: 1 << 20, Outbound: handler})
	memoryTun.attached.Store(true)
	queue := memoryTun.NewOutboundQueue(handler)

	packet := make([]byte, 1000)
	packet[0] = 0x45
	if _, err := memoryTun.WritePackets([][]byte{packet, packet}); err != nil {
		t.Fatalf("WritePackets: %v", err)
	}
	for range 8 {
		if err := queue.enqueue(buf.NewSize(1000), nil, goOutboundDatagram, nil, 0); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}
	if got := memoryTun.QueuedBytes(); got == 0 {
		t.Fatal("nothing was queued: the test would pass vacuously")
	}
	// Keep the handler blocked for the comparison: a draining queue would move both
	// counters between the two reads and make the equality a scheduling race.
	if err := memoryTun.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// The caller-owned queue still holds its datagrams until it is closed itself; the
	// device total must reflect that (only the default queue and the inbound ring are the
	// device's to release). Both counters are read under the queue lock: the queue loop
	// pops (and releases) between two unlocked reads, which is a test race, not a defect.
	queue.access.Lock()
	deviceAfter := memoryTun.QueuedBytes()
	queueAfter := int(queue.queuedBytes)
	queue.access.Unlock()
	if deviceAfter != queueAfter {
		t.Fatalf("device total %d after Close, want the caller queue's %d", deviceAfter, queueAfter)
	}
	if err := queue.Close(); err != nil {
		t.Fatalf("queue Close: %v", err)
	}
	if got := memoryTun.QueuedBytes(); got != 0 {
		t.Fatalf("queued bytes %d after the caller queue closed, want 0", got)
	}
	close(hold)
	if got := memoryTun.MaxQueuedBytes(); got != 1<<20 {
		t.Fatalf("reported cap %d, want 1048576", got)
	}
	// Second Close must not double-release or panic.
	if err := memoryTun.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestMemoryTunByteBudgetDefaults pins the policy default and that a device without an
// explicit budget still has one (the packet counts alone are not a memory bound).
func TestMemoryTunByteBudgetDefaults(t *testing.T) {
	memoryTun := NewMemoryTun(MemoryTunOptions{MTU: 1500})
	t.Cleanup(func() { _ = memoryTun.Close() })
	if got := memoryTun.MaxQueuedBytes(); got != DefaultMemoryTunMaxQueuedBytes {
		t.Fatalf("default cap %d, want %d", got, DefaultMemoryTunMaxQueuedBytes)
	}
	if got := memoryTun.QueuedBytes(); got != 0 {
		t.Fatalf("a fresh device holds %d bytes", got)
	}
}
