package tun

// The three waiter-ownership P1s from the 2026-11-10 audit, as long-lived regressions on
// the production entry points (enqueue, armTransmitWritable, Close, goMemoryIO.writeData):
//
//  1. the old size multiset reset itself on its 65th distinct size, dropping still-waiting
//     connections and making the wake path believe the smallest need was 2,063 B;
//  2. a repeated refusal accumulated a ghost entry per failure while a success removed only
//     one, so the queue kept waking for a connection that had already been served;
//  3. a connection migrating between queues decremented the NEW queue's count using the OLD
//     queue's size, deleting another live waiter from the new queue.
//
// With the waiter record embedded in the connection (one record, owned by exactly one
// queue, moved by the migration hook), all three must end with the real frame in the ring.

import (
	"errors"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
)

// fillHoldingQueue parks a queue and fills it with holdBytes of datagrams.
func fillHoldingQueue(t *testing.T, device *MemoryTun, holdBytes int) *OutboundQueue {
	t.Helper()
	queue := parkedQueue(t, device)
	if err := queue.enqueue(buf.NewSize(holdBytes), nil, goOutboundDatagram, nil, 0); err != nil {
		t.Fatalf("hold %d bytes: %v", holdBytes, err)
	}
	return queue
}

// TestWaitersSurviveManyDistinctSizes is P1-1: the 65th distinct blocked size must not
// erase the 1,000-byte waiter registered earlier.
func TestWaitersSurviveManyDistinctSizes(t *testing.T) {
	device := newCrossQueueDevice(t, 4000)
	target := parkedQueue(t, device)
	smallHolder := fillHoldingQueue(t, device, 1500)
	largeHolder := fillHoldingQueue(t, device, 2500)
	waitForBytes(t, "the budget held", func() bool { return device.QueuedBytes() == 4000 })

	connA := &GoConn{}
	connA.outboundQueue.Store(target)
	if err := target.enqueue(buf.NewSize(1000), nil, goOutboundData, connA, 0); !errors.Is(err, errGoTransmitBlocked) {
		t.Fatalf("writer A enqueue = %v, want errGoTransmitBlocked", err)
	}
	io := &goMemoryIO{tun: device, blocked: make(map[*OutboundQueue]*goBlockedWriters)}
	if waiters, armErr := io.armTransmitWritable(connA); armErr != nil || waiters == nil {
		t.Fatalf("writer A was not armed: (%v, %v)", waiters, armErr)
	}
	// 64 more writers with distinct sizes 2,000..2,063 push the old multiset over its bound.
	for index := 0; index < 64; index++ {
		conn := &GoConn{}
		conn.outboundQueue.Store(target)
		if err := target.enqueue(buf.NewSize(2000+index), nil, goOutboundData, conn, 0); !errors.Is(err, errGoTransmitBlocked) {
			t.Fatalf("size-%d writer enqueue = %v, want errGoTransmitBlocked", 2000+index, err)
		}
	}
	// Releasing 1,500 B fits writer A's 1,000 B frame.
	if err := smallHolder.Close(); err != nil {
		t.Fatalf("small holder Close: %v", err)
	}
	waitForBytes(t, "the 1,500 B release", func() bool { return device.QueuedBytes() == 2500 })
	if len(io.takeTransmitWritable(nil)) == 0 {
		t.Fatal("the 1,500 B release did not hand the group to the engine: the 1,000 B waiter was dropped by the size bound")
	}
	if err := target.enqueue(buf.NewSize(1000), nil, goOutboundData, connA, 0); err != nil {
		t.Fatalf("writer A's retry: %v", err)
	}
	if got := target.data.count; got != 1 {
		t.Fatalf("writer A's frame is not in the data ring (%d frames)", got)
	}
	_ = largeHolder
}

// TestRepeatedRefusalLeavesNoGhostNeed is P1-2: failing twice and then succeeding must not
// leave a stale 1,000-byte claim that keeps waking a 2,000-byte waiter.
func TestRepeatedRefusalLeavesNoGhostNeed(t *testing.T) {
	device := newCrossQueueDevice(t, 6000)
	target := parkedQueue(t, device)
	holder := fillHoldingQueue(t, device, 2000)
	largeHolder := fillHoldingQueue(t, device, 3000)
	smallHolder := fillHoldingQueue(t, device, 1000)
	waitForBytes(t, "the budget held", func() bool { return device.QueuedBytes() == 6000 })

	connA := &GoConn{}
	connA.outboundQueue.Store(target)
	// The same 1,000-byte writer is refused twice.
	for attempt := 0; attempt < 2; attempt++ {
		if err := target.enqueue(buf.NewSize(1000), nil, goOutboundData, connA, 0); !errors.Is(err, errGoTransmitBlocked) {
			t.Fatalf("attempt %d = %v, want errGoTransmitBlocked", attempt, err)
		}
	}
	// Releasing one 1,000-byte holder lets it succeed.
	if err := holder.Close(); err != nil {
		t.Fatalf("holder Close: %v", err)
	}
	waitForBytes(t, "the first release", func() bool { return device.QueuedBytes() == 4000 })
	if err := target.enqueue(buf.NewSize(1000), nil, goOutboundData, connA, 0); err != nil {
		t.Fatalf("writer A's success: %v", err)
	}
	// A now holds its 1,000 B frame; 1,000 B stay free.
	waitForBytes(t, "writer A charged", func() bool { return device.QueuedBytes() == 5000 })
	// Drop the wake that the release queued for A (A retried directly): the ghost check
	// below must observe only what happens after B blocks.
	io := &goMemoryIO{tun: device, blocked: make(map[*OutboundQueue]*goBlockedWriters)}
	_ = io.takeTransmitWritable(nil)
	// A 2,000-byte writer is now blocked with 1,000 B free.
	connB := &GoConn{}
	connB.outboundQueue.Store(target)
	if err := target.enqueue(buf.NewSize(2000), nil, goOutboundData, connB, 0); !errors.Is(err, errGoTransmitBlocked) {
		t.Fatalf("writer B enqueue = %v, want errGoTransmitBlocked", err)
	}
	if waiters, armErr := io.armTransmitWritable(connB); armErr != nil || waiters == nil {
		t.Fatalf("writer B was not armed: (%v, %v)", waiters, armErr)
	}
	// No release and no drain: the ghost 1,000-byte need must not deliver a group that
	// cannot progress. Four arm/take cycles must stay empty.
	for attempt := 0; attempt < 4; attempt++ {
		_, _ = io.armTransmitWritable(connB)
		if len(io.takeTransmitWritable(nil)) != 0 {
			t.Fatalf("attempt %d delivered a group although the 2,000-byte frame cannot fit", attempt)
		}
	}
	// Releasing the last 1,000 B leaves 2,000 B free: enough for writer B.
	if err := smallHolder.Close(); err != nil {
		t.Fatalf("small holder Close: %v", err)
	}
	waitForBytes(t, "the second release", func() bool { return device.QueuedBytes() == 4000 })
	deadline := time.Now().Add(2 * time.Second)
	for len(io.takeTransmitWritable(nil)) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("writer B was not woken after the budget freed")
		}
		time.Sleep(time.Millisecond)
	}
	if err := target.enqueue(buf.NewSize(2000), nil, goOutboundData, connB, 0); err != nil {
		t.Fatalf("writer B's retry: %v", err)
	}
	if got := target.data.count; got != 2 {
		t.Fatalf("the data ring holds %d frames, want A's and B's two", got)
	}
	_ = largeHolder
}

// TestMigrationKeepsTheNewQueuesWaiters is P1-3: a connection migrating to another queue
// must move its own record and must not remove that queue's other waiters.
func TestMigrationKeepsTheNewQueuesWaiters(t *testing.T) {
	var routed *OutboundQueue
	device := NewMemoryTun(MemoryTunOptions{
		MTU:            1500,
		BatchSize:      8,
		MaxQueuedBytes: 4000,
		Outbound:       func([]*buf.Buffer) {},
		Route:          func([]byte) *OutboundQueue { return routed },
	})
	device.attached.Store(true)
	t.Cleanup(func() { _ = device.Close() })

	target := parkedQueue(t, device) // queue A: the connection's first queue (default is unused)
	routed = parkedQueue(t, device)  // queue B: the migration destination
	holdX := fillHoldingQueue(t, device, 2800)
	holdY := fillHoldingQueue(t, device, 1000)
	holdZ := fillHoldingQueue(t, device, 200)
	_ = holdX
	waitForBytes(t, "the budget held", func() bool { return device.QueuedBytes() == 4000 })

	// B already has two live waiters: 1,000 B and 3,000 B.
	connW := &GoConn{}
	connW.outboundQueue.Store(routed)
	if err := routed.enqueue(buf.NewSize(1000), nil, goOutboundData, connW, 0); !errors.Is(err, errGoTransmitBlocked) {
		t.Fatalf("B's 1,000 B writer = %v", err)
	}
	connBig := &GoConn{}
	connBig.outboundQueue.Store(routed)
	if err := routed.enqueue(buf.NewSize(3000), nil, goOutboundData, connBig, 0); !errors.Is(err, errGoTransmitBlocked) {
		t.Fatalf("B's 3,000 B writer = %v", err)
	}
	// The migrating connection M waits on A for 1,000 B.
	connM := &GoConn{}
	connM.outboundQueue.Store(target)
	if err := target.enqueue(buf.NewSize(1000), nil, goOutboundData, connM, 0); !errors.Is(err, errGoTransmitBlocked) {
		t.Fatalf("M's first enqueue = %v", err)
	}
	io := &goMemoryIO{tun: device, blocked: make(map[*OutboundQueue]*goBlockedWriters)}
	if waiters, armErr := io.armTransmitWritable(connW); armErr != nil || waiters == nil {
		t.Fatalf("B's group was not armed: (%v, %v)", waiters, armErr)
	}
	// Release 200 B, then M writes 200 B through the routed path: this migrates M to B.
	if err := holdZ.Close(); err != nil {
		t.Fatalf("holdZ Close: %v", err)
	}
	waitForBytes(t, "the 200 B release", func() bool { return device.QueuedBytes() == 3800 })
	if err := io.writeData([][]byte{make([]byte, 200)}, ForwardFrameMeta{}, connM, 0); err != nil {
		t.Fatalf("M's migrated write: %v", err)
	}
	if got := connM.outboundQueue.Load(); got != routed {
		t.Fatalf("M did not migrate to queue B: %v", got)
	}
	waitForBytes(t, "M's frame charged", func() bool { return device.QueuedBytes() == 4000 })
	// Release 1,000 B: B's 1,000-byte waiter must be woken (the migrated M's record must not
	// have deleted it).
	if err := holdY.Close(); err != nil {
		t.Fatalf("holdY Close: %v", err)
	}
	waitForBytes(t, "the 1,000 B release", func() bool { return device.QueuedBytes() == 3000 })
	deadline := time.Now().Add(2 * time.Second)
	for len(io.takeTransmitWritable(nil)) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("B's live 1,000 B waiter was not woken: the migration removed the wrong record")
		}
		time.Sleep(time.Millisecond)
	}
	if err := routed.enqueue(buf.NewSize(1000), nil, goOutboundData, connW, 0); err != nil {
		t.Fatalf("B's 1,000 B retry: %v", err)
	}
	if got := routed.data.count; got != 2 {
		t.Fatalf("queue B's data ring holds %d frames, want M's 200 B frame and the 1,000 B retry", got)
	}
}
