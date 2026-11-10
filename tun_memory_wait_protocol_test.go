package tun

// Two regressions for the wait protocol:
//
//  - P1-A: armTransmitWritable's post-registration re-check must read the ring state under
//    the same lock the drain/pop path writes it under. The old code called data.full() in
//    the open, which races the pop that decrements the ring count (the race detector
//    reports it; the production consequence is a torn read deciding whether to wake).
//  - P1-B: the queue's wake decision must consider the SMALLEST blocked frame, not the
//    most recent one. A 3,000-byte refusal recorded after a 1,000-byte one must not hide
//    the 1,000-byte waiter when a 1,500-byte release arrives.

import (
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
)

// TestArmRecheckDoesNotRaceTheDrain drives the arm's re-check while the queue's own loop
// pops frames. Run with -race: the old open-coded data.full() read is reported here.
func TestArmRecheckDoesNotRaceTheDrain(t *testing.T) {
	device := newCrossQueueDevice(t, 4096)
	holder := parkedQueue(t, device)
	if err := holder.enqueue(buf.NewSize(4096), nil, goOutboundDatagram, nil, 0); err != nil {
		t.Fatalf("hold enqueue: %v", err)
	}
	waitForBytes(t, "the budget held", func() bool { return device.QueuedBytes() == 4096 })

	target := device.NewOutboundQueue(func(packets []*buf.Buffer) { buf.ReleaseMulti(packets) })
	t.Cleanup(func() { _ = target.Close() })
	conn := &GoConn{}
	conn.outboundQueue.Store(target)
	io := &goMemoryIO{tun: device, blocked: make(map[*OutboundQueue]*goBlockedWriters)}

	// Leave a blocked need on the target (the post-check branch requires one), then free
	// the budget so the target's loop can churn its ring concurrently.
	if err := target.enqueue(buf.NewSize(1000), nil, goOutboundData, conn, 0); !errors.Is(err, errGoTransmitBlocked) {
		t.Fatalf("target data enqueue = %v, want errGoTransmitBlocked", err)
	}
	if err := holder.Close(); err != nil {
		t.Fatalf("holder Close: %v", err)
	}
	waitForBytes(t, "the budget released", func() bool { return device.QueuedBytes() == 0 })

	// Sustained overlap, not a fixed iteration count: the enqueue/pop side and the arm
	// re-check side must run concurrently long enough for the race detector to see the
	// unsynchronized ring read.
	deadline := time.Now().Add(100 * time.Millisecond)
	var waitGroup sync.WaitGroup
	waitGroup.Add(2)
	go func() {
		defer waitGroup.Done()
		for time.Now().Before(deadline) {
			if err := target.enqueue(buf.NewSize(100), nil, goOutboundDatagram, nil, 0); err != nil {
				return
			}
			runtime.Gosched()
		}
	}()
	go func() {
		defer waitGroup.Done()
		for time.Now().Before(deadline) {
			_, _ = io.armTransmitWritable(conn)
			_ = io.takeTransmitWritable(nil)
			runtime.Gosched()
		}
	}()
	waitGroup.Wait()
}

// TestTheSmallestBlockedFrameIsNotMaskedByALargerOne is P1-B: the 1,000-byte waiter must
// make progress when 1,500 bytes are released even though a 3,000-byte frame was refused
// last.
func TestTheSmallestBlockedFrameIsNotMaskedByALargerOne(t *testing.T) {
	device := newCrossQueueDevice(t, 4000)
	target := parkedQueue(t, device)
	smallHolder := parkedQueue(t, device)
	largeHolder := parkedQueue(t, device)
	if err := smallHolder.enqueue(buf.NewSize(1500), nil, goOutboundDatagram, nil, 0); err != nil {
		t.Fatalf("small holder enqueue: %v", err)
	}
	if err := largeHolder.enqueue(buf.NewSize(2500), nil, goOutboundDatagram, nil, 0); err != nil {
		t.Fatalf("large holder enqueue: %v", err)
	}
	waitForBytes(t, "both holders charge the budget", func() bool { return device.QueuedBytes() == 4000 })

	smallConn := &GoConn{}
	smallConn.outboundQueue.Store(target)
	largeConn := &GoConn{}
	largeConn.outboundQueue.Store(target)

	// The 1,000-byte writer is refused, then the 3,000-byte writer is refused later: the
	// most recent refusal is the LARGER one, which is what the old single slot recorded.
	if err := target.enqueue(buf.NewSize(1000), nil, goOutboundData, smallConn, 0); !errors.Is(err, errGoTransmitBlocked) {
		t.Fatalf("small data enqueue = %v, want errGoTransmitBlocked", err)
	}
	if err := target.enqueue(buf.NewSize(3000), nil, goOutboundData, largeConn, 0); !errors.Is(err, errGoTransmitBlocked) {
		t.Fatalf("large data enqueue = %v, want errGoTransmitBlocked", err)
	}
	io := &goMemoryIO{tun: device, blocked: make(map[*OutboundQueue]*goBlockedWriters)}
	if waiters, armErr := io.armTransmitWritable(largeConn); armErr != nil || waiters == nil {
		t.Fatalf("the group was not armed: (%v, %v)", waiters, armErr)
	}

	// Release exactly 1,500 bytes: enough for the 1,000-byte frame, not for the 3,000-byte
	// one. The engine must receive the group so the small writer can retry.
	if err := smallHolder.Close(); err != nil {
		t.Fatalf("small holder Close: %v", err)
	}
	waitForBytes(t, "the small release", func() bool { return device.QueuedBytes() == 2500 })
	woken := io.takeTransmitWritable(nil)
	if len(woken) == 0 {
		t.Fatal("the 1,500-byte release did not hand the group to the engine: the 3,000-byte refusal masked the 1,000-byte waiter")
	}
	if err := target.enqueue(buf.NewSize(1000), nil, goOutboundData, smallConn, 0); err != nil {
		t.Fatalf("the small frame's retry: %v", err)
	}
	if got := target.data.count; got != 1 {
		t.Fatalf("the small retry left %d data frames, want 1", got)
	}
	// The large frame cannot fit yet (only 500 bytes free) and must stay blocked.
	if err := target.enqueue(buf.NewSize(3000), nil, goOutboundData, largeConn, 0); !errors.Is(err, errGoTransmitBlocked) {
		t.Fatalf("the large retry = %v, want errGoTransmitBlocked", err)
	}
	// Releasing the rest lets the large frame through.
	if err := largeHolder.Close(); err != nil {
		t.Fatalf("large holder Close: %v", err)
	}
	waitForBytes(t, "the large release", func() bool { return device.QueuedBytes() == 1000 })
	if err := target.enqueue(buf.NewSize(3000), nil, goOutboundData, largeConn, 0); err != nil {
		t.Fatalf("the large frame's retry after the full release: %v", err)
	}
	if got := target.data.count; got != 2 {
		t.Fatalf("the target holds %d data frames, want 2", got)
	}
	if got := device.QueuedBytes(); got != 4000 {
		t.Fatalf("device total %d, want both frames' 4000", got)
	}
}

// TestWaiterRecordIsPerConnectionAndIdempotent pins the ownership rule that replaces the
// former size multiset: one record per connection, updated in place on a repeated refusal
// (no accumulated ghosts), removed by dropWait, and the queue's minimum is computed from
// the live connections only.
func TestWaiterRecordIsPerConnectionAndIdempotent(t *testing.T) {
	device := newCrossQueueDevice(t, 4000)
	target := parkedQueue(t, device)
	conn := &GoConn{}
	conn.outboundQueue.Store(target)

	target.noteWait(conn, 2000)
	target.noteWait(conn, 1000) // same writer, smaller retry: update in place
	target.waitAccess.Lock()
	count := 0
	for entry := target.waitHead; entry != nil; entry = entry.waitNext {
		count++
	}
	target.waitAccess.Unlock()
	if count != 1 {
		t.Fatalf("the waiter list holds %d records for one connection, want 1", count)
	}
	if got := target.minWaitNeed(); got != 1000 {
		t.Fatalf("minWaitNeed = %d, want the single record's 1000", got)
	}
	// A second connection is a second record; the minimum is still exact.
	other := &GoConn{}
	other.outboundQueue.Store(target)
	target.noteWait(other, 3000)
	if got := target.minWaitNeed(); got != 1000 {
		t.Fatalf("minWaitNeed = %d after a second writer, want 1000", got)
	}
	target.dropWait(conn)
	if got := target.minWaitNeed(); got != 3000 {
		t.Fatalf("minWaitNeed = %d after the small writer left, want 3000", got)
	}
	target.dropWait(other)
	if got := target.minWaitNeed(); got != 0 {
		t.Fatalf("minWaitNeed = %d after all waiters left, want 0", got)
	}
}

// TestCancelClearsTheRecordedWait pins the queue-level revoke GoConn.Close performs: a
// cancelled writer's record leaves the list, so the queue's minimum moves on.
func TestCancelClearsTheRecordedWait(t *testing.T) {
	device := newCrossQueueDevice(t, 4000)
	target := parkedQueue(t, device)
	conn := &GoConn{}
	conn.outboundQueue.Store(target)
	target.noteWait(conn, 1000)
	if target.minWaitNeed() != 1000 {
		t.Fatalf("minWaitNeed = %d, want 1000", target.minWaitNeed())
	}
	// The same call GoConn.Close makes.
	target.dropWait(conn)
	if got := target.minWaitNeed(); got != 0 {
		t.Fatalf("a cancelled writer left its record behind: minWaitNeed = %d", got)
	}
}

// TestQueueCloseClearsEveryWaiter is the audit-de6d regression: closing a queue must clear
// EVERY connection's record, not just the list head, and each of those connections must be
// able to register a fresh record on another queue afterwards.
func TestQueueCloseClearsEveryWaiter(t *testing.T) {
	device := newCrossQueueDevice(t, 4000)
	holder := parkedQueue(t, device)
	queueA := parkedQueue(t, device)
	queueB := parkedQueue(t, device)
	if err := holder.enqueue(buf.NewSize(4000), nil, goOutboundDatagram, nil, 0); err != nil {
		t.Fatalf("hold enqueue: %v", err)
	}
	waitForBytes(t, "the budget held", func() bool { return device.QueuedBytes() == 4000 })
	conns := []*GoConn{{}, {}, {}}
	for index, conn := range conns {
		conn.outboundQueue.Store(queueA)
		if err := queueA.enqueue(buf.NewSize(1000), nil, goOutboundData, conn, 0); !errors.Is(err, errGoTransmitBlocked) {
			t.Fatalf("conn %d enqueue = %v, want errGoTransmitBlocked", index, err)
		}
	}
	if got := queueA.minWaitNeed(); got != 1000 {
		t.Fatalf("queue A minWaitNeed = %d, want 1000", got)
	}
	if err := queueA.Close(); err != nil {
		t.Fatalf("queue A Close: %v", err)
	}
	for index, conn := range conns {
		queueA.waitAccess.Lock()
		owned := conn.waitQueue
		need := conn.pendingNeed
		queueA.waitAccess.Unlock()
		if owned != nil || need != 0 {
			t.Fatalf("conn %d still owns a record after the close: queue=%p need=%d", index, owned, need)
		}
	}
	// Every cancelled connection can register on another queue.
	for index, conn := range conns {
		conn.outboundQueue.Store(queueB)
		if err := queueB.enqueue(buf.NewSize(1000), nil, goOutboundData, conn, 0); !errors.Is(err, errGoTransmitBlocked) {
			t.Fatalf("conn %d re-register = %v, want errGoTransmitBlocked", index, err)
		}
	}
	queueB.waitAccess.Lock()
	linked := 0
	for conn := queueB.waitHead; conn != nil; conn = conn.waitNext {
		linked++
	}
	queueB.waitAccess.Unlock()
	if linked != len(conns) {
		t.Fatalf("queue B holds %d of %d waiters: the close left stale ownership", linked, len(conns))
	}
	if got := queueB.minWaitNeed(); got != 1000 {
		t.Fatalf("queue B minWaitNeed = %d, want 1000", got)
	}
}

// TestWaitRegistrationRacesQueueCloseSafely is the concurrency half of the audit-de6d
// finding: registration/drop on one goroutine and the queue close on another must stay
// under waitAccess, leave consistent per-connection ownership and never panic.
func TestWaitRegistrationRacesQueueCloseSafely(t *testing.T) {
	device := newCrossQueueDevice(t, 4000)
	queue := parkedQueue(t, device)
	conns := make([]*GoConn, 8)
	for index := range conns {
		conns[index] = &GoConn{}
	}
	var waitGroup sync.WaitGroup
	for _, conn := range conns {
		waitGroup.Add(1)
		go func(conn *GoConn) {
			defer waitGroup.Done()
			for iteration := 0; iteration < 500; iteration++ {
				queue.noteWait(conn, int64(100+iteration))
				queue.dropWait(conn)
			}
		}(conn)
	}
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		_ = queue.Close()
	}()
	waitGroup.Wait()
	for index, conn := range conns {
		queue.waitAccess.Lock()
		owned, need := conn.waitQueue, conn.pendingNeed
		queue.waitAccess.Unlock()
		if (owned == nil) != (need == 0) {
			t.Fatalf("conn %d is inconsistent after the close: queue=%p need=%d", index, owned, need)
		}
	}
}
