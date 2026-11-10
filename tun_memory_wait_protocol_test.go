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
