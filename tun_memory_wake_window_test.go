package tun

// The two wake windows between a failed byte reservation and the engine's registration:
//
//  1. A release lands AFTER the reservation failed but BEFORE the interest is published.
//     The notifier cannot see the interest yet, so its notification is lost. Publishing
//     and then RETRYING the reservation must observe the release and queue the frame.
//  2. A release lands AFTER the interest is published but BEFORE armTransmitWritable
//     registers the blocked-writer group. The notifier clears the interest and queues the
//     queue, but the group does not exist yet. The arm must re-observe the budget after
//     registering the group and hand it to the engine.
//
// The target queue's handler is parked with a filler before the test frame is enqueued, so
// the ring holds the frame and the assertions are not racing the queue's own drain.

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
)

// parkedQueue creates a queue whose handler is parked with a filler, so later enqueues
// stay in the ring instead of being delivered.
func parkedQueue(t *testing.T, device *MemoryTun) *OutboundQueue {
	t.Helper()
	handler := newBlockedHandler()
	queue := device.NewOutboundQueue(handler.handle)
	t.Cleanup(func() {
		select {
		case <-handler.release:
		default:
			close(handler.release)
		}
		_ = queue.Close()
	})
	if err := queue.enqueue(buf.NewSize(200), nil, goOutboundDatagram, nil, 0); err != nil {
		t.Fatalf("filler enqueue: %v", err)
	}
	select {
	case <-handler.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the queue handler never entered")
	}
	waitForBytes(t, "the filler to leave the rings", func() bool { return queue.QueuedBytes() == 0 })
	return queue
}

// TestReleaseInsideTheReservationWindowQueuesTheFrame is window 1: the release happens
// inside the failed-reservation-to-publish window (byteBlockedHook is that seam).
func TestReleaseInsideTheReservationWindowQueuesTheFrame(t *testing.T) {
	device := newCrossQueueDevice(t, 4000)
	// Park the target FIRST: its filler needs budget, and the extra queue is about to hold
	// all of it.
	target := parkedQueue(t, device)
	extra := parkedQueue(t, device)
	if err := extra.enqueue(buf.NewSize(3600), nil, goOutboundDatagram, nil, 0); err != nil {
		t.Fatalf("hold enqueue: %v", err)
	}
	waitForBytes(t, "the device budget held", func() bool { return device.QueuedBytes() == 3600 })

	var once sync.Once
	byteBlockedHook = func() {
		once.Do(func() {
			// The whole budget is released right after the target's reservation failed
			// and before its interest is visible.
			if err := extra.Close(); err != nil {
				t.Logf("close inside the window: %v", err)
			}
		})
	}
	t.Cleanup(func() { byteBlockedHook = nil })

	err := target.enqueue(buf.NewSize(1000), nil, goOutboundData, nil, 0)
	if err != nil {
		t.Fatalf("the frame was not queued by the retry after the in-window release: %v", err)
	}
	if got := target.data.count; got != 1 {
		t.Fatalf("the data ring holds %d frames, want 1", got)
	}
	if got := target.QueuedBytes(); got != 1000 {
		t.Fatalf("the queue holds %d bytes, want 1000", got)
	}
	// No extra release: the device holds exactly the queued frame, not less (a double
	// release) and not more (a phantom charge).
	if got := device.QueuedBytes(); got != 1000 {
		t.Fatalf("device total %d after the in-window release, want 1000", got)
	}
}

// TestReleaseBeforeArmStillDeliversTheGroup is window 2: the release happens after the
// interest is published (so the notifier consumes it) but before the engine registers the
// blocked-writer group.
func TestReleaseBeforeArmStillDeliversTheGroup(t *testing.T) {
	device := newCrossQueueDevice(t, 4000)
	target := parkedQueue(t, device)
	extra := parkedQueue(t, device)
	if err := extra.enqueue(buf.NewSize(3600), nil, goOutboundDatagram, nil, 0); err != nil {
		t.Fatalf("hold enqueue: %v", err)
	}
	waitForBytes(t, "the device budget held", func() bool { return device.QueuedBytes() == 3600 })

	// The target's data frame is refused and publishes its interest.
	if err := target.enqueue(buf.NewSize(1000), nil, goOutboundData, nil, 0); !errors.Is(err, errGoTransmitBlocked) {
		t.Fatalf("target data enqueue = %v, want errGoTransmitBlocked", err)
	}
	// The release happens now: the notifier sees the interest, clears it and queues the
	// queue - but no blocked-writer group exists yet.
	if err := extra.Close(); err != nil {
		t.Fatalf("extra queue Close: %v", err)
	}
	waitForBytes(t, "the release", func() bool { return device.QueuedBytes() == 0 })

	conn := &GoConn{}
	conn.outboundQueue.Store(target)
	io := &goMemoryIO{tun: device, blocked: make(map[*OutboundQueue]*goBlockedWriters)}
	waiters, armErr := io.armTransmitWritable(conn)
	if armErr != nil {
		t.Fatalf("armTransmitWritable: %v", armErr)
	}
	if waiters == nil {
		t.Fatal("the writer was not armed even though its frame is still blocked and the budget is free")
	}
	woken := io.takeTransmitWritable(nil)
	if len(woken) == 0 {
		t.Fatal("the arm did not re-queue the group after the release had already consumed the interest")
	}
	// The retry now fits and queues the original frame.
	if err := target.enqueue(buf.NewSize(1000), nil, goOutboundData, nil, 0); err != nil {
		t.Fatalf("the retry after the early release: %v", err)
	}
	if got := target.data.count; got != 1 {
		t.Fatalf("the data ring holds %d frames, want 1", got)
	}
	if got := target.QueuedBytes(); got != 1000 {
		t.Fatalf("the target holds %d bytes, want 1000", got)
	}
}
