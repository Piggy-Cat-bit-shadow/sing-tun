package tun

// Debug matrix rows that the first pass did not hit directly:
//
//  - a byte-blocked FRAGMENT GROUP: the need is the whole group, a partial release keeps
//    it waiting, the full release lets the group enqueue and the accounting is the group's;
//  - ring-full with bytes to spare, and ring-full together with byte-full: both arm the
//    writer, a drain frees them, the original frame retries and enqueues;
//  - closing one queue wakes only its own blocked writer (cancellation), not a waiter in
//    another queue of the same device.

import (
	"errors"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
)

// TestFragmentGroupNeedAndRetry pins the fragment path: the recorded need is the sum of
// the fragments' reserved bytes, not one fragment's size.
func TestFragmentGroupNeedAndRetry(t *testing.T) {
	device := newCrossQueueDevice(t, 4000)
	target := parkedQueue(t, device)
	holder := parkedQueue(t, device)
	if err := holder.enqueue(buf.NewSize(4000), nil, goOutboundDatagram, nil, 0); err != nil {
		t.Fatalf("hold enqueue: %v", err)
	}
	waitForBytes(t, "the budget held", func() bool { return device.QueuedBytes() == 4000 })

	conn := &GoConn{}
	conn.outboundQueue.Store(target)
	fragments := [][]byte{make([]byte, 1000), make([]byte, 1000), make([]byte, 1000)}
	if err := target.enqueue(buf.NewSize(1), fragments, goOutboundData, conn, 0); !errors.Is(err, errGoTransmitBlocked) {
		t.Fatalf("fragment group enqueue = %v, want errGoTransmitBlocked", err)
	}
	if got := target.minNeed(); got != 3000 {
		t.Fatalf("the group need is %d, want the fragments' 3000", got)
	}
	io := &goMemoryIO{tun: device, blocked: make(map[*OutboundQueue]*goBlockedWriters)}
	if waiters, armErr := io.armTransmitWritable(conn); armErr != nil || waiters == nil {
		t.Fatalf("the fragment writer was not armed: (%v, %v)", waiters, armErr)
	}

	if err := holder.Close(); err != nil {
		t.Fatalf("holder Close: %v", err)
	}
	waitForBytes(t, "the release", func() bool { return device.QueuedBytes() == 0 })
	if len(io.takeTransmitWritable(nil)) == 0 {
		t.Fatal("the group's full release did not hand it to the engine")
	}
	if err := target.enqueue(buf.NewSize(1), fragments, goOutboundData, conn, 0); err != nil {
		t.Fatalf("the group's retry: %v", err)
	}
	if got := target.data.count; got != len(fragments) {
		t.Fatalf("the data ring holds %d fragments, want %d", got, len(fragments))
	}
	if got := device.QueuedBytes(); got != 3000 {
		t.Fatalf("device total %d, want the group's 3000", got)
	}
	if got := target.QueuedBytes(); got != 3000 {
		t.Fatalf("the queue holds %d, want the group's 3000", got)
	}
}

// TestRingFullAndByteFullBothArmAndWake pins the two independent conditions: ring full with
// bytes to spare, and ring full together with byte full. In both cases a drain must hand the
// writer's group to the engine and the original frame must enqueue on retry.
func TestRingFullAndByteFullBothArmAndWake(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		budget int
	}{
		{name: "ring-full-bytes-free", budget: 1 << 20},
		{name: "ring-and-bytes-full", budget: 1600},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			device := newCrossQueueDevice(t, testCase.budget)
			target := parkedQueue(t, device)
			// Fill the data ring to its capacity (2 x batchSize = 16) with 100-byte frames.
			for index := 0; index < 16; index++ {
				if err := target.enqueue(buf.NewSize(100), nil, goOutboundData, nil, 0); err != nil {
					t.Fatalf("fill %d: %v", index, err)
				}
			}
			conn := &GoConn{}
			conn.outboundQueue.Store(target)
			if err := target.enqueue(buf.NewSize(100), nil, goOutboundData, conn, 0); !errors.Is(err, errGoTransmitBlocked) {
				t.Fatalf("a full data ring returned %v, want errGoTransmitBlocked", err)
			}
			io := &goMemoryIO{tun: device, blocked: make(map[*OutboundQueue]*goBlockedWriters)}
			if waiters, armErr := io.armTransmitWritable(conn); armErr != nil || waiters == nil {
				t.Fatalf("the ring-blocked writer was not armed: (%v, %v)", waiters, armErr)
			}
			// Free the ring the way the queue's loop does when its handler returns.
			if err := target.drainNow(); err != nil {
				t.Fatalf("drain: %v", err)
			}
			if len(io.takeTransmitWritable(nil)) == 0 {
				t.Fatal("the drain did not hand the ring-blocked writer to the engine")
			}
			if err := target.enqueue(buf.NewSize(100), nil, goOutboundData, conn, 0); err != nil {
				t.Fatalf("the retry after the drain: %v", err)
			}
		})
	}
}

// drainNow pops one batch from the queue and releases it, the way the queue's loop does.
func (q *OutboundQueue) drainNow() error {
	buffers := make([]*buf.Buffer, 8)
	for {
		count := q.drain(buffers)
		if count == 0 {
			return nil
		}
		for _, buffer := range buffers[:count] {
			buffer.Release()
		}
	}
}

// TestClosingOneQueueWakesOnlyItsOwnWriter pins queue identity: closing A hands A's group to
// the engine (cancellation) while a waiter in B stays parked.
func TestClosingOneQueueWakesOnlyItsOwnWriter(t *testing.T) {
	device := newCrossQueueDevice(t, 4000)
	targetA := parkedQueue(t, device)
	targetB := parkedQueue(t, device)
	holder := parkedQueue(t, device)
	if err := holder.enqueue(buf.NewSize(4000), nil, goOutboundDatagram, nil, 0); err != nil {
		t.Fatalf("hold enqueue: %v", err)
	}
	waitForBytes(t, "the budget held", func() bool { return device.QueuedBytes() == 4000 })

	connA := &GoConn{}
	connA.outboundQueue.Store(targetA)
	connB := &GoConn{}
	connB.outboundQueue.Store(targetB)
	if err := targetA.enqueue(buf.NewSize(1000), nil, goOutboundData, connA, 0); !errors.Is(err, errGoTransmitBlocked) {
		t.Fatalf("A enqueue = %v", err)
	}
	if err := targetB.enqueue(buf.NewSize(1000), nil, goOutboundData, connB, 0); !errors.Is(err, errGoTransmitBlocked) {
		t.Fatalf("B enqueue = %v", err)
	}
	io := &goMemoryIO{tun: device, blocked: make(map[*OutboundQueue]*goBlockedWriters)}
	if waiters, armErr := io.armTransmitWritable(connA); armErr != nil || waiters == nil {
		t.Fatalf("A was not armed: (%v, %v)", waiters, armErr)
	}
	if waiters, armErr := io.armTransmitWritable(connB); armErr != nil || waiters == nil {
		t.Fatalf("B was not armed: (%v, %v)", waiters, armErr)
	}
	if err := targetA.Close(); err != nil {
		t.Fatalf("A Close: %v", err)
	}
	waitForBytes(t, "the device idle", func() bool { return device.QueuedBytes() == 4000 })
	woken := io.takeTransmitWritable(nil)
	if len(woken) != 1 {
		t.Fatalf("%d groups were handed to the engine, want only A's cancellation", len(woken))
	}
	// B is still blocked and its state is intact: a later release wakes it.
	if err := holder.Close(); err != nil {
		t.Fatalf("holder Close: %v", err)
	}
	waitForBytes(t, "the release", func() bool { return device.QueuedBytes() == 0 })
	deadline := time.Now().Add(2 * time.Second)
	for len(io.takeTransmitWritable(nil)) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("B's waiter was lost after A closed")
		}
		time.Sleep(time.Millisecond)
	}
}
