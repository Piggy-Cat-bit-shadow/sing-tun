package tun

// TCP outbound backpressure when only the device BYTE budget is exhausted.
//
// A data-class write refused by the byte budget is backpressure, not a drop: the queue is
// armed, the writer parks, and it retries when the budget frees. UDP keeps the drop policy.
// The wake has two sources: the queue's own drain (pop returns bytes) and the inbound
// reader (a read frees the same device budget for an outbound writer).

import (
	"errors"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

func TestDataWriteIsBackpressuredByTheByteBudget(t *testing.T) {
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
	device := NewMemoryTun(MemoryTunOptions{MTU: 1500, BatchSize: 8, MaxQueuedBytes: 2000, Outbound: handler})
	t.Cleanup(func() { _ = device.Close() })
	io := &goMemoryIO{tun: device, blocked: make(map[*OutboundQueue]*goBlockedWriters)}

	// Block the handler with a filler, then hold 2,000 B (the whole budget) in the ring.
	if err := device.outbound.enqueue(buf.NewSize(500), nil, goOutboundDatagram, nil, 0); err != nil {
		t.Fatalf("filler enqueue: %v", err)
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the handler never entered")
	}
	waitForBytes(t, "the filler to leave the rings", func() bool { return device.outbound.QueuedBytes() == 0 })
	if err := device.outbound.enqueue(buf.NewSize(2000), nil, goOutboundDatagram, nil, 0); err != nil {
		t.Fatalf("hold enqueue: %v", err)
	}
	waitForBytes(t, "the budget held", func() bool { return device.outbound.QueuedBytes() == 2000 })

	// A TCP segment that only the byte budget refuses: backpressure, not a drop.
	err := device.outbound.enqueue(buf.NewSize(500), nil, goOutboundData, nil, 0)
	if !errors.Is(err, errGoTransmitBlocked) {
		t.Fatalf("a data write blocked only by the byte budget returned %v, want errGoTransmitBlocked", err)
	}
	// And the queue must have armed the writer.
	waiters, armErr := io.armTransmitWritable(nil)
	if armErr != nil {
		t.Fatalf("armTransmitWritable: %v", armErr)
	}
	if waiters == nil {
		t.Fatal("the byte-blocked data write was not armed: no writer would ever retry")
	}

	// When the queue drains, the blocked writer must be woken.
	close(hold)
	waitForBytes(t, "the held datagram to drain", func() bool { return device.outbound.QueuedBytes() == 0 })
	woken := io.takeTransmitWritable(nil)
	if len(woken) == 0 {
		t.Fatal("draining the queue did not hand the blocked writer to the engine")
	}
	// The retry now fits.
	if err := device.outbound.enqueue(buf.NewSize(500), nil, goOutboundData, nil, 0); err != nil {
		t.Fatalf("the retry after the release: %v", err)
	}
}

// TestInboundReadWakesAByteBlockedDataWriter is the cross-direction wake: the budget is
// held by an inbound frame, a data write is byte-blocked, and the inbound READ frees the
// budget for the outbound writer.
func TestInboundReadWakesAByteBlockedDataWriter(t *testing.T) {
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
	device := NewMemoryTun(MemoryTunOptions{MTU: 1500, BatchSize: 8, MaxQueuedBytes: 4000, Outbound: handler})
	t.Cleanup(func() { _ = device.Close() })
	io := &goMemoryIO{tun: device, blocked: make(map[*OutboundQueue]*goBlockedWriters)}
	device.attached.Store(true)

	// Hold the budget in the outbound ring (handler blocked), then take the rest inbound.
	if err := device.outbound.enqueue(buf.NewSize(500), nil, goOutboundDatagram, nil, 0); err != nil {
		t.Fatalf("filler enqueue: %v", err)
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the handler never entered")
	}
	waitForBytes(t, "the filler to leave the rings", func() bool { return device.outbound.QueuedBytes() == 0 })
	if err := device.outbound.enqueue(buf.NewSize(1000), nil, goOutboundDatagram, nil, 0); err != nil {
		t.Fatalf("hold enqueue: %v", err)
	}
	waitForBytes(t, "the outbound hold", func() bool { return device.outbound.QueuedBytes() == 1000 })
	// Inbound frames take the remaining budget: but the outbound pop releases the 1,000,
	// so keep the inbound side holding the rest.
	frame := make([]byte, 3000)
	frame[0] = 0x45
	if accepted, err := device.WritePackets([][]byte{frame}); err != nil || accepted != 1 {
		t.Fatalf("inbound write = (%d, %v)", accepted, err)
	}
	waitForBytes(t, "the device budget full", func() bool { return device.QueuedBytes() == 4000 })

	// A TCP segment is byte-blocked.
	if err := device.outbound.enqueue(buf.NewSize(500), nil, goOutboundData, nil, 0); !errors.Is(err, errGoTransmitBlocked) {
		t.Fatalf("byte-blocked data write = %v, want errGoTransmitBlocked", err)
	}
	if waiters, err := io.armTransmitWritable(nil); err != nil || waiters == nil {
		t.Fatalf("the data writer was not armed: (%v, %v)", waiters, err)
	}

	// Read the inbound frame through the real read path: that frees the same device budget
	// for the outbound writer and must wake it.
	frames := make([]goFrame, 8)
	count, _, readErr := io.readBurst(frames, N.ReadWaitOptions{})
	if readErr != nil || count != 1 {
		t.Fatalf("readBurst = (%d, %v), want the one inbound frame", count, readErr)
	}
	for _, frame := range frames[:count] {
		frame.buffer.Release()
	}
	if got := device.QueuedBytes(); got != 1000 {
		t.Fatalf("device total %d after the inbound read, want the outbound hold's 1000", got)
	}
	woken := io.takeTransmitWritable(nil)
	if len(woken) == 0 {
		t.Fatal("the inbound read did not hand the byte-blocked outbound writer to the engine")
	}
	if err := device.outbound.enqueue(buf.NewSize(500), nil, goOutboundData, nil, 0); err != nil {
		t.Fatalf("the retry after the inbound read: %v", err)
	}
	close(hold)
}
