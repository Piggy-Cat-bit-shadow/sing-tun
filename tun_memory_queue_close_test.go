package tun

// 1B red test: after MemoryTun.Close returns, a caller-owned OutboundQueue still accepts
// new submissions. The handler keeps receiving packets, which means a MASQUE-style owner
// can feed a dead device forever.
//
// The contract this pins: device Close stops admission on every queue of the device
// (default and caller-owned) while leaving the datagrams already queued to their actual
// owner - they are released by that queue's own Close (the 1C regression).

import (
	"errors"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
)

func TestCallerQueueRefusesSubmissionsAfterDeviceClose(t *testing.T) {
	device := NewMemoryTun(MemoryTunOptions{MTU: 1500, BatchSize: 8, MaxQueuedBytes: 1 << 20, Outbound: func([]*buf.Buffer) {}})
	delivered := make(chan int, 8)
	queue := device.NewOutboundQueue(func(packets []*buf.Buffer) {
		delivered <- len(packets)
		buf.ReleaseMulti(packets)
	})
	defer queue.Close()

	if err := device.Close(); err != nil {
		t.Fatalf("device Close: %v", err)
	}
	// The queue's own entry point (used by the routing path).
	if err := queue.enqueue(buf.NewSize(1000), nil, goOutboundDatagram, nil, 0); !errors.Is(err, errGoFrameDropped) {
		t.Fatalf("enqueue after device Close = %v, want errGoFrameDropped", err)
	}
	// The public batch entry point (the one MASQUE calls).
	queue.WriteBuffers([]*buf.Buffer{buf.NewSize(1000), buf.NewSize(1000), buf.NewSize(1000)})
	select {
	case count := <-delivered:
		t.Fatalf("the handler received %d packets after the device closed", count)
	case <-time.After(200 * time.Millisecond):
	}
	if got := device.QueuedBytes(); got != 0 {
		t.Fatalf("device total %d after refused submissions, want 0", got)
	}
}

// TestCallerQueueKeepsWhatTheDeviceDoesNotOwn is the 1C regression kept in place: a
// datagram already queued when the device closes is still the caller's to release, and the
// device total must say so until that queue is closed.
func TestCallerQueueKeepsWhatTheDeviceDoesNotOwn(t *testing.T) {
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
	device := NewMemoryTun(MemoryTunOptions{MTU: 1500, BatchSize: 8, MaxQueuedBytes: 1 << 20, Outbound: handler})
	queue := device.NewOutboundQueue(handler)

	// Block the handler with a filler so the next datagram stays in the ring.
	if err := queue.enqueue(buf.NewSize(500), nil, goOutboundDatagram, nil, 0); err != nil {
		t.Fatalf("filler enqueue: %v", err)
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the handler never entered")
	}
	waitForBytes(t, "the filler to leave the rings", func() bool { return queue.QueuedBytes() == 0 })
	if err := queue.enqueue(buf.NewSize(1000), nil, goOutboundDatagram, nil, 0); err != nil {
		t.Fatalf("ring enqueue: %v", err)
	}
	waitForBytes(t, "one datagram held", func() bool { return device.QueuedBytes() == 1000 })

	if err := device.Close(); err != nil {
		t.Fatalf("device Close: %v", err)
	}
	if got := device.QueuedBytes(); got != 1000 {
		t.Fatalf("device total %d after Close while the caller queue holds 1000, want 1000", got)
	}
	close(hold)
	if err := queue.Close(); err != nil {
		t.Fatalf("queue Close: %v", err)
	}
	if got := device.QueuedBytes(); got != 0 {
		t.Fatalf("device total %d after the caller queue closed, want 0", got)
	}
}
