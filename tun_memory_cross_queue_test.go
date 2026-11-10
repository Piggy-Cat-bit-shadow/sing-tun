package tun

// TCP cross-queue wake: the device byte budget is shared by the default queue and every
// caller-owned (route) queue, so a release in ONE of them has to wake a data writer parked
// in ANOTHER. Two probes:
//
//   - an inbound read frees the budget, and a route queue's blocked TCP data write must be
//     handed to the engine;
//   - a caller queue is closed (releasing its ring), and the DEFAULT queue's blocked TCP
//     data write must be handed to the engine.
//
// Both assert the engine receives the right blocked-writer group AND that the original
// frame actually retries and enqueues.

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

// blockedHandler is a handler that reports entry once and then holds every batch until
// release. It is the barrier that keeps a queue's rings holding packets.
type blockedHandler struct {
	entered chan struct{}
	exited  chan struct{}
	release chan struct{}
}

func newBlockedHandler() *blockedHandler {
	return &blockedHandler{entered: make(chan struct{}), exited: make(chan struct{}), release: make(chan struct{})}
}

func (h *blockedHandler) handle(packets []*buf.Buffer) {
	select {
	case <-h.entered:
	default:
		close(h.entered)
	}
	<-h.release
	buf.ReleaseMulti(packets)
	select {
	case <-h.exited:
	default:
		close(h.exited)
	}
}

func newCrossQueueDevice(t *testing.T, maxQueuedBytes int) *MemoryTun {
	t.Helper()
	device := NewMemoryTun(MemoryTunOptions{MTU: 1500, BatchSize: 8, MaxQueuedBytes: maxQueuedBytes, Outbound: func([]*buf.Buffer) {}})
	device.attached.Store(true)
	t.Cleanup(func() { _ = device.Close() })
	return device
}

// TestInboundReadWakesARouteQueueDataWaiter is probe 1: inbound frames hold the budget, a
// route queue's TCP data write is blocked, and the real readBurst frees the budget.
func TestInboundReadWakesARouteQueueDataWaiter(t *testing.T) {
	device := newCrossQueueDevice(t, 4000)
	handler := newBlockedHandler()
	route := device.NewOutboundQueue(handler.handle)
	t.Cleanup(func() {
		close(handler.release)
		_ = route.Close()
	})

	// Stop the route queue from draining by blocking its handler with a filler.
	if err := route.enqueue(buf.NewSize(200), nil, goOutboundDatagram, nil, 0); err != nil {
		t.Fatalf("filler enqueue: %v", err)
	}
	select {
	case <-handler.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the route queue handler never entered")
	}
	waitForBytes(t, "the filler to leave the rings", func() bool { return route.QueuedBytes() == 0 })

	// Inbound takes the whole budget.
	frame := make([]byte, 4000)
	frame[0] = 0x45
	if accepted, err := device.WritePackets([][]byte{frame}); err != nil || accepted != 1 {
		t.Fatalf("inbound write = (%d, %v)", accepted, err)
	}
	waitForBytes(t, "the device budget full", func() bool { return device.QueuedBytes() == 4000 })

	conn := &GoConn{}
	conn.outboundQueue.Store(route)
	io := &goMemoryIO{tun: device, blocked: make(map[*OutboundQueue]*goBlockedWriters)}

	// A TCP data frame for the route queue, blocked only by the byte budget.
	if err := route.enqueue(buf.NewSize(1000), nil, goOutboundData, nil, 0); !errors.Is(err, errGoTransmitBlocked) {
		t.Fatalf("route data enqueue = %v, want errGoTransmitBlocked", err)
	}
	waiters, err := io.armTransmitWritable(conn)
	if err != nil || waiters == nil {
		t.Fatalf("the route data writer was not armed: (%v, %v)", waiters, err)
	}

	// The real read path releases the inbound frame.
	frames := make([]goFrame, 8)
	count, _, readErr := io.readBurst(frames, N.ReadWaitOptions{})
	if readErr != nil || count != 1 {
		t.Fatalf("readBurst = (%d, %v)", count, readErr)
	}
	for _, readFrame := range frames[:count] {
		readFrame.buffer.Release()
	}
	if got := device.QueuedBytes(); got != 0 {
		t.Fatalf("device total %d after the inbound read, want 0", got)
	}

	woken := io.takeTransmitWritable(nil)
	if len(woken) == 0 {
		t.Fatal("the inbound read did not hand the route queue's byte-blocked data writer to the engine")
	}
	// The original frame must actually retry and enqueue.
	if err := route.enqueue(buf.NewSize(1000), nil, goOutboundData, nil, 0); err != nil {
		t.Fatalf("the retry after the inbound read: %v", err)
	}
}

// TestAnotherQueueCloseWakesTheDefaultQueueDataWaiter is probe 2: an extra queue holds the
// budget, the DEFAULT queue's TCP data write is blocked, and closing the extra queue
// releases the budget.
func TestAnotherQueueCloseWakesTheDefaultQueueDataWaiter(t *testing.T) {
	device := newCrossQueueDevice(t, 4000)
	handler := newBlockedHandler()
	extra := device.NewOutboundQueue(handler.handle)
	t.Cleanup(func() { close(handler.release) })

	// Block the extra queue's handler, then leave 4,000 B in its ring.
	if err := extra.enqueue(buf.NewSize(200), nil, goOutboundDatagram, nil, 0); err != nil {
		t.Fatalf("filler enqueue: %v", err)
	}
	select {
	case <-handler.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the extra queue handler never entered")
	}
	waitForBytes(t, "the filler to leave the rings", func() bool { return extra.QueuedBytes() == 0 })
	if err := extra.enqueue(buf.NewSize(4000), nil, goOutboundDatagram, nil, 0); err != nil {
		t.Fatalf("hold enqueue: %v", err)
	}
	waitForBytes(t, "the budget held by the extra queue", func() bool { return device.QueuedBytes() == 4000 })

	io := &goMemoryIO{tun: device, blocked: make(map[*OutboundQueue]*goBlockedWriters)}
	if err := device.outbound.enqueue(buf.NewSize(1000), nil, goOutboundData, nil, 0); !errors.Is(err, errGoTransmitBlocked) {
		t.Fatalf("default data enqueue = %v, want errGoTransmitBlocked", err)
	}
	waiters, err := io.armTransmitWritable(nil)
	if err != nil || waiters == nil {
		t.Fatalf("the default data writer was not armed: (%v, %v)", waiters, err)
	}

	// Closing the extra queue releases its ring to the shared budget.
	if err := extra.Close(); err != nil {
		t.Fatalf("extra queue Close: %v", err)
	}
	waitForBytes(t, "the extra queue released the budget", func() bool { return device.QueuedBytes() == 0 })

	woken := io.takeTransmitWritable(nil)
	if len(woken) == 0 {
		t.Fatal("the other queue's Close did not hand the default queue's data writer to the engine")
	}
	if err := device.outbound.enqueue(buf.NewSize(1000), nil, goOutboundData, nil, 0); err != nil {
		t.Fatalf("the retry after the other queue closed: %v", err)
	}
}

// TestRouteQueueDrainWakesTheDefaultQueueDataWaiter is the drain half of the matrix: the
// extra queue's release comes from its own DRAIN (not its Close), and the default queue's
// blocked data writer must still be woken.
func TestRouteQueueDrainWakesTheDefaultQueueDataWaiter(t *testing.T) {
	device := newCrossQueueDevice(t, 4000)
	handler := newBlockedHandler()
	extra := device.NewOutboundQueue(handler.handle)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(handler.release) }) }
	t.Cleanup(func() { release(); _ = extra.Close() })

	if err := extra.enqueue(buf.NewSize(200), nil, goOutboundDatagram, nil, 0); err != nil {
		t.Fatalf("filler enqueue: %v", err)
	}
	select {
	case <-handler.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the extra queue handler never entered")
	}
	waitForBytes(t, "the filler to leave the rings", func() bool { return extra.QueuedBytes() == 0 })
	if err := extra.enqueue(buf.NewSize(4000), nil, goOutboundDatagram, nil, 0); err != nil {
		t.Fatalf("hold enqueue: %v", err)
	}
	waitForBytes(t, "the budget held by the extra queue", func() bool { return device.QueuedBytes() == 4000 })

	io := &goMemoryIO{tun: device, blocked: make(map[*OutboundQueue]*goBlockedWriters)}
	if err := device.outbound.enqueue(buf.NewSize(1000), nil, goOutboundData, nil, 0); !errors.Is(err, errGoTransmitBlocked) {
		t.Fatalf("default data enqueue = %v, want errGoTransmitBlocked", err)
	}
	if waiters, err := io.armTransmitWritable(nil); err != nil || waiters == nil {
		t.Fatalf("the default data writer was not armed: (%v, %v)", waiters, err)
	}

	// The extra queue drains its ring when its handler is released.
	release()
	waitForBytes(t, "the extra queue to drain", func() bool { return extra.QueuedBytes() == 0 })
	if got := device.QueuedBytes(); got != 0 {
		t.Fatalf("device total %d after the drain, want 0", got)
	}
	woken := io.takeTransmitWritable(nil)
	if len(woken) == 0 {
		t.Fatal("the extra queue's drain did not hand the default queue's data writer to the engine")
	}
	if err := device.outbound.enqueue(buf.NewSize(1000), nil, goOutboundData, nil, 0); err != nil {
		t.Fatalf("the retry after the drain: %v", err)
	}
}

// TestDetachWakesAByteBlockedDataWriter is the detach row of the matrix: the detach
// releases the inbound frames, and a data writer blocked on the shared budget in the
// DEFAULT queue must be woken by that release.
func TestDetachWakesAByteBlockedDataWriter(t *testing.T) {
	device := newCrossQueueDevice(t, 4000)
	frame := make([]byte, 4000)
	frame[0] = 0x45
	if accepted, err := device.WritePackets([][]byte{frame}); err != nil || accepted != 1 {
		t.Fatalf("inbound write = (%d, %v)", accepted, err)
	}
	waitForBytes(t, "the device budget full", func() bool { return device.QueuedBytes() == 4000 })

	io := &goMemoryIO{tun: device, blocked: make(map[*OutboundQueue]*goBlockedWriters)}
	if err := device.outbound.enqueue(buf.NewSize(1000), nil, goOutboundData, nil, 0); !errors.Is(err, errGoTransmitBlocked) {
		t.Fatalf("default data enqueue = %v, want errGoTransmitBlocked", err)
	}
	if waiters, err := io.armTransmitWritable(nil); err != nil || waiters == nil {
		t.Fatalf("the default data writer was not armed: (%v, %v); interest=%v dataCount=%d device=%d",
			waiters, err, device.outbound.transmitInterest.Load(), device.outbound.data.count, device.QueuedBytes())
	}

	(&goMemoryIO{tun: device}).close()
	if got := device.QueuedBytes(); got != 0 {
		t.Fatalf("the detach left %d bytes charged", got)
	}
	woken := io.takeTransmitWritable(nil)
	if len(woken) == 0 {
		t.Fatal("the detach did not hand the default queue's byte-blocked data writer to the engine")
	}
	if err := device.outbound.enqueue(buf.NewSize(1000), nil, goOutboundData, nil, 0); err != nil {
		t.Fatalf("the retry after the detach: %v", err)
	}
}

// TestDeviceCloseCancelsAByteBlockedDataWriter is the close row: after the device closes,
// the blocked writer's queue is handed to the engine so the writer can see the close and
// exit instead of waiting forever.
func TestDeviceCloseCancelsAByteBlockedDataWriter(t *testing.T) {
	device := newCrossQueueDevice(t, 4000)
	frame := make([]byte, 4000)
	frame[0] = 0x45
	if accepted, err := device.WritePackets([][]byte{frame}); err != nil || accepted != 1 {
		t.Fatalf("inbound write = (%d, %v)", accepted, err)
	}
	io := &goMemoryIO{tun: device, blocked: make(map[*OutboundQueue]*goBlockedWriters)}
	if err := device.outbound.enqueue(buf.NewSize(1000), nil, goOutboundData, nil, 0); !errors.Is(err, errGoTransmitBlocked) {
		t.Fatalf("default data enqueue = %v, want errGoTransmitBlocked", err)
	}
	if waiters, err := io.armTransmitWritable(nil); err != nil || waiters == nil {
		t.Fatalf("the default data writer was not armed: (%v, %v)", waiters, err)
	}
	if err := device.Close(); err != nil {
		t.Fatalf("device Close: %v", err)
	}
	if woken := io.takeTransmitWritable(nil); len(woken) == 0 {
		t.Fatal("the device Close did not hand the blocked writer's queue to the engine")
	}
	// A new submission is refused, so the writer exits instead of looping.
	if err := device.outbound.enqueue(buf.NewSize(1000), nil, goOutboundData, nil, 0); !errors.Is(err, errGoFrameDropped) {
		t.Fatalf("enqueue after Close = %v, want errGoFrameDropped", err)
	}
}
