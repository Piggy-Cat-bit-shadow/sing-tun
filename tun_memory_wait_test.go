package tun

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
)

// WaitWritePackets is the blocking half of the memory TUN's inbound contract: a full queue must park
// the writer (which is what stops a MASQUE session's read loop from dropping), a freed slot must
// wake it, and Close must wake it with os.ErrClosed. The non-blocking WritePackets keeps the old
// drop policy, and neither path may grow the queue past its bound.

func newAttachedTestMemoryTun(t *testing.T, batchSize int) *MemoryTun {
	t.Helper()
	memoryTun := NewMemoryTun(MemoryTunOptions{
		MTU:       1500,
		BatchSize: batchSize,
		Outbound:  func([]*buf.Buffer) {},
	})
	// The Go stack attaches through goMemoryIO.start; a unit test can raise the same flag directly.
	memoryTun.attached.Store(true)
	t.Cleanup(func() { memoryTun.Close() })
	return memoryTun
}

func fillTestMemoryTun(t *testing.T, memoryTun *MemoryTun) int {
	t.Helper()
	packet := make([]byte, 24)
	packet[0] = 0x45
	acceptedTotal := 0
	for range 1 << 16 {
		accepted, err := memoryTun.WritePackets([][]byte{packet})
		if err != nil {
			t.Fatal(err)
		}
		if accepted == 0 {
			return acceptedTotal
		}
		acceptedTotal += accepted
	}
	t.Fatal("the memory TUN never reported a full inbound queue")
	return 0
}

func TestMemoryTunWaitWritePacketsParksUntilASlotFrees(t *testing.T) {
	memoryTun := newAttachedTestMemoryTun(t, 8)
	capacity := fillTestMemoryTun(t, memoryTun)
	if capacity != 4*8 {
		t.Fatalf("inbound queue capacity = %d, want 32", capacity)
	}

	packet := make([]byte, 24)
	packet[0] = 0x45
	done := make(chan error, 1)
	go func() {
		done <- memoryTun.WaitWritePackets([][]byte{packet})
	}()
	select {
	case err := <-done:
		t.Fatalf("WaitWritePackets returned %v while the queue was full", err)
	case <-time.After(100 * time.Millisecond):
	}

	memoryTun.inboundAccess.Lock()
	if memoryTun.inbound.count != capacity {
		queueLength := memoryTun.inbound.count
		memoryTun.inboundAccess.Unlock()
		t.Fatalf("a parked writer changed the queue length to %d", queueLength)
	}
	// Free one slot exactly as goMemoryIO.readBurst does after it pops a frame.
	drained, _, _ := memoryTun.inbound.pop()
	drained.Release()
	memoryTun.inboundWritable.Signal()
	memoryTun.inboundAccess.Unlock()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the woken writer returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("freeing a slot did not wake the parked writer")
	}

	memoryTun.inboundAccess.Lock()
	queueLength := memoryTun.inbound.count
	memoryTun.inboundAccess.Unlock()
	if queueLength != capacity {
		t.Fatalf("the woken writer left %d queued packets, want the %d bound", queueLength, capacity)
	}
}

func TestMemoryTunWaitWritePacketsCloseWakesIt(t *testing.T) {
	memoryTun := newAttachedTestMemoryTun(t, 8)
	fillTestMemoryTun(t, memoryTun)
	packet := make([]byte, 24)
	packet[0] = 0x45
	done := make(chan error, 1)
	go func() { done <- memoryTun.WaitWritePackets([][]byte{packet}) }()
	select {
	case err := <-done:
		t.Fatalf("WaitWritePackets returned %v while the queue was full", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := memoryTun.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("the parked writer returned %v after close, want os.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not wake the parked writer")
	}
}

func TestMemoryTunNonBlockingWriteDropsAtTheBound(t *testing.T) {
	memoryTun := newAttachedTestMemoryTun(t, 8)
	capacity := fillTestMemoryTun(t, memoryTun)
	packet := make([]byte, 24)
	packet[0] = 0x45
	accepted, err := memoryTun.WritePackets([][]byte{packet, packet, packet})
	if err != nil {
		t.Fatal(err)
	}
	if accepted != 0 {
		t.Fatalf("a full queue accepted %d packets on the non-blocking path", accepted)
	}
	memoryTun.inboundAccess.Lock()
	queueLength := memoryTun.inbound.count
	memoryTun.inboundAccess.Unlock()
	if queueLength != capacity {
		t.Fatalf("queue length = %d after a dropped write, want %d", queueLength, capacity)
	}
}
