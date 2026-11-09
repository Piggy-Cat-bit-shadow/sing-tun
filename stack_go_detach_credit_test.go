package tun

// 1A red test: the stack detach path (goMemoryIO.close) clears the inbound ring WITHOUT
// returning the device byte quota. The ring is empty, but the device still charges the
// bytes: a later attach is refused its frames and the device Close keeps the residue.
//
// The inbound ring has three clear paths - the normal read (readBurst), the stack detach
// (goMemoryIO.close) and the device Close - and all three must return the reservation.
//
// The test calls the detach path directly rather than through Go.Close: a live engine also
// reads the ring (and returns the quota itself), so a full-stack test would race the very
// behaviour under test instead of pinning the detach path.

import (
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
)

func newQuotaDevice(t *testing.T, maxQueuedBytes int) *MemoryTun {
	t.Helper()
	device := NewMemoryTun(MemoryTunOptions{MTU: 1500, BatchSize: 8, MaxQueuedBytes: maxQueuedBytes, Outbound: func([]*buf.Buffer) {}})
	t.Cleanup(func() { _ = device.Close() })
	return device
}

// queueFourFrames attaches the device and queues four 1 KiB frames (4,000 B of a 4 KiB
// budget).
func queueFourFrames(t *testing.T, device *MemoryTun) {
	t.Helper()
	device.attached.Store(true)
	frame := make([]byte, 1000)
	frame[0] = 0x45
	for index := 0; index < 4; index++ {
		accepted, err := device.WritePackets([][]byte{frame})
		if err != nil || accepted != 1 {
			t.Fatalf("queue frame %d = (%d, %v)", index, accepted, err)
		}
	}
	waitForBytes(t, "four frames queued", func() bool { return device.QueuedBytes() == 4000 })
}

func TestDetachReturnsTheInboundByteQuota(t *testing.T) {
	device := newQuotaDevice(t, 4096)
	queueFourFrames(t, device)

	(&goMemoryIO{tun: device}).close()

	if got := device.QueuedBytes(); got != 0 {
		t.Fatalf("the detach left %d bytes charged while the inbound ring is empty", got)
	}
	device.inboundAccess.Lock()
	queued := device.inbound.count
	device.inboundAccess.Unlock()
	if queued != 0 {
		t.Fatalf("the detach left %d inbound frames", queued)
	}

	// A fresh attach must be able to queue again: the quota is the device's, not the
	// detached stack's.
	device.attached.Store(true)
	frame := make([]byte, 1000)
	frame[0] = 0x45
	accepted, err := device.WritePackets([][]byte{frame})
	if err != nil || accepted != 1 {
		t.Fatalf("a frame after re-attach = (%d, %v), want (1, nil): the detach kept the quota", accepted, err)
	}
	// The device Close returns whatever the re-attached queue holds.
	if err := device.Close(); err != nil {
		t.Fatalf("device Close: %v", err)
	}
	if got := device.QueuedBytes(); got != 0 {
		t.Fatalf("device Close left %d bytes charged", got)
	}
}

// TestDetachWithWaiterReleasesAndWakes pins the interaction with a writer parked on the
// byte budget: the detach must release the queued frames and the parked writer must
// return, not hang.
func TestDetachWithWaiterReleasesAndWakes(t *testing.T) {
	device := newQuotaDevice(t, 4096)
	queueFourFrames(t, device)

	frame := make([]byte, 1000)
	frame[0] = 0x45
	done := make(chan error, 1)
	go func() { done <- device.WaitWritePackets([][]byte{frame}) }()
	time.Sleep(50 * time.Millisecond)

	(&goMemoryIO{tun: device}).close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a writer parked on the byte budget did not return after the detach")
	}
	if got := device.QueuedBytes(); got != 0 {
		t.Fatalf("the detach returned the waiter but left %d bytes charged", got)
	}
}
