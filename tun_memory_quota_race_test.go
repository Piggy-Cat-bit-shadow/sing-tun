package tun

// Shared-quota interleaving: WaitWritePackets checks that the byte budget has room and
// then reserves it with a CAS. If another queue takes the room between the two, the
// current code skips the frame (a silent lost write). The blocking contract is that the
// writer waits instead and writes once the room returns.
//
// packetWriteHook is the controlled interleaving: it runs between the room check and the
// reservation, which is exactly the window the race needs.

import (
	"sync"
	"testing"
	"time"
)

func TestBlockingWriteRetriesWhenAnotherQueueTakesTheQuota(t *testing.T) {
	device := newQuotaDevice(t, 4000)
	device.attached.Store(true)

	var once sync.Once
	packetWriteHook = func() {
		once.Do(func() {
			// The competitor takes ALL 4,000 bytes right before the writer's CAS, so the
			// writer has no room to retry until the competitor releases.
			reserved := device.reserveQueuedBytes(4000)
			t.Logf("hook ran: reserved=%v total=%d", reserved, device.QueuedBytes())
		})
	}
	t.Cleanup(func() { packetWriteHook = nil })

	frame := make([]byte, 1000)
	frame[0] = 0x45
	done := make(chan error, 1)
	go func() { done <- device.WaitWritePackets([][]byte{frame}) }()

	// The writer must NOT return with the frame skipped: it has to wait for room.
	select {
	case err := <-done:
		t.Fatalf("the blocked writer returned (%v) although the competing reservation ate its room; the frame was silently skipped", err)
	case <-time.After(100 * time.Millisecond):
	}

	// The competitor releases its 4,000 bytes; the writer must complete with its frame.
	device.releaseQueuedBytes(4000)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the woken writer returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the writer did not resume after the competing reservation was released")
	}
	device.inboundAccess.Lock()
	queued := device.inbound.count
	device.inboundAccess.Unlock()
	if queued != 1 {
		t.Fatalf("the writer queued %d frames, want its own 1", queued)
	}
	if got := device.QueuedBytes(); got != 1000 {
		t.Fatalf("device total %d, want the writer's 1000", got)
	}
}
