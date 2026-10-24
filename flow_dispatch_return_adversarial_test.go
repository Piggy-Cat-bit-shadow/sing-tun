package tun

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
)

// Adversarial cases for the return path's in-place compaction.
//
// The implementation does NOT use an inline array: it compacts the caller's own slice while every
// packet shares one writeback, and only builds the original grouping when a second writeback
// appears. The invariants that shape depends on are therefore different from an inline array's:
//
//   - the write only ever lands at positions already read, so no packet is overwritten before it is
//     classified;
//   - the returned "unconsumed" slice no longer aliases the input, because the input now holds the
//     packets being sent;
//   - the multi-writeback fallback must produce exactly the old batches, boundaries and order.

// batchRecorder records the pointer identity, content and order of what each writeback received.
type batchRecorder struct {
	access  sync.Mutex
	batches [][][]byte
	copies  [][][]byte
}

func (r *batchRecorder) ReturnHeadroom() int { return 0 }

func (r *batchRecorder) WriteReturnPackets(packets [][]byte) error {
	r.access.Lock()
	defer r.access.Unlock()
	batch := append([][]byte(nil), packets...)
	r.batches = append(r.batches, batch)
	copied := make([][]byte, len(packets))
	for i, packet := range packets {
		copied[i] = append([]byte(nil), packet...)
	}
	r.copies = append(r.copies, copied)
	return nil
}

func (r *batchRecorder) batchCount() int {
	r.access.Lock()
	defer r.access.Unlock()
	return len(r.batches)
}

func (r *batchRecorder) flat() [][]byte {
	r.access.Lock()
	defer r.access.Unlock()
	var out [][]byte
	for _, batch := range r.batches {
		out = append(out, batch...)
	}
	return out
}

// TestReturnPacketsSizeMatrix walks the batch sizes the return path sees, including the empty one.
func TestReturnPacketsSizeMatrix(t *testing.T) {
	writeback := &batchRecorder{}
	harness := newReturnHarness(t, writeback)

	for _, size := range []int{0, 1, 2, 3, 4, 8, 32, 64, 128, 1024} {
		packets := make([][]byte, size)
		for i := range packets {
			packets[i] = harness.packet(40000, fmt.Sprintf("p%d", i))
		}
		unconsumed := harness.returnPath.ReturnPackets(packets)
		if len(unconsumed) != 0 {
			t.Fatalf("size %d: %d packets passed back", size, len(unconsumed))
		}
		if size == 0 {
			if writeback.batchCount() != 0 {
				t.Fatalf("an empty batch must not reach the writeback")
			}
			continue
		}
		if writeback.batchCount() != 1 {
			t.Fatalf("size %d: one writeback must receive one batch, got %d", size, writeback.batchCount())
		}
		flat := writeback.flat()
		if len(flat) != size {
			t.Fatalf("size %d: writeback saw %d packets", size, len(flat))
		}
		for i, packet := range flat {
			if want := harness.packet(40000, fmt.Sprintf("p%d", i)); string(packet) != string(want) {
				t.Fatalf("size %d: packet %d out of order or corrupted", size, i)
			}
			if &packet[0] != &packets[i][0] {
				t.Fatalf("size %d: packet %d is not the caller's own slice", size, i)
			}
		}
		writeback.access.Lock()
		writeback.batches = nil
		writeback.copies = nil
		writeback.access.Unlock()
	}
}

// TestReturnPacketsPortMatrix walks the number of writebacks a single batch can carry, which is
// what decides whether the fast path or the grouping fallback runs.
func TestReturnPacketsPortMatrix(t *testing.T) {
	for _, ports := range []int{1, 2, 3, 8, 64} {
		t.Run(fmt.Sprintf("ports=%d", ports), func(t *testing.T) {
			writebacks := make([]*batchRecorder, ports)
			all := make([]ForwardWriteback, ports)
			for i := range writebacks {
				writebacks[i] = &batchRecorder{}
				all[i] = writebacks[i]
			}
			harness := newReturnHarness(t, all...)

			const roundTrips = 4
			for round := 0; round < roundTrips; round++ {
				packets := make([][]byte, ports)
				for port := 0; port < ports; port++ {
					packets[port] = harness.packet(uint16(40000+port), fmt.Sprintf("round%d-port%d", round, port))
				}
				if unconsumed := harness.returnPath.ReturnPackets(packets); len(unconsumed) != 0 {
					t.Fatalf("%d packets passed back", len(unconsumed))
				}
			}

			for port, writeback := range writebacks {
				if writeback.batchCount() != roundTrips {
					t.Fatalf("port %d: expected one batch per round (%d), got %d",
						port, roundTrips, writeback.batchCount())
				}
				flat := writeback.flat()
				if len(flat) != roundTrips {
					t.Fatalf("port %d: got %d packets, want %d", port, len(flat), roundTrips)
				}
				for round, packet := range flat {
					want := fmt.Sprintf("round%d-port%d", round, port)
					body := packet[header.IPv4MinimumSize+header.UDPMinimumSize:]
					if string(body) != want {
						t.Fatalf("port %d round %d: payload %q, want %q", port, round, body, want)
					}
				}
			}
		})
	}
}

// TestReturnPacketsInterleavedOrder is the P1,P2,P1,P3,P2 shape: each writeback must still get its
// own packets in arrival order, in ONE batch, exactly as the previous implementation grouped them.
func TestReturnPacketsInterleavedOrder(t *testing.T) {
	first := &batchRecorder{}
	second := &batchRecorder{}
	third := &batchRecorder{}
	harness := newReturnHarness(t, first, second, third)

	packets := [][]byte{
		harness.packet(40000, "a1"),
		harness.packet(40001, "b1"),
		harness.packet(40000, "a2"),
		harness.packet(40002, "c1"),
		harness.packet(40001, "b2"),
	}
	if unconsumed := harness.returnPath.ReturnPackets(packets); len(unconsumed) != 0 {
		t.Fatalf("%d packets passed back", len(unconsumed))
	}

	expect := []struct {
		name     string
		recorder *batchRecorder
		want     []string
	}{
		{"first", first, []string{"a1", "a2"}},
		{"second", second, []string{"b1", "b2"}},
		{"third", third, []string{"c1"}},
	}
	for _, testCase := range expect {
		if testCase.recorder.batchCount() != 1 {
			t.Fatalf("%s: expected one batch, got %d", testCase.name, testCase.recorder.batchCount())
		}
		flat := testCase.recorder.flat()
		if len(flat) != len(testCase.want) {
			t.Fatalf("%s: got %d packets, want %d", testCase.name, len(flat), len(testCase.want))
		}
		for i, packet := range flat {
			body := packet[header.IPv4MinimumSize+header.UDPMinimumSize:]
			if string(body) != testCase.want[i] {
				t.Fatalf("%s: packet %d is %q, want %q", testCase.name, i, body, testCase.want[i])
			}
		}
	}
}

// TestReturnPacketsDuplicatesAndEmpty proves a repeated packet is delivered twice (the function is
// per packet, not per unique pointer) and an empty batch does nothing.
func TestReturnPacketsDuplicatesAndEmpty(t *testing.T) {
	writeback := &batchRecorder{}
	harness := newReturnHarness(t, writeback)

	if unconsumed := harness.returnPath.ReturnPackets(nil); len(unconsumed) != 0 {
		t.Fatal("nil input must return nil")
	}
	if writeback.batchCount() != 0 {
		t.Fatal("nil input must not reach the writeback")
	}

	packet := harness.packet(40000, "dup")
	if unconsumed := harness.returnPath.ReturnPackets([][]byte{packet, packet, packet}); len(unconsumed) != 0 {
		t.Fatalf("%d packets passed back", len(unconsumed))
	}
	if got := len(writeback.flat()); got != 3 {
		t.Fatalf("three copies of one packet must be delivered three times, got %d", got)
	}
}

// TestReturnPacketsBytesAreUnchanged proves the pass-through path does not rely on the compaction
// having moved anything: with no rewrite rule the packets must be byte-identical afterwards.
func TestReturnPacketsBytesAreUnchanged(t *testing.T) {
	writeback := &batchRecorder{}
	harness := newReturnHarness(t, writeback)

	packets := [][]byte{
		harness.packet(40000, "alpha"),
		harness.packet(40000, "beta"),
	}
	before := make([][]byte, len(packets))
	for i, packet := range packets {
		before[i] = append([]byte(nil), packet...)
	}
	if unconsumed := harness.returnPath.ReturnPackets(packets); len(unconsumed) != 0 {
		t.Fatalf("%d packets passed back", len(unconsumed))
	}
	for i := range packets {
		if string(packets[i]) != string(before[i]) {
			t.Fatalf("packet %d changed: no rewrite rule was configured", i)
		}
	}
}

// TestReturnPacketsDownstreamCopiesDuringTheCall is the borrow contract: every writeback in this
// repository consumes the slice before returning, so a writeback that copies at call time must see
// the right bytes. A writeback that retained the slice past the call would be a new, unsupported
// contract, which is why the implementations are checked instead of assumed.
func TestReturnPacketsDownstreamCopiesDuringTheCall(t *testing.T) {
	writeback := &batchRecorder{}
	harness := newReturnHarness(t, writeback)

	packets := make([][]byte, 32)
	for i := range packets {
		packets[i] = harness.packet(40000, fmt.Sprintf("copy-%d", i))
	}
	if unconsumed := harness.returnPath.ReturnPackets(packets); len(unconsumed) != 0 {
		t.Fatalf("%d packets passed back", len(unconsumed))
	}
	copies := writeback.copies
	if len(copies) != 1 {
		t.Fatalf("expected one batch copy, got %d", len(copies))
	}
	for i, packet := range copies[0] {
		if want := fmt.Sprintf("copy-%d", i); string(packet[header.IPv4MinimumSize+header.UDPMinimumSize:]) != want {
			t.Fatalf("copy %d is %q, want %q", i, packet, want)
		}
	}
}

// TestReturnPacketsConcurrentWithClose runs the classifier against a dispatcher that is closing.
// Either outcome is legal; a panic, a double release or a hang is not.
func TestReturnPacketsConcurrentWithClose(t *testing.T) {
	writeback := &batchRecorder{}
	harness := newReturnHarness(t, writeback)

	// Each caller owns its batch: ReturnPackets may compact a batch in place when a packet is
	// dropped or passed, so sharing one input slice across goroutines is not a supported
	// contract and would be a race in the test, not in the product.
	var waitGroup sync.WaitGroup
	var calls atomic.Int64
	stop := make(chan struct{})
	for worker := 0; worker < 4; worker++ {
		packets := make([][]byte, 16)
		for i := range packets {
			packets[i] = harness.packet(40000, fmt.Sprintf("close-%d-%d", worker, i))
		}
		waitGroup.Add(1)
		go func(owned [][]byte) {
			defer waitGroup.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				harness.returnPath.ReturnPackets(owned)
				calls.Add(1)
			}
		}(packets)
	}
	time.Sleep(20 * time.Millisecond)
	harness.dispatcher.Close()
	time.Sleep(10 * time.Millisecond)
	close(stop)
	waitGroup.Wait()
	if calls.Load() == 0 {
		t.Fatal("the concurrent callers never ran")
	}
}

// TestReturnPacketsAllocationStaysZeroAtScale proves the fast path stays allocation-free at the
// sizes a TUN burst can reach, so the change is not only true for a single packet.
func TestReturnPacketsAllocationStaysZeroAtScale(t *testing.T) {
	writeback := &countingWriteback{}
	harness := newReturnHarness(t, writeback)

	for _, size := range []int{1, 64, 256, 1024} {
		packets := make([][]byte, size)
		for i := range packets {
			packets[i] = harness.packet(40000, "alloc")
		}
		allocations := testing.AllocsPerRun(50, func() {
			harness.returnPath.ReturnPackets(packets)
		})
		if allocations != 0 {
			t.Fatalf("size %d: expected 0 allocs, got %.2f", size, allocations)
		}
	}
}

// TestReturnPacketsLeavesAnAllWriteBatchUntouched pins the narrowed contract: when every packet is
// written back, the input slice must not be modified at all, because each compaction write would
// land on the element already in that position. Callers that share a read-only batch rely on it.
func TestReturnPacketsLeavesAnAllWriteBatchUntouched(t *testing.T) {
	writeback := &batchRecorder{}
	harness := newReturnHarness(t, writeback)

	packets := make([][]byte, 8)
	for i := range packets {
		packets[i] = harness.packet(40000, fmt.Sprintf("untouched-%d", i))
	}
	snapshot := append([][]byte(nil), packets...)
	if unconsumed := harness.returnPath.ReturnPackets(packets); len(unconsumed) != 0 {
		t.Fatalf("%d packets passed back", len(unconsumed))
	}
	for i := range packets {
		if &packets[i][0] != &snapshot[i][0] {
			t.Fatalf("packet %d was moved: an all-write batch must not be compacted", i)
		}
	}
}

// TestReturnPacketsCompactsAroundADroppedPacket proves the gap case still works: a packet that is
// passed back must not leave a hole in what the writeback receives.
func TestReturnPacketsCompactsAroundADroppedPacket(t *testing.T) {
	writeback := &batchRecorder{}
	harness := newReturnHarness(t, writeback)

	matchedA := harness.packet(40000, "a")
	unmatched := harness.packet(49999, "unmatched")
	matchedB := harness.packet(40000, "b")
	unconsumed := harness.returnPath.ReturnPackets([][]byte{matchedA, unmatched, matchedB})
	if len(unconsumed) != 1 {
		t.Fatalf("expected one unconsumed packet, got %d", len(unconsumed))
	}
	flat := writeback.flat()
	if len(flat) != 2 {
		t.Fatalf("the writeback must receive the two matched packets, got %d", len(flat))
	}
	if string(flat[0][header.IPv4MinimumSize+header.UDPMinimumSize:]) != "a" ||
		string(flat[1][header.IPv4MinimumSize+header.UDPMinimumSize:]) != "b" {
		t.Fatal("compaction around a gap must keep the matched packets in order")
	}
}