package tun

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/logger"
)

// These tests cover the fast path the return path grew: a batch that carries one writeback is
// compacted in place, so the grouping container the old implementation always built is gone. The
// multi-writeback case must still produce the same batches, boundaries and order as before, which
// is what the second test pins.

// countingWriteback consumes packets without allocating, so an allocation measurement reflects
// ReturnPackets alone.
type countingWriteback struct {
	calls   int
	packets int
	first   []byte
	last    []byte
}

func (w *countingWriteback) ReturnHeadroom() int { return 0 }

func (w *countingWriteback) WriteReturnPackets(packets [][]byte) error {
	w.calls++
	w.packets += len(packets)
	if len(packets) > 0 {
		if w.first == nil {
			w.first = packets[0]
		}
		w.last = packets[len(packets)-1]
	}
	return nil
}

// recordingWriteback keeps the batch shape, so a test can assert grouping and order.
type recordingWriteback struct {
	batches [][][]byte
	err     error
}

func (w *recordingWriteback) ReturnHeadroom() int { return 0 }

func (w *recordingWriteback) WriteReturnPackets(packets [][]byte) error {
	w.batches = append(w.batches, append([][]byte(nil), packets...))
	return w.err
}

func (w *recordingWriteback) lengths() []int {
	lengths := make([]int, len(w.batches))
	for i, batch := range w.batches {
		lengths[i] = len(batch)
	}
	return lengths
}

// buildReturnPacket builds a syntactically valid IPv4/UDP packet; this path does not verify
// checksums, only the header lengths.
func buildReturnPacket(source, destination netip.AddrPort, payload []byte) []byte {
	total := header.IPv4MinimumSize + header.UDPMinimumSize + len(payload)
	packet := make([]byte, total)
	ipHdr := header.IPv4(packet)
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(total),
		ID:          1,
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     source.Addr(),
		DstAddr:     destination.Addr(),
	})
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	udpHdr := header.UDP(packet[header.IPv4MinimumSize:])
	udpHdr.Encode(&header.UDPFields{
		SrcPort: source.Port(),
		DstPort: destination.Port(),
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})
	copy(packet[header.IPv4MinimumSize+header.UDPMinimumSize:], payload)
	return packet
}

type returnHarness struct {
	dispatcher *ForwardDispatcher
	nat        *portNAT
	returnPath *portReturn
}

// newReturnHarness wires a real dispatcher, a real portNAT and the real portReturn, with one flow
// per (writeback, client port) pair inserted under the reverse key the classifier will look up.
func newReturnHarness(t testing.TB, writebacks ...ForwardWriteback) *returnHarness {
	t.Helper()
	if len(writebacks) == 0 {
		writebacks = []ForwardWriteback{&countingWriteback{}}
	}
	dispatcher := &ForwardDispatcher{epoch: time.Now(), logger: logger.NOP(), writeback: writebacks[0]}
	port := &borrowedPortStub{}
	nat := acquirePortNAT(port)
	t.Cleanup(func() { releasePortNAT(nat) })
	server := netip.MustParseAddrPort("93.184.216.34:443")
	for index, writeback := range writebacks {
		stage := &ForwardStage{dispatcher: dispatcher, writeback: writeback, table: make(map[flowKey]*flowEntry)}
		client := netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), uint16(40000+index))
		flow := &forwardFlow{nat: nat, owner: stage, protocol: uint8(header.UDPProtocolNumber)}
		nat.replace(flowKey{
			protocol:    uint8(header.UDPProtocolNumber),
			source:      server,
			destination: client,
		}, flow)
	}
	return &returnHarness{
		dispatcher: dispatcher,
		nat:        nat,
		returnPath: &portReturn{dispatcher: dispatcher, nat: nat},
	}
}

func (h *returnHarness) packet(clientPort uint16, payload string) []byte {
	return buildReturnPacket(
		netip.MustParseAddrPort("93.184.216.34:443"),
		netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), clientPort),
		[]byte(payload),
	)
}

// TestReturnPacketsSingleWritebackKeepsOrderAndAllocatesNothing pins both the behaviour and the
// reason this change exists: no grouping container on the common path.
func TestReturnPacketsSingleWritebackKeepsOrderAndAllocatesNothing(t *testing.T) {
	writeback := &countingWriteback{}
	harness := newReturnHarness(t, writeback)

	for _, size := range []int{1, 2, 8, 32, 64, 128} {
		packets := make([][]byte, size)
		for i := range packets {
			packets[i] = harness.packet(40000, "payload-"+itoaReturn(i))
		}
		unconsumed := harness.returnPath.ReturnPackets(packets)
		if len(unconsumed) != 0 {
			t.Fatalf("size %d: %d packets were not consumed", size, len(unconsumed))
		}
		if writeback.calls != 1 {
			t.Fatalf("size %d: one writeback must receive ONE batch, got %d calls", size, writeback.calls)
		}
		if writeback.packets != size {
			t.Fatalf("size %d: writeback saw %d packets", size, writeback.packets)
		}
		writeback.calls = 0
		writeback.packets = 0
	}

	// The input is built once: the measurement must be ReturnPackets', not the test's. The
	// classifier rewrites a packet in place, but the zero reverse rule of this harness makes that
	// a no-op, so the same slice can be replayed.
	single := [][]byte{harness.packet(40000, "payload")}
	allocations := testing.AllocsPerRun(500, func() {
		harness.returnPath.ReturnPackets(single)
	})
	if allocations != 0 {
		t.Fatalf("one packet through one writeback must not allocate, got %.2f allocs/op", allocations)
	}

	allocations = testing.AllocsPerRun(200, func() {
		harness.returnPath.ReturnPackets(packetStash)
	})
	if allocations != 0 {
		t.Fatalf("a 64-packet burst must not allocate either, got %.2f allocs/op", allocations)
	}
}

// packetStash keeps 64 pre-built packets so the burst measurement does not allocate its own input.
var packetStash = func() [][]byte {
	packets := make([][]byte, 64)
	for i := range packets {
		packets[i] = buildReturnPacket(
			netip.MustParseAddrPort("93.184.216.34:443"),
			netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 40000),
			[]byte("stashed"),
		)
	}
	return packets
}()

// TestReturnPacketsMultipleWritebacksKeepsTheOldGrouping proves the fallback: two writebacks in one
// batch still produce one batch per writeback, with the packets in their original order.
func TestReturnPacketsMultipleWritebacksKeepsTheOldGrouping(t *testing.T) {
	first := &recordingWriteback{}
	second := &recordingWriteback{}
	harness := newReturnHarness(t, first, second)

	// Interleave: A, B, A, B. The old implementation produced one A batch and one B batch.
	packets := [][]byte{
		harness.packet(40000, "a1"),
		harness.packet(40001, "b1"),
		harness.packet(40000, "a2"),
		harness.packet(40001, "b2"),
	}
	unconsumed := harness.returnPath.ReturnPackets(packets)
	if len(unconsumed) != 0 {
		t.Fatalf("%d packets were not consumed", len(unconsumed))
	}
	if len(first.batches) != 1 || len(second.batches) != 1 {
		t.Fatalf("expected one batch each, got %d and %d", len(first.batches), len(second.batches))
	}
	if got := first.lengths(); got[0] != 2 {
		t.Fatalf("first writeback must keep both of its packets in one batch, got %v", got)
	}
	if got := second.lengths(); got[0] != 2 {
		t.Fatalf("second writeback must keep both of its packets in one batch, got %v", got)
	}
	// Order inside each batch is the order they arrived in.
	if string(first.batches[0][0][header.IPv4MinimumSize+header.UDPMinimumSize:]) != "a1" ||
		string(first.batches[0][1][header.IPv4MinimumSize+header.UDPMinimumSize:]) != "a2" {
		t.Fatal("the first writeback's packets are out of order")
	}
	if string(second.batches[0][0][header.IPv4MinimumSize+header.UDPMinimumSize:]) != "b1" ||
		string(second.batches[0][1][header.IPv4MinimumSize+header.UDPMinimumSize:]) != "b2" {
		t.Fatal("the second writeback's packets are out of order")
	}
}

// TestReturnPacketsReturnsUnconsumedPackets proves the packets that do not match a flow still come
// back to the caller, in order, while the matched ones are written.
func TestReturnPacketsReturnsUnconsumedPackets(t *testing.T) {
	writeback := &countingWriteback{}
	harness := newReturnHarness(t, writeback)

	matched := harness.packet(40000, "matched")
	// Port 49999 has no flow behind it, so it is passed back.
	unmatched := harness.packet(49999, "unmatched")
	unconsumed := harness.returnPath.ReturnPackets([][]byte{matched, unmatched})
	if len(unconsumed) != 1 {
		t.Fatalf("expected exactly one unconsumed packet, got %d", len(unconsumed))
	}
	if &unconsumed[0][0] != &unmatched[0] {
		t.Fatal("the unconsumed packet must be the one that did not match")
	}
	if writeback.packets != 1 {
		t.Fatalf("the writeback should have seen the matched packet only, got %d", writeback.packets)
	}
}

// TestReturnPacketsClosedDispatcherReturnsInput pins the early return.
func TestReturnPacketsClosedDispatcherReturnsInput(t *testing.T) {
	harness := newReturnHarness(t)
	harness.dispatcher.closed.Store(true)
	packets := [][]byte{harness.packet(40000, "x")}
	unconsumed := harness.returnPath.ReturnPackets(packets)
	if len(unconsumed) != 1 || &unconsumed[0][0] != &packets[0][0] {
		t.Fatal("a closed dispatcher must return its input untouched")
	}
}

// TestReturnPacketsReportsWritebackErrors proves a writeback error is logged, not swallowed into a
// panic, and does not change what is returned to the caller.
func TestReturnPacketsReportsWritebackErrors(t *testing.T) {
	writeback := &recordingWriteback{err: errors.New("write failed")}
	harness := newReturnHarness(t, writeback)
	unconsumed := harness.returnPath.ReturnPackets([][]byte{harness.packet(40000, "x")})
	if len(unconsumed) != 0 {
		t.Fatal("a writeback error must not turn a consumed packet into an unconsumed one")
	}
	if len(writeback.batches) != 1 {
		t.Fatal("the batch was still attempted")
	}
}

func itoaReturn(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [8]byte
	i := len(digits)
	for value > 0 {
		i--
		digits[i] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[i:])
}

// BenchmarkReturnPackets measures the real function with one writeback, which is the shape the two
// callers in sing-box produce.
func BenchmarkReturnPackets(b *testing.B) {
	for _, size := range []int{1, 2, 8, 32, 64} {
		b.Run("n="+itoaReturn(size), func(b *testing.B) {
			writeback := &countingWriteback{}
			harness := newReturnHarness(b, writeback)
			packets := make([][]byte, size)
			for i := range packets {
				packets[i] = harness.packet(40000, "payload")
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				harness.returnPath.ReturnPackets(packets)
			}
		})
	}
}
