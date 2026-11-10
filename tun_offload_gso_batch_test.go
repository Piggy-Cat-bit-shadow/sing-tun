package tun

// A GSO frame read from a TUN can carry more segments than the caller's batch has buffers.
// The read path must split such a frame in several passes, each one continuing where the
// previous stopped, and each emitted segment must keep counting from the frame's start:
// the IPv4 ID and the TCP sequence number are positions inside the aggregate, not inside
// the pass. A pass that restarts them (or a read path that drops the remainder) hands the
// peer duplicate sequence numbers and shared IP IDs, which is what the previous
// hoist-the-frame-into-the-next-read implementation did.
//
// GSOSplit is the function that owns that contract, so the test drives it directly at the
// batch boundary: three passes over a five segment frame with a two buffer batch.

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-tun/gtcpip/header"
)

func buildGSOTCPv4Frame(headerLength int, segmentSize int, segmentCount int, firstID uint16, firstSeq uint32) []byte {
	frame := make([]byte, headerLength+segmentSize*segmentCount)
	header.IPv4(frame).Encode(&header.IPv4Fields{
		TotalLength: uint16(len(frame)),
		ID:          firstID,
		TTL:         synthesizedTTL,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     netip.MustParseAddr("192.0.2.10"),
		DstAddr:     netip.MustParseAddr("198.51.100.20"),
	})
	header.TCP(frame[header.IPv4MinimumSize:headerLength]).Encode(&header.TCPFields{
		SrcPort:    40000,
		DstPort:    443,
		SeqNum:     firstSeq,
		DataOffset: uint8(header.TCPMinimumSize),
		Flags:      header.TCPFlagPsh | header.TCPFlagAck,
		WindowSize: 65535,
	})
	for index := range segmentSize * segmentCount {
		frame[headerLength+index] = byte(index)
	}
	return frame
}

func TestGSOSplitResumesAcrossBatches(t *testing.T) {
	const (
		headerLength = header.IPv4MinimumSize + header.TCPMinimumSize
		segmentSize  = 100
		segmentCount = 5
		batchSize    = 2
		firstID      = uint16(7)
		firstSeq     = uint32(1000)
	)
	frame := buildGSOTCPv4Frame(headerLength, segmentSize, segmentCount, firstID, firstSeq)
	options := GSOOptions{
		GSOType:    GSOTCPv4,
		HdrLen:     uint16(headerLength),
		GSOSize:    uint16(segmentSize),
		CsumStart:  uint16(header.IPv4MinimumSize),
		CsumOffset: header.TCPChecksumOffset,
	}

	var (
		segment  int
		passes   int
		emitted  int
		expected = segmentCount
	)
	for {
		buffers := make([][]byte, batchSize)
		sizes := make([]int, batchSize)
		for index := range buffers {
			buffers[index] = make([]byte, 4096)
		}
		count, err := GSOSplit(frame, options, segment, buffers, sizes, 0)
		passes++
		if count == 0 {
			t.Fatalf("pass %d from segment %d emitted nothing (err %v)", passes, segment, err)
		}
		if count > batchSize {
			t.Fatalf("pass %d from segment %d emitted %d segments into %d buffers", passes, segment, count, batchSize)
		}
		for index := 0; index < count; index++ {
			if sizes[index] != headerLength+segmentSize {
				t.Fatalf("segment %d has size %d, want %d", segment+index, sizes[index], headerLength+segmentSize)
			}
			packet := buffers[index][:sizes[index]]
			ipHdr := header.IPv4(packet)
			wantID := firstID + uint16(segment+index)
			if got := ipHdr.ID(); got != wantID {
				t.Fatalf("pass %d segment %d: IPv4 ID = %d, want %d (IDs must count from the frame's start, not from the pass)", passes, segment+index, got, wantID)
			}
			tcpHdr := header.TCP(ipHdr.Payload())
			wantSeq := firstSeq + uint32(segmentSize*(segment+index))
			if got := tcpHdr.SequenceNumber(); got != wantSeq {
				t.Fatalf("pass %d segment %d: TCP sequence = %d, want %d (sequence numbers must count from the frame's start, not from the pass)", passes, segment+index, got, wantSeq)
			}
			emitted++
		}
		segment += count
		if err == nil {
			if segment != expected {
				t.Fatalf("the frame produced %d segments, want %d", segment, expected)
			}
			break
		}
		if !errors.Is(err, ErrTooManySegments) {
			t.Fatalf("pass %d from segment %d failed: %v", passes, segment-count, err)
		}
		if count != batchSize {
			t.Fatalf("a short pass (%d of %d buffers) returned ErrTooManySegments", count, batchSize)
		}
		if passes > segmentCount {
			t.Fatalf("splitting did not terminate after %d passes", passes)
		}
	}
	if emitted != segmentCount {
		t.Fatalf("emitted %d segments, want %d", emitted, segmentCount)
	}
	if passes != 3 {
		t.Fatalf("a %d segment frame split into %d buffer batches took %d passes, want 3", segmentCount, batchSize, passes)
	}
}

// TestGSOSplitSinglePassNeedsNoResume pins the boundary: a frame that fits the batch is
// emitted in one pass and reports no error, so the read path clears its pending state
// instead of repeating the same segments on the next read.
func TestGSOSplitSinglePassNeedsNoResume(t *testing.T) {
	const (
		headerLength = header.IPv4MinimumSize + header.TCPMinimumSize
		segmentSize  = 100
		segmentCount = 2
	)
	frame := buildGSOTCPv4Frame(headerLength, segmentSize, segmentCount, 40, 500)
	options := GSOOptions{
		GSOType:    GSOTCPv4,
		HdrLen:     uint16(headerLength),
		GSOSize:    uint16(segmentSize),
		CsumStart:  uint16(header.IPv4MinimumSize),
		CsumOffset: header.TCPChecksumOffset,
	}
	buffers := [][]byte{make([]byte, 4096), make([]byte, 4096), make([]byte, 4096)}
	sizes := make([]int, len(buffers))
	count, err := GSOSplit(frame, options, 0, buffers, sizes, 0)
	if err != nil {
		t.Fatalf("a frame that fits the batch failed: %v", err)
	}
	if count != segmentCount {
		t.Fatalf("emitted %d segments, want %d", count, segmentCount)
	}
}
