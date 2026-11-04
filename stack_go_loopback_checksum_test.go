package tun

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
)

// Reflection exchanges the two addresses and writes the frame back to the platform. Two checksum
// facts decide whether the device accepts that frame, and they are opposite: the IPv4 header
// checksum covers the addresses and must be recomputed, while the TCP/UDP/ICMPv6 pseudo-header
// sums them and is therefore unchanged by a swap. Getting the first wrong makes every reflected
// IPv4 packet invalid; "fixing" the second needlessly rewrites a valid checksum.

func ipv4PacketWithChecksum(source, destination netip.Addr, protocol uint8, payload []byte) []byte {
	packet := make([]byte, header.IPv4MinimumSize+len(payload))
	ipHdr := header.IPv4(packet)
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		TTL:         64,
		Protocol:    protocol,
		SrcAddr:     source,
		DstAddr:     destination,
	})
	ipHdr.SetChecksum(0)
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	copy(packet[header.IPv4MinimumSize:], payload)
	return packet
}

func tcpSegmentWithChecksum(source, destination netip.Addr, sourcePort, destinationPort uint16, payload []byte) []byte {
	segment := make([]byte, header.TCPMinimumSize+len(payload))
	tcpHdr := header.TCP(segment)
	tcpHdr.Encode(&header.TCPFields{
		SrcPort:    sourcePort,
		DstPort:    destinationPort,
		SeqNum:     1,
		AckNum:     0,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 65535,
	})
	copy(segment[header.TCPMinimumSize:], payload)
	partial := header.PseudoHeaderChecksum(header.TCPProtocolNumber, source.AsSlice(), destination.AsSlice(), uint16(len(segment)))
	tcpHdr.SetChecksum(0)
	tcpHdr.SetChecksum(^checksum.Checksum(segment, partial))
	return segment
}

func TestSwapKeepsTheIPv4HeaderChecksumValid(t *testing.T) {
	t.Parallel()
	source := netip.MustParseAddr("198.18.0.1")
	loopback := netip.MustParseAddr("10.7.0.1")
	packet := ipv4PacketWithChecksum(source, loopback, uint8(header.TCPProtocolNumber), []byte{0, 0, 0, 0, 0, 0, 0, 0})
	if !header.IPv4(packet).IsChecksumValid() {
		t.Fatal("the test fixture starts out invalid")
	}

	swapLoopbackAddresses(packet, 4)

	if !header.IPv4(packet).IsChecksumValid() {
		t.Fatal("the reflected packet's IPv4 header checksum is invalid; the device would drop it")
	}
}

func TestSwapLeavesTheTransportChecksumValid(t *testing.T) {
	t.Parallel()
	// The pseudo-header sums both addresses, so exchanging them cannot invalidate a TCP, UDP or
	// ICMPv6 checksum. This pins that the reflection does not "helpfully" rewrite it.
	source := netip.MustParseAddr("198.18.0.1")
	loopback := netip.MustParseAddr("10.7.0.1")
	segment := tcpSegmentWithChecksum(source, loopback, 12345, 443, nil)
	packet := ipv4PacketWithChecksum(source, loopback, uint8(header.TCPProtocolNumber), segment)

	swapLoopbackAddresses(packet, 4)

	swappedSource := loopback
	swappedDestination := source
	transport := header.TCP(packet[header.IPv4MinimumSize:])
	partial := header.PseudoHeaderChecksum(header.TCPProtocolNumber, swappedSource.AsSlice(), swappedDestination.AsSlice(), uint16(len(transport)))
	if checksum.Checksum(transport, partial) != 0xffff {
		t.Fatal("the reflected TCP checksum is invalid")
	}
}

func TestSwapKeepsAnIPv6PacketWithoutAHeaderChecksum(t *testing.T) {
	t.Parallel()
	// IPv6 has no header checksum; the only thing to prove is that the swap does not invent one
	// or corrupt the payload.
	source := netip.MustParseAddr("fd00::1")
	loopback := netip.MustParseAddr("fdfe:7::1")
	packet := ipv6PacketBytes(source, loopback, []byte{0xaa, 0xbb, 0xcc})
	before := append([]byte(nil), packet...)
	swapLoopbackAddresses(packet, 6)
	if !equalBytes(packet[40:], before[40:]) {
		t.Fatal("the IPv6 payload was modified")
	}
}
