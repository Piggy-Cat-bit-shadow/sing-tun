package tun

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-tun/gtcpip/header"
)

// The loopback hairpin is the whole data-plane half of the local signing loopback feature: every
// stack above it only decides which packets reach it. These tests pin the two properties the
// packet path depends on - which transports are reflected, and that reflection exchanges exactly
// the addresses and nothing else - because a mistake in either is invisible until a device fails
// to reach its own service.

func TestIsLoopbackProtocolCoversEveryTransportTheAddressMeans(t *testing.T) {
	t.Parallel()
	for _, protocol := range []uint8{
		uint8(header.TCPProtocolNumber),
		uint8(header.UDPProtocolNumber),
		uint8(header.ICMPv4ProtocolNumber),
		uint8(header.ICMPv6ProtocolNumber),
	} {
		if !isLoopbackProtocol(protocol) {
			t.Fatalf("protocol %d is not reflected", protocol)
		}
	}
	for _, protocol := range []uint8{132 /* SCTP */, 47 /* GRE */, 0} {
		if isLoopbackProtocol(protocol) {
			t.Fatalf("protocol %d should not be reflected", protocol)
		}
	}
}

func ipv4PacketBytes(source, destination netip.Addr, payload []byte) []byte {
	packet := make([]byte, header.IPv4MinimumSize+len(payload))
	packet[0] = 0x45 // version 4, header length 5 words
	copy(packet[12:16], source.AsSlice())
	copy(packet[16:20], destination.AsSlice())
	copy(packet[header.IPv4MinimumSize:], payload)
	return packet
}

func ipv6PacketBytes(source, destination netip.Addr, payload []byte) []byte {
	packet := make([]byte, header.IPv6MinimumSize+len(payload))
	packet[0] = 0x60 // version 6
	copy(packet[8:24], source.AsSlice())
	copy(packet[24:40], destination.AsSlice())
	copy(packet[header.IPv6MinimumSize:], payload)
	return packet
}

func TestSwapLoopbackAddressesExchangesOnlyTheAddresses(t *testing.T) {
	t.Parallel()
	source := netip.MustParseAddr("198.18.0.1")
	loopback := netip.MustParseAddr("10.7.0.1")
	// A TCP header's worth of bytes, distinct from the addresses so a misplaced write shows up.
	payload := []byte{0x00, 0x50, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef}
	packet := ipv4PacketBytes(source, loopback, payload)
	before := append([]byte(nil), packet...)

	swapLoopbackAddresses(packet, 4)

	if !equalBytes(packet[12:16], loopback.AsSlice()) {
		t.Fatalf("source is %v, want the loopback address", packet[12:16])
	}
	if !equalBytes(packet[16:20], source.AsSlice()) {
		t.Fatalf("destination is %v, want the original source", packet[16:20])
	}
	if !equalBytes(packet[header.IPv4MinimumSize:], before[header.IPv4MinimumSize:]) {
		t.Fatal("the transport payload was modified")
	}
}

func TestSwapLoopbackAddressesHandlesIPv6(t *testing.T) {
	t.Parallel()
	source := netip.MustParseAddr("fd00::1")
	loopback := netip.MustParseAddr("fdfe:7::1")
	packet := ipv6PacketBytes(source, loopback, []byte{0x12, 0x34})

	swapLoopbackAddresses(packet, 6)

	if !equalBytes(packet[8:24], loopback.AsSlice()) {
		t.Fatalf("source is %v", packet[8:24])
	}
	if !equalBytes(packet[24:40], source.AsSlice()) {
		t.Fatalf("destination is %v", packet[24:40])
	}
}

func TestSwapLoopbackAddressesIgnoresTruncatedPackets(t *testing.T) {
	t.Parallel()
	// A short frame must not panic on the address write: the engine's parser already rejects it,
	// and this function is the last place a malformed packet would reach a slice index.
	ipv4 := make([]byte, 16)
	copy(ipv4[12:16], netip.MustParseAddr("198.18.0.1").AsSlice())
	swapLoopbackAddresses(ipv4, 4)
	if !equalBytes(ipv4[12:16], netip.MustParseAddr("198.18.0.1").AsSlice()) {
		t.Fatal("a truncated IPv4 packet was modified")
	}
	ipv6 := make([]byte, 24)
	swapLoopbackAddresses(ipv6, 6)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
