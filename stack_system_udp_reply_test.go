package tun

// The system stack synthesizes the UDP replies it answers itself. Two properties of those
// headers are easy to get wrong and impossible to see from the outside until a real peer
// misbehaves:
//
//   - the IPv4 ID must be per reply. A shared ID makes a reassembling peer treat unrelated
//     replies as fragments of one datagram, and the receiving stack then holds or discards
//     them.
//   - the header must be the REPLY's header. Copying the request's header carries its length
//     into the reply, and the reply then advertises a total length that does not match the
//     packet.
//
// The test drives the reply writer directly: preparePacketConnection builds it exactly as
// the UDP NAT's Prepare callback does, and preparePacket is what fills each reply.

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-tun/gtcpip"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// writeSystemUDPReply fills one reply through the writer's own prepare step, using the
// headroom the writer asks for, and returns the packet bytes.
func writeSystemUDPReply(t *testing.T, writer N.PacketWriter, server M.Socksaddr, payload []byte) []byte {
	t.Helper()
	headroom := writer.(interface{ FrontHeadroom() int }).FrontHeadroom()
	buffer := buf.NewSize(headroom + len(payload))
	buffer.Resize(headroom, 0)
	common.Must1(buffer.Write(payload))
	switch typed := writer.(type) {
	case *systemUDPPacketWriter4:
		typed.preparePacket(buffer, server)
	case *systemUDPPacketWriter6:
		typed.preparePacket(buffer, server)
	default:
		t.Fatalf("unexpected reply writer %T", writer)
	}
	packet := append([]byte(nil), buffer.Bytes()...)
	buffer.Release()
	return packet
}

func TestSystemUDPReplyHeadersCarryDistinctIPv4IDs(t *testing.T) {
	client := M.SocksaddrFrom(netip.MustParseAddr("10.7.0.2"), 40000)
	server := M.SocksaddrFrom(netip.MustParseAddr("93.184.216.34"), 443)
	system := &System{}
	_, _, writer, _ := system.preparePacketConnection(client, server, nil)

	var ids []uint16
	for range 2 {
		packet := writeSystemUDPReply(t, writer, server, []byte("dns-answer"))
		ipHdr := header.IPv4(packet)
		if int(ipHdr.TotalLength()) != len(packet) {
			t.Fatalf("reply total length = %d, packet length = %d", ipHdr.TotalLength(), len(packet))
		}
		if got := ipHdr.SourceAddress(); !got.Equal(tcpip.AddrFromSlice(server.Addr.AsSlice())) {
			t.Fatalf("reply source = %v, want the server %v", got, server.Addr)
		}
		if got := ipHdr.DestinationAddress(); !got.Equal(tcpip.AddrFromSlice(client.Addr.AsSlice())) {
			t.Fatalf("reply destination = %v, want the client %v", got, client.Addr)
		}
		udpHdr := header.UDP(ipHdr.Payload())
		if udpHdr.SourcePort() != server.Port {
			t.Fatalf("reply source port = %d, want %d", udpHdr.SourcePort(), server.Port)
		}
		if udpHdr.DestinationPort() != client.Port {
			t.Fatalf("reply destination port = %d, want the client's %d", udpHdr.DestinationPort(), client.Port)
		}
		if int(udpHdr.Length()) != header.UDPMinimumSize+len("dns-answer") {
			t.Fatalf("reply UDP length = %d", udpHdr.Length())
		}
		ids = append(ids, ipHdr.ID())
	}
	if ids[0] == ids[1] {
		t.Fatalf("two replies share IPv4 ID %d: a reassembling peer cannot tell them apart", ids[0])
	}
	if ids[1] != ids[0]+1 {
		t.Fatalf("reply IPv4 IDs jumped from %d to %d, want consecutive", ids[0], ids[1])
	}
}

func TestSystemUDPReplyHeadersAreSynthesizedPerFamily(t *testing.T) {
	client := M.SocksaddrFrom(netip.MustParseAddr("fdfe:dcba:9876::2"), 40001)
	server := M.SocksaddrFrom(netip.MustParseAddr("2001:db8::20"), 443)
	system := &System{}
	_, _, writer, _ := system.preparePacketConnection(client, server, nil)
	packet := writeSystemUDPReply(t, writer, server, []byte("answer"))
	ipHdr := header.IPv6(packet)
	if got := ipHdr.PayloadLength(); int(got) != header.UDPMinimumSize+len("answer") {
		t.Fatalf("reply payload length = %d", got)
	}
	if got := ipHdr.SourceAddress(); !got.Equal(tcpip.AddrFromSlice(server.Addr.AsSlice())) {
		t.Fatalf("reply source = %v, want the server %v", got, server.Addr)
	}
	if got := ipHdr.DestinationAddress(); !got.Equal(tcpip.AddrFromSlice(client.Addr.AsSlice())) {
		t.Fatalf("reply destination = %v, want the client %v", got, client.Addr)
	}
	udpHdr := header.UDP(ipHdr.Payload())
	if udpHdr.DestinationPort() != client.Port || udpHdr.SourcePort() != server.Port {
		t.Fatalf("reply ports = %d -> %d, want %d -> %d", udpHdr.SourcePort(), udpHdr.DestinationPort(), server.Port, client.Port)
	}
}
