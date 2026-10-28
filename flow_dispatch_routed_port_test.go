package tun

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/logger"
)

// routedPortStub is a Port the dispatcher routes a flow into, the way the Go stack serves a local
// flow. It records what it was handed so the test can prove the forward packet reached the port.
type routedPortStub struct {
	attached Return
	packets  [][]byte
}

func (p *routedPortStub) PortAddresses() (netip.Addr, netip.Addr) {
	return netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("fd00::1")
}
func (p *routedPortStub) PortMTU() uint32 { return 1500 }
func (p *routedPortStub) AttachReturn(returnPath Return) error {
	p.attached = returnPath
	return nil
}
func (p *routedPortStub) DetachReturn(Return) error { return nil }
func (p *routedPortStub) WritePackets(packets [][]byte) error {
	p.packets = append(p.packets, packets...)
	return nil
}
func (p *routedPortStub) RoutedPort() {}

// routedWriteback is the layer a consumed return is written back through. Unlike the existing
// recordingWriteback it carries a headroom, because a return accepted off the stack has to be given
// the prefix ReturnPackets slices by.
type routedWriteback struct {
	headroom int
	packets  [][]byte
}

func (w *routedWriteback) ReturnHeadroom() int { return w.headroom }
func (w *routedWriteback) WriteReturnPackets(packets [][]byte) error {
	for _, packet := range packets {
		w.packets = append(w.packets, append([]byte(nil), packet...))
	}
	return nil
}

// buildTestIPv4TCP builds the header-only frame parseForwardPacket needs. Checksums are left zero:
// the parser does not validate them, and the dispatcher recomputes the ones it rewrites.
func buildTestIPv4TCP(t *testing.T, source netip.AddrPort, destination netip.AddrPort, flags header.TCPFlags) []byte {
	t.Helper()
	packet := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = uint8(header.TCPProtocolNumber)
	copy(packet[12:16], source.Addr().AsSlice())
	copy(packet[16:20], destination.Addr().AsSlice())
	transport := packet[header.IPv4MinimumSize:]
	binary.BigEndian.PutUint16(transport[0:2], source.Port())
	binary.BigEndian.PutUint16(transport[2:4], destination.Port())
	transport[12] = 5 << 4
	transport[13] = byte(flags)
	binary.BigEndian.PutUint16(transport[14:16], 65535)
	return packet
}

func newRoutedPortDispatcher() (*ForwardDispatcher, *ForwardStage, *routedWriteback) {
	writeback := &routedWriteback{headroom: 9}
	dispatcher := NewForwardDispatcher(nil, writeback, logger.NOP(), UDPNatOptions{}, 0)
	return dispatcher, dispatcher.NewStage(writeback, nil), writeback
}

// Nothing is consumed while no routed port is registered: the stack keeps writing its own packets
// exactly as before the feature existed.
func TestReturnParsedPassesThroughWithoutRoutedPort(t *testing.T) {
	dispatcher, stage, writeback := newRoutedPortDispatcher()
	defer dispatcher.Close()
	packet := buildTestIPv4TCP(t,
		netip.MustParseAddrPort("10.0.0.1:443"),
		netip.MustParseAddrPort("10.0.0.2:12345"), header.TCPFlagAck)
	if stage.ReturnParsed(packet, ForwardFrameMeta{}, nil) {
		t.Fatal("a packet must not be consumed while no routed port is registered")
	}
	if len(writeback.packets) != 0 {
		t.Fatalf("writeback received %d packets, want 0", len(writeback.packets))
	}
}

// A registered routed port still must not swallow packets that belong to no flow: it only takes the
// ones its own return classifier matches.
func TestReturnParsedPassesThroughUnmatchedFlow(t *testing.T) {
	dispatcher, stage, writeback := newRoutedPortDispatcher()
	defer dispatcher.Close()
	port := &routedPortStub{}
	if nat := dispatcher.natFor(port); nat == nil {
		t.Fatal("the routed port was not registered")
	}
	packet := buildTestIPv4TCP(t,
		netip.MustParseAddrPort("10.0.0.1:443"),
		netip.MustParseAddrPort("10.0.0.2:12345"), header.TCPFlagAck)
	if stage.ReturnParsed(packet, ForwardFrameMeta{}, nil) {
		t.Fatal("a packet that matches no flow must not be consumed")
	}
	if len(writeback.packets) != 0 {
		t.Fatalf("writeback received %d packets, want 0", len(writeback.packets))
	}
}

// A return that belongs to a flow the routed port serves is consumed and written back through the
// flow's writeback with the reverse rewrite applied: the client sees the original destination, not
// the stack address the flow was routed to.
func TestReturnParsedConsumesAndRewritesFlowReturn(t *testing.T) {
	dispatcher, stage, writeback := newRoutedPortDispatcher()
	defer dispatcher.Close()
	port := &routedPortStub{}

	client := netip.MustParseAddrPort("10.0.0.2:12345")
	destination := netip.MustParseAddrPort("1.1.1.1:443")
	syn := buildTestIPv4TCP(t, client, destination, header.TCPFlagSyn)
	parsed, ok := parseForwardPacket(syn)
	if !ok {
		t.Fatal("the test SYN did not parse")
	}
	verdict := FlowVerdict{
		Action:      ActionFlow,
		Port:        port,
		Destination: netip.MustParseAddrPort("10.0.0.1:443"),
	}
	key := parsed.flowKey()
	stage.access.Lock()
	installed := stage.install(key, &parsed, syn, nil, verdict, dispatcher.now())
	stage.access.Unlock()
	if !installed {
		t.Fatal("the flow was not installed on the routed port")
	}
	stage.Flush()
	if len(port.packets) != 1 {
		t.Fatalf("the routed port received %d packets, want 1", len(port.packets))
	}

	// The stack answers the rewritten source, which is the selector the NAT handed the flow, not the
	// client's own port.
	entry := stage.table[key]
	if entry == nil || entry.flow == nil {
		t.Fatal("the installed flow is missing from the stage table")
	}
	selector := entry.flow.forwardRule.sourcePort
	reply := buildTestIPv4TCP(t,
		netip.MustParseAddrPort("10.0.0.1:443"),
		netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), selector), header.TCPFlagAck)
	if !stage.ReturnParsed(reply, ForwardFrameMeta{}, nil) {
		t.Fatal("the return of an installed flow must be consumed")
	}
	if len(writeback.packets) != 1 {
		t.Fatalf("writeback received %d packets, want 1", len(writeback.packets))
	}
	written := writeback.packets[0]
	if len(written) != writeback.headroom+len(reply) {
		t.Fatalf("written packet is %d bytes, want %d", len(written), writeback.headroom+len(reply))
	}
	ipHeader := header.IPv4(written[writeback.headroom:])
	if ipHeader.SourceAddress() != addrToTCPIP(destination.Addr()) {
		t.Fatalf("source address = %v, want the original destination %v", ipHeader.SourceAddress(), destination.Addr())
	}
	if ipHeader.DestinationAddress() != addrToTCPIP(client.Addr()) {
		t.Fatalf("destination address = %v, want the client %v", ipHeader.DestinationAddress(), client.Addr())
	}
}

// The marker is what the dispatcher keys the routed path on: a Port that does not implement it must
// never become the routed port, however many flows it serves.
func TestRoutedPortNotRegisteredForPlainPort(t *testing.T) {
	dispatcher, _, _ := newRoutedPortDispatcher()
	defer dispatcher.Close()
	port := &borrowedPortStub{}
	if nat := dispatcher.natFor(port); nat == nil {
		t.Fatal("the plain port was not registered")
	}
	if dispatcher.routedPort.Load() != nil {
		t.Fatal("a plain port must not become the routed port")
	}
}
