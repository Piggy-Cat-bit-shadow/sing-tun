package tun

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
)

type packetBufferPortStub struct {
	headroom int
	refuse   bool

	starts   []int
	payloads [][]byte
	releases int
}

func (p *packetBufferPortStub) PortAddresses() (netip.Addr, netip.Addr) {
	return netip.Addr{}, netip.Addr{}
}
func (p *packetBufferPortStub) PortMTU() uint32             { return 1500 }
func (p *packetBufferPortStub) AttachReturn(Return) error   { return nil }
func (p *packetBufferPortStub) DetachReturn(Return) error   { return nil }
func (p *packetBufferPortStub) WritePackets([][]byte) error { return nil }
func (p *packetBufferPortStub) PacketHeadroom() int         { return p.headroom }

func (p *packetBufferPortStub) WritePacketBuffers(buffers []*buf.Buffer) error {
	// The contract is ownership ALWAYS: consume every buffer even when refusing.
	for _, buffer := range buffers {
		p.starts = append(p.starts, buffer.Start())
		p.payloads = append(p.payloads, append([]byte(nil), buffer.Bytes()...))
		buffer.Release()
		p.releases++
	}
	if p.refuse {
		return errors.New("refused")
	}
	return nil
}

type borrowedPortStub struct {
	packets [][]byte
}

func (p *borrowedPortStub) PortAddresses() (netip.Addr, netip.Addr) {
	return netip.Addr{}, netip.Addr{}
}
func (p *borrowedPortStub) PortMTU() uint32           { return 1500 }
func (p *borrowedPortStub) AttachReturn(Return) error { return nil }
func (p *borrowedPortStub) DetachReturn(Return) error { return nil }
func (p *borrowedPortStub) WritePackets(packets [][]byte) error {
	p.packets = append(p.packets, packets...)
	return nil
}

func newTestForwardStage() *ForwardStage {
	return &ForwardStage{
		dispatcher: &ForwardDispatcher{epoch: time.Now(), logger: logger.NOP()},
		table:      make(map[flowKey]*flowEntry),
	}
}

// A port that takes owned buffers must receive one headroomed buffer per packet, with the bytes
// copied exactly once by the dispatcher.
func TestForwardStageHandsOwnedBuffersToPacketBufferPort(t *testing.T) {
	port := &packetBufferPortStub{headroom: 9}
	stage := newTestForwardStage()
	nat := &portNAT{port: port}
	first := []byte{0x45, 0, 0, 20, 1, 2, 3, 4}
	second := []byte{0x45, 0, 0, 20, 5, 6, 7, 8}
	stage.stagePort(nat, first)
	stage.stagePort(nat, second)

	if len(stage.ports) != 1 || len(stage.ports[0].buffers) != 2 || len(stage.ports[0].packets) != 0 {
		t.Fatalf("owned port must stage buffers only: ports=%d buffers=%d packets=%d",
			len(stage.ports), len(stage.ports[0].buffers), len(stage.ports[0].packets))
	}
	stage.Flush()

	if len(port.payloads) != 2 {
		t.Fatalf("port received %d packets, want 2", len(port.payloads))
	}
	for i, want := range [][]byte{first, second} {
		if port.starts[i] != 9 {
			t.Fatalf("packet %d start = %d, want headroom 9", i, port.starts[i])
		}
		if !bytes.Equal(port.payloads[i], want) {
			t.Fatalf("packet %d payload changed: %x", i, port.payloads[i])
		}
	}
	if len(stage.ports[0].buffers) != 0 {
		t.Fatal("staged buffers must be cleared after the flush")
	}
}

// A refusal is reported, but ownership has already moved: the port consumed and released every
// buffer, so the stage must not release them again.
func TestForwardStageOwnedBuffersSurviveRefusal(t *testing.T) {
	port := &packetBufferPortStub{headroom: 9, refuse: true}
	stage := newTestForwardStage()
	stage.stagePort(&portNAT{port: port}, []byte{0x45, 0, 0, 20})
	stage.Flush()
	if port.releases != 1 {
		t.Fatalf("a refused owned batch must be released exactly once by the port, got %d", port.releases)
	}
	if len(stage.ports[0].buffers) != 0 {
		t.Fatal("staged buffers must be cleared after the flush")
	}
}

// A port without the capability keeps the borrowed staging path and WritePackets.
func TestForwardStageKeepsBorrowedPathForPlainPort(t *testing.T) {
	port := &borrowedPortStub{}
	stage := newTestForwardStage()
	payload := []byte{0x45, 0, 0, 20, 9, 9}
	stage.stagePort(&portNAT{port: port}, payload)
	if len(stage.ports[0].packets) != 1 || len(stage.ports[0].buffers) != 0 {
		t.Fatal("a plain port must keep the borrowed staging path")
	}
	stage.Flush()
	if len(port.packets) != 1 || !bytes.Equal(port.packets[0], payload) {
		t.Fatalf("plain port received %d packets", len(port.packets))
	}
}

// Closing a dispatcher with staged owned packets must release them instead of leaking them.
func TestForwardDispatcherCloseReleasesStagedOwnedBuffers(t *testing.T) {
	port := &packetBufferPortStub{headroom: 9}
	dispatcher := &ForwardDispatcher{epoch: time.Now(), logger: logger.NOP()}
	stage := dispatcher.NewStage(nil, nil)
	stage.stagePort(&portNAT{port: port}, []byte{0x45, 0, 0, 20})
	if len(stage.ports[0].buffers) != 1 {
		t.Fatal("the packet was not staged as an owned buffer")
	}
	dispatcher.Close()
	if stage.ports[0].buffers != nil {
		t.Fatal("close must release and clear staged owned buffers")
	}
	if port.releases != 0 {
		t.Fatal("close must release staged buffers directly, not hand them to the port")
	}
}
