package tun

import (
	"testing"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// A full session queue must count what it drops; otherwise a shedding tunnel is indistinguishable
// from an idle one.
func TestUDPNatCountsQueueFullDrop(t *testing.T) {
	conn := &UDPNatConn{
		packetChan: make(chan *N.PacketBuffer, 1),
		doneChan:   make(chan struct{}),
	}
	conn.enqueue(buf.NewSize(16), M.Socksaddr{})
	before := UDPNatDroppedPackets()
	conn.enqueue(buf.NewSize(16), M.Socksaddr{})
	if got := UDPNatDroppedPackets() - before; got != 1 {
		t.Fatalf("queue-full drop counted %d times, want 1", got)
	}
	select {
	case packet := <-conn.packetChan:
		packet.Buffer.Release()
		N.PutPacketBuffer(packet)
	default:
		t.Fatal("the first packet must still be queued")
	}
}

// A datagram that arrives after the session closed is dropped too, and it must be counted.
func TestUDPNatCountsClosedSessionDrop(t *testing.T) {
	conn := &UDPNatConn{
		packetChan: make(chan *N.PacketBuffer, 1),
		doneChan:   make(chan struct{}),
	}
	close(conn.doneChan)
	before := UDPNatDroppedPackets()
	conn.enqueue(buf.NewSize(16), M.Socksaddr{})
	if got := UDPNatDroppedPackets() - before; got != 1 {
		t.Fatalf("closed-session drop counted %d times, want 1", got)
	}
}
