package tun

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing-tun/gtcpip/header"
)

// The close-dependency edge, pinned as a regression test.
//
// # Why this test exists
//
// Flush holds the stage lock while it hands the staged packets to the port. If the port blocks --
// a QUIC DATAGRAM queue that cannot drain is the real case -- then Close, Dispatch and the idle
// sweeper on the same stage wait for it. The stack's own shutdown reaches this path through Go.Close,
// which posts a close message to the engine and then waits for its exit signal; the engine goroutine
// is the one calling Flush, so a blocked port write delays the whole stack close.
//
// The test is deterministic on purpose: a channel marks the exact moment the write is inside the
// port, and the assertion is "Close has not returned while the port holds the call", not "Close is
// usually slow". Releasing the port must complete both operations, which is what makes this a wait
// and not a deadlock.

// blockingBufferPort is a PacketBufferPort that parks inside WritePacketBuffers until released.
type blockingBufferPort struct {
	access   sync.Mutex
	entered  chan struct{}
	release  chan struct{}
	enterOne sync.Once
	received [][]byte
	attached Return
}

func newBlockingBufferPort() *blockingBufferPort {
	return &blockingBufferPort{entered: make(chan struct{}), release: make(chan struct{})}
}

func (p *blockingBufferPort) PortAddresses() (netip.Addr, netip.Addr) {
	// A UDP flow binds a NAT endpoint on the port, so the port has to have addresses: without them
	// createFlow refuses and Dispatch reports false before anything is staged.
	return netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("fdfe:dcba:9876::1")
}

func (p *blockingBufferPort) PortMTU() uint32 { return 1500 }

func (p *blockingBufferPort) AttachReturn(returnPath Return) error {
	p.access.Lock()
	p.attached = returnPath
	p.access.Unlock()
	return nil
}

func (p *blockingBufferPort) DetachReturn(Return) error { return nil }

func (p *blockingBufferPort) WritePackets([][]byte) error { return nil }

func (p *blockingBufferPort) PacketHeadroom() int { return 9 }

func (p *blockingBufferPort) WritePacketBuffers(buffers []*buf.Buffer) error {
	p.enterOne.Do(func() { close(p.entered) })
	<-p.release
	p.access.Lock()
	for _, buffer := range buffers {
		p.received = append(p.received, append([]byte(nil), buffer.Bytes()...))
	}
	p.access.Unlock()
	// The port owns these buffers, so it releases them exactly once, like a real port does.
	buf.ReleaseMulti(buffers)
	return nil
}

func (p *blockingBufferPort) receivedPackets() [][]byte {
	p.access.Lock()
	defer p.access.Unlock()
	return append([][]byte(nil), p.received...)
}

// blockingPortHandler routes every flow to the blocking port.
type blockingPortHandler struct {
	Handler
	port Port
}

func (h *blockingPortHandler) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) FlowVerdict {
	return FlowVerdict{Action: ActionFlow, Port: h.port, Destination: destination}
}

func TestDispatcherCloseWaitsForAnInFlightPortWrite(t *testing.T) {
	port := newBlockingBufferPort()
	writeback := &countingWriteback{}
	dispatcher := NewForwardDispatcher(&blockingPortHandler{port: port}, writeback, logger.NOP(), UDPNatOptions{}, 0)
	t.Cleanup(dispatcher.Close)
	stage := dispatcher.NewStage(writeback)

	client := netip.MustParseAddrPort("10.0.0.1:40000")
	server := netip.MustParseAddrPort("93.184.216.34:443")
	if !stage.Dispatch(buildReturnPacket(client, server, []byte("close-edge"))) {
		t.Fatal("dispatch refused the packet")
	}

	flushDone := make(chan struct{})
	go func() {
		stage.Flush()
		close(flushDone)
	}()
	select {
	case <-port.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("Flush never reached the port")
	}

	closeDone := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		dispatcher.Close()
		closeDone <- time.Since(start)
	}()
	select {
	case elapsed := <-closeDone:
		t.Fatalf("Close returned in %v while the port was blocking: the stage lock was not held across the write", elapsed)
	case <-time.After(200 * time.Millisecond):
		// The edge is pinned: Close is behind the port write.
	}

	close(port.release)
	select {
	case <-flushDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Flush did not finish after the port was released")
	}
	select {
	case elapsed := <-closeDone:
		if elapsed < 200*time.Millisecond {
			t.Fatalf("Close reported %v, but it was blocked for at least 200ms", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close never completed after the port was released: this would be a deadlock, not a wait")
	}

	received := port.receivedPackets()
	if len(received) != 1 {
		t.Fatalf("the port must have received the one staged packet, got %d", len(received))
	}
	payload := received[0][header.IPv4MinimumSize+header.UDPMinimumSize:]
	if string(payload) != "close-edge" {
		t.Fatalf("the port received %q, want %q", payload, "close-edge")
	}
}

// The two interfaces are asserted at compile time so a future change to Port cannot silently make
// this fixture test something else.
var (
	_ Port             = (*blockingBufferPort)(nil)
	_ PacketBufferPort = (*blockingBufferPort)(nil)
	_ Handler          = (*blockingPortHandler)(nil)
)
