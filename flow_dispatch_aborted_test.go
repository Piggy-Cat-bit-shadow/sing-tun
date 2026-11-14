package tun

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
)

// A flow the caller aborted must not swallow the next connection on the same four-tuple.
//
// CloseFlow marks the flow closed, but the entry stays in the stage's table until the idle
// sweeper reaches it. Without a record of the abort, a new packet on that tuple matched the
// closed entry instead of being classified: the connection was dropped, JudgeFlow was never
// asked again, and the tuple stayed a black hole until the entry was swept. The test drives the
// real asynchronous judgement path - the verdict is applied by the stage's resume pump, exactly
// like a stack's packet loop - and asserts the second packet is judged again.

type abortTestPort struct {
	packets atomic.Int32
}

func (p *abortTestPort) PortAddresses() (netip.Addr, netip.Addr) {
	// A flow binds a NAT endpoint on the port, so the port has to have addresses.
	return netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("fdfe:dcba:9876::1")
}

func (p *abortTestPort) PortMTU() uint32           { return 1500 }
func (p *abortTestPort) AttachReturn(Return) error { return nil }
func (p *abortTestPort) DetachReturn(Return) error { return nil }
func (p *abortTestPort) PacketHeadroom() int       { return 9 }

func (p *abortTestPort) WritePackets(packets [][]byte) error {
	p.packets.Add(int32(len(packets)))
	return nil
}

func (p *abortTestPort) WritePacketBuffers(buffers []*buf.Buffer) error {
	p.packets.Add(int32(len(buffers)))
	// The port owns these buffers, so it releases them exactly once, like a real port does.
	buf.ReleaseMulti(buffers)
	return nil
}

type abortTestHandler struct {
	Handler
	port   Port
	judged atomic.Int32
}

func (h *abortTestHandler) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) FlowVerdict {
	h.judged.Add(1)
	return FlowVerdict{Action: ActionFlow, Port: h.port, Destination: destination}
}

func TestAbortedFlowIsJudgedAgainOnTheSameFourTuple(t *testing.T) {
	handler := &abortTestHandler{port: &abortTestPort{}}
	dispatcher := NewForwardDispatcher(handler, nil, logger.NOP(), UDPNatOptions{}, 0)
	t.Cleanup(dispatcher.Close)
	var stage *ForwardStage
	resumed := make(chan struct{}, 4)
	stage = dispatcher.NewStage(nil, func() {
		stage.ResumeJudged(func([]byte, ForwardFrameMeta) {})
		resumed <- struct{}{}
	})

	client := netip.MustParseAddrPort("10.0.0.1:40000")
	server := netip.MustParseAddrPort("93.184.216.34:443")
	waitResumed := func(after string) {
		t.Helper()
		select {
		case <-resumed:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: the judgement was never applied", after)
		}
	}
	currentFlow := func() *forwardFlow {
		t.Helper()
		stage.access.Lock()
		defer stage.access.Unlock()
		if len(stage.table) != 1 {
			t.Fatalf("the stage must hold exactly one entry, has %d", len(stage.table))
		}
		for _, entry := range stage.table {
			if entry.action != ActionFlow || entry.flow == nil {
				t.Fatalf("the entry is not a live flow: action=%d", entry.action)
			}
			return entry.flow
		}
		return nil
	}

	if !stage.Dispatch(buildReturnPacket(client, server, []byte("first-connection"))) {
		t.Fatal("the first packet of a new flow must be consumed by the judgement")
	}
	waitResumed("first connection")
	if judged := handler.judged.Load(); judged != 1 {
		t.Fatalf("JudgeFlow ran %d times for the first connection", judged)
	}
	firstFlow := currentFlow()

	// The caller aborts the flow, the way a policy change or a closed session does.
	firstFlow.CloseFlow()

	// The entry is still in the table at this point - that is the state the old code answered a
	// new connection from - and the next packet on the same tuple has to be classified again.
	stage.access.Lock()
	staleEntries := len(stage.table)
	stage.access.Unlock()
	if staleEntries != 1 {
		t.Fatalf("expected the aborted entry to remain until the sweeper runs, has %d", staleEntries)
	}
	if !stage.Dispatch(buildReturnPacket(client, server, []byte("second-connection"))) {
		t.Fatal("the new connection on the aborted four-tuple was refused instead of judged")
	}
	select {
	case <-resumed:
	case <-time.After(2 * time.Second):
		t.Fatalf("the aborted flow swallowed the new connection: JudgeFlow ran %d times", handler.judged.Load())
	}
	if judged := handler.judged.Load(); judged != 2 {
		t.Fatalf("JudgeFlow ran %d times; the aborted flow swallowed the new connection", judged)
	}
	secondFlow := currentFlow()
	if secondFlow == firstFlow {
		t.Fatal("the aborted flow was reused for the new connection")
	}
}

// The two interfaces are asserted at compile time so a future change to Port cannot silently make
// this fixture test something else.
var (
	_ Port             = (*abortTestPort)(nil)
	_ PacketBufferPort = (*abortTestPort)(nil)
	_ Handler          = (*abortTestHandler)(nil)
)
