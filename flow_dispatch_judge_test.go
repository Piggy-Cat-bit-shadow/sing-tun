package tun

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

// A flow judgement runs on its own goroutine: a slow rule engine must not hold the stage lock and
// must not stop unrelated flows from being forwarded. These tests pin that, and the bound that
// keeps "slow" from turning into "unbounded".

type gatedJudgeHandler struct {
	Handler
	gate   chan struct{}
	slow   func(destination netip.AddrPort) bool
	active atomic.Int32
	peak   atomic.Int32
}

func (h *gatedJudgeHandler) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) FlowVerdict {
	if h.slow == nil || !h.slow(destination) {
		return FlowVerdict{Action: ActionAccept}
	}
	current := h.active.Add(1)
	for {
		peak := h.peak.Load()
		if current <= peak || h.peak.CompareAndSwap(peak, current) {
			break
		}
	}
	<-h.gate
	h.active.Add(-1)
	return FlowVerdict{Action: ActionAccept}
}

type judgeTestStage struct {
	dispatcher *ForwardDispatcher
	stage      *ForwardStage
	handler    *gatedJudgeHandler
	forwarded  atomic.Int32
	resumed    chan struct{}
}

func newJudgeTestStage(t *testing.T, handler *gatedJudgeHandler) *judgeTestStage {
	t.Helper()
	fixture := &judgeTestStage{
		dispatcher: NewForwardDispatcher(handler, nil, logger.NOP(), UDPNatOptions{}, 0),
		handler:    handler,
		resumed:    make(chan struct{}, flowHoldCapacity+64),
	}
	fixture.stage = fixture.dispatcher.NewStage(nil, func() {
		fixture.stage.ResumeJudged(func(packet []byte, meta ForwardFrameMeta) {
			fixture.forwarded.Add(1)
		})
		fixture.resumed <- struct{}{}
	})
	t.Cleanup(fixture.dispatcher.Close)
	return fixture
}

func flowPacket(source, destination netip.AddrPort, payload string) []byte {
	return buildReturnPacket(source, destination, []byte(payload))
}

func TestSlowJudgementDoesNotBlockUnrelatedFlows(t *testing.T) {
	handler := &gatedJudgeHandler{
		gate: make(chan struct{}),
		slow: func(destination netip.AddrPort) bool { return destination.Port() == 9999 },
	}
	fixture := newJudgeTestStage(t, handler)
	stage := fixture.stage

	client := netip.MustParseAddrPort("10.0.0.1:40000")
	server := netip.MustParseAddrPort("93.184.216.34:443")

	// Install one accepted flow through the real pump.
	if !stage.Dispatch(flowPacket(client, server, "flow-a")) {
		t.Fatal("the first packet of a new flow must be consumed by the judgement")
	}
	select {
	case <-fixture.resumed:
	case <-time.After(2 * time.Second):
		t.Fatal("the first judgement was never applied")
	}
	if fixture.forwarded.Load() != 1 {
		t.Fatalf("the accepted packet must be handed to the stack once, got %d", fixture.forwarded.Load())
	}

	// Park the next flow inside JudgeFlow.
	if !stage.Dispatch(flowPacket(client, netip.MustParseAddrPort("93.184.216.34:9999"), "slow-flow")) {
		t.Fatal("the slow flow packet must be consumed by the judgement")
	}
	deadline := time.Now().Add(2 * time.Second)
	for handler.active.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the slow judgement never started")
		}
		time.Sleep(time.Millisecond)
	}

	// The accepted flow keeps moving: its packets are consumed synchronously and never wait for
	// the blocked judgement.
	done := make(chan bool, 1)
	go func() {
		handled := stage.Dispatch(flowPacket(client, server, "flow-a-again"))
		done <- handled
	}()
	select {
	case handled := <-done:
		if handled {
			t.Fatal("a packet of an installed ACCEPT flow must continue to the stack, not be consumed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the packet path was blocked behind a slow flow judgement")
	}

	// Throughput on the unrelated flow is not affected while the judgement is still blocked.
	for range 100 {
		if stage.Dispatch(flowPacket(client, server, "flow-a-burst")) {
			t.Fatal("an installed ACCEPT flow must not be re-judged")
		}
	}
	if handler.active.Load() != 1 {
		t.Fatalf("the unrelated flow started another judgement: %d active", handler.active.Load())
	}

	close(handler.gate)
	select {
	case <-fixture.resumed:
	case <-time.After(2 * time.Second):
		t.Fatal("the slow judgement did not resume")
	}
	if handler.active.Load() != 0 {
		t.Fatalf("the judgement goroutine did not finish: %d active", handler.active.Load())
	}
}

func TestJudgementHoldIsBoundedPerFlowAndPerStage(t *testing.T) {
	handler := &gatedJudgeHandler{
		gate: make(chan struct{}),
		slow: func(netip.AddrPort) bool { return true },
	}
	fixture := newJudgeTestStage(t, handler)
	stage := fixture.stage

	client := netip.MustParseAddrPort("10.0.0.1:40000")
	server := netip.MustParseAddrPort("93.184.216.34:443")
	for range flowHoldPerFlow + 40 {
		stage.Dispatch(flowPacket(client, server, "same-flow"))
	}

	stage.access.Lock()
	perFlow := 0
	for _, judgement := range stage.judging {
		perFlow = len(judgement.packets)
	}
	held := stage.held
	stage.access.Unlock()
	if perFlow != flowHoldPerFlow {
		t.Fatalf("one flow parked %d packets, want the bound %d", perFlow, flowHoldPerFlow)
	}
	if held != flowHoldPerFlow {
		t.Fatalf("stage holds %d packets for one flow, want %d", held, flowHoldPerFlow)
	}

	// Fill the stage with distinct flows. Every one of them holds at least its first packet, so
	// the stage-wide budget is what has to stop it.
	for index := range flowHoldCapacity + 64 {
		source := netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), uint16(20000+index))
		stage.Dispatch(flowPacket(source, server, "fill"))
	}
	stage.access.Lock()
	held = stage.held
	bounded := held <= flowHoldCapacity
	stage.access.Unlock()
	if !bounded {
		t.Fatalf("the stage parked %d packets, over the %d bound", held, flowHoldCapacity)
	}
	if peak := handler.peak.Load(); peak > int32(flowHoldCapacity) {
		t.Fatalf("%d concurrent judgements exceed the %d packet budget", peak, flowHoldCapacity)
	}

	// Close while every judge is still blocked: the stage drops the judgements and the blocked
	// goroutines must return without installing anything or leaking.
	fixture.dispatcher.Close()
	close(handler.gate)
	deadline := time.Now().Add(5 * time.Second)
	for handler.active.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d judge goroutines did not return after Close", handler.active.Load())
		}
		time.Sleep(time.Millisecond)
	}
	stage.access.Lock()
	remaining := len(stage.judging) + len(stage.judged)
	held = stage.held
	stage.access.Unlock()
	if remaining != 0 || held != 0 {
		t.Fatalf("Close left %d judgements and %d held packets", remaining, held)
	}
	if len(stage.table) != 0 {
		t.Fatalf("Close left %d flows installed after a blocked judgement", len(stage.table))
	}
}

// A judgement that completes after Close must not install a flow. The resume is driven directly
// here because Close intentionally drops the judgement before the pump can see it.
func TestJudgementAfterCloseDoesNotInstall(t *testing.T) {
	handler := &gatedJudgeHandler{
		gate: make(chan struct{}),
		slow: func(netip.AddrPort) bool { return true },
	}
	fixture := newJudgeTestStage(t, handler)
	stage := fixture.stage

	client := netip.MustParseAddrPort("10.0.0.1:40000")
	server := netip.MustParseAddrPort("93.184.216.34:443")
	stage.Dispatch(flowPacket(client, server, "install-me"))
	deadline := time.Now().Add(2 * time.Second)
	for handler.active.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the judgement never started")
		}
		time.Sleep(time.Millisecond)
	}

	stage.dispatcher.Close()
	close(handler.gate)
	deadline = time.Now().Add(2 * time.Second)
	for handler.active.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the blocked judgement did not return")
		}
		time.Sleep(time.Millisecond)
	}

	stage.access.Lock()
	defer stage.access.Unlock()
	if len(stage.table) != 0 || len(stage.judging) != 0 || len(stage.judged) != 0 {
		t.Fatalf("a judgement completing after Close installed state: table=%d judging=%d judged=%d",
			len(stage.table), len(stage.judging), len(stage.judged))
	}
}
