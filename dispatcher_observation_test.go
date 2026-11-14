package tun

import (
	"context"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// blockingUDPHandler parks the dispatcher goroutine without spawning a reader of its own. That makes
// the measurement below the NAT's own cost (entry + queue + one dispatcher goroutine), not the
// route handler's.
type blockingUDPHandler struct {
	release chan struct{}
	active  atomic.Int64
}

func (h *blockingUDPHandler) NewPacketConnectionEx(context.Context, N.PacketConn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
	h.active.Add(1)
	<-h.release
	h.active.Add(-1)
}

func newStatsNAT(t *testing.T, handler N.UDPConnectionHandlerEx, maxSize uint32) *UDPNat {
	t.Helper()
	upstream := &natStressUpstream{}
	nat := NewUDPNat(UDPNatOptions{
		Handler: handler,
		Prepare: func(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return true, context.Background(), upstream, func(error) {}
		},
		Timeout:   time.Minute,
		Mapping:   NATMappingEndpointIndependent,
		Filtering: NATFilteringEndpointIndependent,
		MaxSize:   maxSize,
	})
	if err := nat.Start(); err != nil {
		t.Fatalf("start the NAT: %v", err)
	}
	t.Cleanup(func() { _ = nat.Close() })
	return nat
}

// UDPNatStats is the LOGICAL-FLOW layer's view: one entry per flow the tunnel tracks, the bytes those
// flows hold, and the cumulative sessions created. It says nothing about sockets or TLS sessions.
func TestUDPNatStatsReportLogicalFlows(t *testing.T) {
	handler := &blockingUDPHandler{release: make(chan struct{})}
	nat := newStatsNAT(t, handler, 4096)

	const flows = 64
	for index := range flows {
		sendSizedPacket(nat, uint16(2000+index), "203.0.113.1:53", 1200)
	}
	requireEventually(t, "NAT entries", func() bool { return nat.Stats().Entries == flows })

	stats := nat.Stats()
	if stats.Entries != flows {
		t.Fatalf("entries = %d, want %d", stats.Entries, flows)
	}
	if stats.SessionsCreated != flows {
		t.Fatalf("sessionsCreated = %d, want %d", stats.SessionsCreated, flows)
	}
	if stats.MaxEntries != 4096 {
		t.Fatalf("maxEntries = %d, want 4096", stats.MaxEntries)
	}
	if stats.QueuedBytes != flows*1200 {
		t.Fatalf("queuedBytes = %d, want %d", stats.QueuedBytes, flows*1200)
	}
	if stats.MaxQueuedBytes != DefaultUDPNatMaxBytes {
		t.Fatalf("maxQueuedBytes = %d, want %d", stats.MaxQueuedBytes, DefaultUDPNatMaxBytes)
	}
	if stats.MaxBytesPerSession != DefaultUDPNatMaxBytesPerSession {
		t.Fatalf("maxBytesPerSession = %d, want %d", stats.MaxBytesPerSession, DefaultUDPNatMaxBytesPerSession)
	}

	close(handler.release)
	nat.Close()
}

// TestUDPNatPerFlowCost measures what one logical UDP flow costs at the NAT layer at the burst sizes
// the device evidence uses. The numbers are Go-runtime numbers on the host: they are the per-flow
// SHAPE (one entry, one dispatcher goroutine, the queued first datagram), not iOS phys_footprint.
func TestUDPNatPerFlowCost(t *testing.T) {
	for _, flows := range []int{200, 1000} {
		handler := &blockingUDPHandler{release: make(chan struct{})}
		nat := newStatsNAT(t, handler, 4096)

		runtime.GC()
		var baseline runtime.MemStats
		runtime.ReadMemStats(&baseline)
		baseGoroutines := runtime.NumGoroutine()

		for index := range flows {
			sendSizedPacket(nat, uint16(3000+index), "203.0.113.1:53", 1200)
		}
		requireEventually(t, "NAT entries", func() bool { return nat.Stats().Entries == flows })

		runtime.GC()
		var loaded runtime.MemStats
		runtime.ReadMemStats(&loaded)
		stats := nat.Stats()
		goroutines := runtime.NumGoroutine() - baseGoroutines
		heapDelta := int64(loaded.HeapAlloc) - int64(baseline.HeapAlloc)
		stackDelta := int64(loaded.StackInuse) - int64(baseline.StackInuse)
		// The queued datagrams are heap allocations; they are a SUBSET of heapDelta, not an
		// additional cost on top of it. Subtracting them leaves the structural per-entry cost.
		structural := heapDelta - stats.QueuedBytes
		structural = max(structural, 0)
		perFlowHeap := heapDelta / int64(flows)
		perFlowStructural := structural / int64(flows)
		perFlowStack := stackDelta / int64(flows)
		perFlowQueued := stats.QueuedBytes / int64(flows)

		t.Logf("udp flows=%d entries=%d sessions=%d queued=%d goroutines+%d heap=%d B (%d B/flow, includes queued) structural=%d B/structure=%d B/flow stack=%d B (%d B/flow) queued=%d B/flow",
			flows, stats.Entries, stats.SessionsCreated, stats.QueuedBytes, goroutines,
			heapDelta, perFlowHeap, structural, perFlowStructural, stackDelta, perFlowStack, perFlowQueued)

		if stats.Entries != flows || stats.SessionsCreated != uint64(flows) {
			t.Fatalf("flows=%d: entries=%d sessions=%d", flows, stats.Entries, stats.SessionsCreated)
		}
		if goroutines < flows || goroutines > flows*2 {
			t.Fatalf("flows=%d: goroutines grew by %d; one dispatcher goroutine per flow is the expected shape", flows, goroutines)
		}
		if structural <= 0 {
			t.Fatalf("flows=%d: no measurable structural heap after subtracting the queued datagrams", flows)
		}
		if stackDelta <= 0 {
			t.Fatalf("flows=%d: StackInuse did not grow with %d parked goroutines", flows, goroutines)
		}

		close(handler.release)
		nat.Close()
		requireEventually(t, "NAT entries drained", func() bool { return nat.Stats().Entries == 0 })
	}
}

// TCPDispatcherStats counts LOGICAL dispatches and the handler calls still in flight. The cost test
// uses the same helper the real dispatchers call, so the goroutine shape is the production one; the
// TCP state machine itself is covered by the stack integration tests, not here.
func TestTCPDispatcherPerDispatchCost(t *testing.T) {
	before := TCPDispatcherStats()
	if before.TCPActive != 0 {
		t.Fatalf("dispatcher active = %d before the test; another test leaked a dispatch", before.TCPActive)
	}

	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)
	baseGoroutines := runtime.NumGoroutine()

	const dispatches = 1000
	release := make(chan struct{})
	for range dispatches {
		goDispatch(func() { <-release })
	}
	requireEventually(t, "active dispatches", func() bool {
		return TCPDispatcherStats().TCPActive == dispatches
	})

	runtime.GC()
	var loaded runtime.MemStats
	runtime.ReadMemStats(&loaded)
	after := TCPDispatcherStats()
	goroutines := runtime.NumGoroutine() - baseGoroutines
	// This test measures the DISPATCHER overhead (one goroutine per handler call), not the TCP
	// state machine's memory or a physical socket. Heap is not attributed per dispatch: a GC can
	// move it either way, and the handler in this test is an empty closure, so a per-dispatch heap
	// number would describe the test, not the dispatcher.
	t.Logf("tcp dispatches=%d active=%d goroutines+%d (dispatcher goroutines only; no per-dispatch heap claim)",
		after.TCPAccepted-before.TCPAccepted, after.TCPActive, goroutines)

	if after.TCPAccepted-before.TCPAccepted != dispatches {
		t.Fatalf("accepted delta = %d, want %d", after.TCPAccepted-before.TCPAccepted, dispatches)
	}
	if goroutines < dispatches {
		t.Fatalf("goroutines grew by %d, want at least one per dispatch (%d)", goroutines, dispatches)
	}

	close(release)
	requireEventually(t, "active dispatches drained", func() bool {
		return TCPDispatcherStats().TCPActive == 0
	})
}

type memorySample struct {
	heapAlloc   uint64
	heapObjects uint64
	stackInuse  uint64
	goroutines  int
}

func readMemorySample() memorySample {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return memorySample{
		heapAlloc:   stats.HeapAlloc,
		heapObjects: stats.HeapObjects,
		stackInuse:  stats.StackInuse,
		goroutines:  runtime.NumGoroutine(),
	}
}

// TestUDPNatFlowCostAtScale extends the per-flow measurement to the burst sizes the device profile
// uses, and separates the three questions the earlier tests could not answer together:
//
//  1. burst creation: what does the process hold the moment N entries exist?
//  2. stable hold: what remains after a GC (HeapAlloc/HeapObjects/StackInuse are different views)?
//     3.集中释放: after every conn is closed, do entries, queued bytes and dispatcher goroutines return
//     to the baseline, or is something retained?
//
// Host Go runtime only. The numbers characterize growth and recovery; they are not iOS phys_footprint
// and must not be used to justify an ingress gate on their own.
func TestUDPNatFlowCostAtScale(t *testing.T) {
	for _, flows := range []int{2000, 4096} {
		handler := &blockingUDPHandler{release: make(chan struct{})}
		nat := newStatsNAT(t, handler, 4096)

		runtime.GC()
		baseline := readMemorySample()

		for index := range flows {
			sendSizedPacket(nat, uint16(4000+index), "203.0.113.1:53", 1200)
		}
		requireEventually(t, "NAT entries", func() bool { return nat.Stats().Entries == flows })
		burst := readMemorySample()
		burstStats := nat.Stats()

		// Stable hold: nothing is created or released; a GC separates live retention from floating
		// garbage. HeapAlloc after GC is the live figure; HeapObjects counts the same live objects.
		runtime.GC()
		stable := readMemorySample()
		stableStats := nat.Stats()
		t.Logf("flows=%d BURST entries=%d sessions=%d queued=%d goroutines=%d heap=%d objects=%d stack=%d | STABLE(after GC) heap=%d objects=%d stack=%d goroutines=%d entries=%d queued=%d",
			flows, burstStats.Entries, burstStats.SessionsCreated, burstStats.QueuedBytes,
			burst.goroutines, burst.heapAlloc, burst.heapObjects, burst.stackInuse,
			stable.heapAlloc, stable.heapObjects, stable.stackInuse, stable.goroutines,
			stableStats.Entries, stableStats.QueuedBytes)

		// Concentrated release: every handler is released and the NAT is closed without per-flow
		// pacing, which is the shape a network teardown produces.
		close(handler.release)
		if err := nat.Close(); err != nil {
			t.Fatalf("flows=%d: close NAT: %v", flows, err)
		}
		requireEventually(t, "NAT entries drained", func() bool { return nat.Stats().Entries == 0 })
		requireEventually(t, "queued bytes drained", func() bool { return nat.Stats().QueuedBytes == 0 })
		requireEventually(t, "dispatcher goroutines", func() bool {
			return runtime.NumGoroutine() <= baseline.goroutines+10
		})

		// One GC may leave runtime caches (mcache spans, heap arenas) in HeapAlloc; sample after the
		// first and after two more collections so "live objects fell" is distinguishable from "the
		// allocator has not returned pages yet".
		runtime.GC()
		recovered := readMemorySample()
		runtime.GC()
		runtime.GC()
		settled := readMemorySample()
		recoveredStats := nat.Stats()
		var settledMem runtime.MemStats
		runtime.ReadMemStats(&settledMem)
		t.Logf("flows=%d RECOVERED entries=%d queued=%d goroutines=%d (baseline %d) after1GC heap=%d objects=%d stack=%d | after3GC heap=%d objects=%d stack=%d heapInuse=%d heapReleased=%d",
			flows, recoveredStats.Entries, recoveredStats.QueuedBytes, settled.goroutines, baseline.goroutines,
			recovered.heapAlloc, recovered.heapObjects, recovered.stackInuse,
			settled.heapAlloc, settled.heapObjects, settled.stackInuse, settledMem.HeapInuse, settledMem.HeapReleased)

		if recoveredStats.Entries != 0 || recoveredStats.QueuedBytes != 0 {
			t.Fatalf("flows=%d: NAT retained entries=%d queued=%d after close", flows, recoveredStats.Entries, recoveredStats.QueuedBytes)
		}
		if settled.heapObjects >= stable.heapObjects/2 {
			t.Fatalf("flows=%d: live objects did not fall after release: stable=%d settled=%d",
				flows, stable.heapObjects, settled.heapObjects)
		}
	}
}

func requireEventually(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("%s did not reach the expected state", what)
}
