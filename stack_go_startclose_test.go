package tun

import (
	"context"
	"errors"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing/common/logger"
)

// This file pins the Start/Close ownership contract of the Go stack.
//
// The rule under test:
//
//   - Start owns the started resources. It is the only writer of s.engines, s.udpNats,
//     s.dispatcher and the directory map it sizes, it publishes them while holding s.access, and it
//     publishes before it creates any engine goroutine, so every goroutine Start creates observes
//     the published state without further synchronisation.
//   - Close owns the started state. It sets s.closed and snapshots the published resources in one
//     critical section, so the snapshot is either empty (Start has not published, and Start's own
//     closed check then refuses to) or complete (Start published, and every resource it published is
//     torn down by that same Close call).
//   - Close wins. Once s.closed is set, Start publishes nothing, so nothing can start again after
//     Close returns.
//
// Everything below drives that handshake with barriers and channels, never with sleeps. The
// observable state is the stack's closed bit, the memory tun's attached bit (set by the queue's
// start, cleared by its close), whether each engine goroutine has exited, and how many times Start
// reached its queue factory: a refused or duplicate Start must not reach it.

type goStartCloseFixture struct {
	stack   *Go
	device  *MemoryTun
	reached atomic.Int64
	// beforeEntered is closed when Start enters its queue factory and beforeHold is closed by the
	// test to let it continue. nil means "do not hold".
	beforeEntered chan struct{}
	beforeHold    chan struct{}
	beforeOnce    sync.Once
	// afterBuilt is closed once the queue factory has returned and afterHold is closed by the test
	// to let Start publish. nil means "do not hold".
	afterBuilt chan struct{}
	afterHold  chan struct{}
	afterOnce  sync.Once
}

// newGoStartCloseFixture builds a device-free Go stack over a MemoryTun - the construction
// TestGoUDPReceiveBudget uses - so these tests need no TUN device and no privileges.
func newGoStartCloseFixture(t *testing.T) *goStartCloseFixture {
	t.Helper()
	device := NewMemoryTun(MemoryTunOptions{MTU: 1500})
	t.Cleanup(func() { device.Close() })
	stack, err := NewGo(StackOptions{
		Context:    context.Background(),
		Tun:        device,
		TunOptions: Options{MTU: 1500},
		Logger:     logger.NOP(),
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture := &goStartCloseFixture{stack: stack, device: device}
	factory := stack.queueFactory
	stack.queueFactory = func(current *Go) ([]goPlatformIO, error) {
		fixture.reached.Add(1)
		if fixture.beforeEntered != nil {
			fixture.beforeOnce.Do(func() { close(fixture.beforeEntered) })
			<-fixture.beforeHold
		}
		queues, err := factory(current)
		if fixture.afterBuilt != nil {
			fixture.afterOnce.Do(func() { close(fixture.afterBuilt) })
			<-fixture.afterHold
		}
		return queues, err
	}
	return fixture
}

// holdAtFactoryEntry makes the next Start stop inside its queue factory, while it holds s.access and
// before anything is built.
func (f *goStartCloseFixture) holdAtFactoryEntry() (entered, hold chan struct{}) {
	f.beforeEntered = make(chan struct{})
	f.beforeHold = make(chan struct{})
	return f.beforeEntered, f.beforeHold
}

// holdAfterFactory makes the next Start stop once its queues exist, at the publish boundary: the
// resources are about to be assigned and the engine goroutines are about to be created, still under
// s.access.
func (f *goStartCloseFixture) holdAfterFactory() (built, hold chan struct{}) {
	f.afterBuilt = make(chan struct{})
	f.afterHold = make(chan struct{})
	return f.afterBuilt, f.afterHold
}

// stopped asserts the state Close promises. It is only called once every racer has returned, so
// reading stack.engines here has no concurrent writer.
func (f *goStartCloseFixture) stopped(t *testing.T) {
	t.Helper()
	if !f.stack.closed.Load() {
		t.Error("the stack is not closed")
	}
	if f.device.attached.Load() {
		t.Error("the queue is still attached after Close returned")
	}
	for index, engine := range f.stack.engines {
		select {
		case <-engine.exitSignal:
		default:
			t.Errorf("engine %d is still running after Close returned", index)
		}
	}
}

// closeFromAnotherGoroutine starts Close and reports whether it was able to observe the attempt
// before returning the result channel. The observation is a barrier, not a sleep: the caller checks
// the result channel before releasing whatever Start is holding, so a Close that returned early is
// caught, and a Close that correctly waits is never reported as having returned.
func closeFromAnotherGoroutine(fixture *goStartCloseFixture) (attempted <-chan struct{}, done <-chan error) {
	attemptedChan := make(chan struct{})
	doneChan := make(chan error, 1)
	go func() {
		close(attemptedChan)
		doneChan <- fixture.stack.Close()
	}()
	return attemptedChan, doneChan
}

// TestGoStackStartAndCloseConcurrently is the shape a stop landing on a starting stack takes: one
// Start and one Close with nothing but a barrier ordering them against the test goroutine.
func TestGoStackStartAndCloseConcurrently(t *testing.T) {
	for iteration := range 200 {
		fixture := newGoStartCloseFixture(t)
		release := make(chan struct{})
		var waitGroup sync.WaitGroup
		var startErr, closeErr error
		waitGroup.Add(2)
		go func() {
			defer waitGroup.Done()
			<-release
			startErr = fixture.stack.Start()
		}()
		go func() {
			defer waitGroup.Done()
			<-release
			closeErr = fixture.stack.Close()
		}()
		close(release)
		waitGroup.Wait()

		if closeErr != nil {
			t.Fatalf("iteration %d: Close: %v", iteration, closeErr)
		}
		if startErr != nil && !errors.Is(startErr, os.ErrClosed) {
			t.Fatalf("iteration %d: Start: %v", iteration, startErr)
		}
		if reached := fixture.reached.Load(); reached > 1 {
			t.Fatalf("iteration %d: %d Starts reached the queue factory, want at most 1", iteration, reached)
		}
		fixture.stopped(t)
	}
}

// TestGoStackStartCloseStartConcurrently adds a second Start, which is the case that separates "no
// race" from "no resurrection": a duplicate Start must not publish a second set of engines (the
// first set would be leaked), and a Start that arrives after Close must publish nothing at all.
func TestGoStackStartCloseStartConcurrently(t *testing.T) {
	runGoStackStartCloseStart(t, 200)
}

func TestGoStackStartCloseRepeat100(t *testing.T) {
	runGoStackStartCloseStart(t, 100)
}

func TestGoStackStartCloseRepeat1000(t *testing.T) {
	runGoStackStartCloseStart(t, 1000)
}

func runGoStackStartCloseStart(t *testing.T, iterations int) {
	t.Helper()
	for iteration := range iterations {
		fixture := newGoStartCloseFixture(t)
		release := make(chan struct{})
		var waitGroup sync.WaitGroup
		var firstErr, closeErr, secondErr error
		waitGroup.Add(3)
		go func() {
			defer waitGroup.Done()
			<-release
			firstErr = fixture.stack.Start()
		}()
		go func() {
			defer waitGroup.Done()
			<-release
			closeErr = fixture.stack.Close()
		}()
		go func() {
			defer waitGroup.Done()
			<-release
			secondErr = fixture.stack.Start()
		}()
		close(release)
		waitGroup.Wait()

		if closeErr != nil {
			t.Fatalf("iteration %d: Close: %v", iteration, closeErr)
		}
		for name, err := range map[string]error{"first Start": firstErr, "second Start": secondErr} {
			if err != nil && !errors.Is(err, os.ErrClosed) {
				t.Fatalf("iteration %d: %s: %v", iteration, name, err)
			}
		}
		if reached := fixture.reached.Load(); reached > 1 {
			t.Fatalf("iteration %d: %d Starts reached the queue factory, want at most 1", iteration, reached)
		}
		fixture.stopped(t)

		// No resurrection: after every racer has returned, a later Start is refused and reaches no
		// resource.
		before := fixture.reached.Load()
		if err := fixture.stack.Start(); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("iteration %d: Start after Close = %v, want %v", iteration, err, os.ErrClosed)
		}
		if after := fixture.reached.Load(); after != before {
			t.Fatalf("iteration %d: Start after Close reached the queue factory (%d -> %d)", iteration, before, after)
		}
		fixture.stopped(t)
	}
}

// TestGoStackCloseBeforeStartCompletes holds Start inside s.access before it builds anything and
// closes from another goroutine. Close must wait for the publish to finish and then tear down
// everything Start published; it must not return early with the stack still live.
func TestGoStackCloseBeforeStartCompletes(t *testing.T) {
	fixture := newGoStartCloseFixture(t)
	entered, hold := fixture.holdAtFactoryEntry()

	startDone := make(chan error, 1)
	go func() { startDone <- fixture.stack.Start() }()
	<-entered

	attempted, closeDone := closeFromAnotherGoroutine(fixture)
	<-attempted
	// Close's first act is to take s.access, which Start holds until it has published and launched
	// its engines. No synchronization other than that lock can order them, so this check can only
	// fail if Close really did return while Start was still in flight.
	runtime.Gosched()
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned (%v) while Start was still publishing", err)
	default:
	}

	close(hold)
	if err := <-startDone; err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close: %v", err)
	}
	if reached := fixture.reached.Load(); reached != 1 {
		t.Fatalf("%d Starts reached the queue factory, want 1", reached)
	}
	if len(fixture.stack.engines) != 1 {
		t.Fatalf("%d engines published, want 1", len(fixture.stack.engines))
	}
	fixture.stopped(t)
}

// TestGoStackCloseImmediatelyAfterPublish issues the Close at the earliest point the test can observe
// after the queue is built: the queues exist, and the same Start is about to assign s.engines and
// launch the engine. Close must wait for that publish and then stop the engine it produced, not miss
// it.
func TestGoStackCloseImmediatelyAfterPublish(t *testing.T) {
	fixture := newGoStartCloseFixture(t)
	built, hold := fixture.holdAfterFactory()

	startDone := make(chan error, 1)
	go func() { startDone <- fixture.stack.Start() }()
	<-built

	attempted, closeDone := closeFromAnotherGoroutine(fixture)
	<-attempted
	runtime.Gosched()
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned (%v) before Start finished publishing", err)
	default:
	}

	close(hold)
	if err := <-startDone; err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close: %v", err)
	}
	if len(fixture.stack.engines) != 1 {
		t.Fatalf("%d engines published, want 1", len(fixture.stack.engines))
	}
	fixture.stopped(t)
}

// TestGoStackStartAfterCloseIsRefused pins Close-before-Start directly: the refusal must happen
// before any resource is built, and Close itself stays idempotent.
func TestGoStackStartAfterCloseIsRefused(t *testing.T) {
	fixture := newGoStartCloseFixture(t)
	if err := fixture.stack.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := fixture.stack.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	for attempt := range 3 {
		if err := fixture.stack.Start(); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("Start attempt %d after Close = %v, want %v", attempt, err, os.ErrClosed)
		}
	}
	if reached := fixture.reached.Load(); reached != 0 {
		t.Fatalf("%d Starts reached the queue factory after Close, want 0", reached)
	}
	fixture.stopped(t)
}
