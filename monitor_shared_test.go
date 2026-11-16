//go:build linux || windows || darwin

package tun

import (
	"errors"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
)

type closeTestNetworkMonitor struct{}

func (closeTestNetworkMonitor) Start() error { return nil }
func (closeTestNetworkMonitor) Close() error { return nil }

func (closeTestNetworkMonitor) RegisterCallback(callback NetworkUpdateCallback) *list.Element[NetworkUpdateCallback] {
	var callbacks list.List[NetworkUpdateCallback]
	return callbacks.PushBack(callback)
}

func (closeTestNetworkMonitor) UnregisterCallback(element *list.Element[NetworkUpdateCallback]) {}

type closeTestInterfaceFinder struct {
	updateCalls atomic.Int64
}

func (f *closeTestInterfaceFinder) Update() error {
	f.updateCalls.Add(1)
	return errors.New("test: no default interface")
}

func (f *closeTestInterfaceFinder) Interfaces() []control.Interface { return nil }

func (f *closeTestInterfaceFinder) ByName(string) (*control.Interface, error) {
	return nil, errors.New("test: no interface")
}

func (f *closeTestInterfaceFinder) ByIndex(int) (*control.Interface, error) {
	return nil, errors.New("test: no interface")
}

func (f *closeTestInterfaceFinder) ByAddr(netip.Addr) (*control.Interface, error) {
	return nil, errors.New("test: no interface")
}

func (f *closeTestInterfaceFinder) RegisterInterfaceUpdateCallback(callback control.InterfaceUpdateCallback) *list.Element[control.InterfaceUpdateCallback] {
	var callbacks list.List[control.InterfaceUpdateCallback]
	return callbacks.PushBack(callback)
}

func (f *closeTestInterfaceFinder) UnregisterInterfaceUpdateCallback(element *list.Element[control.InterfaceUpdateCallback]) {
}

// TestDefaultInterfaceMonitorCloseStopsPendingUpdate pins the Close contract: a
// network update that has already been coalesced into the one-second timer must
// not run after Close, and must not reschedule itself through the error path.
func TestDefaultInterfaceMonitorCloseStopsPendingUpdate(t *testing.T) {
	finder := &closeTestInterfaceFinder{}
	monitor, err := NewDefaultInterfaceMonitor(closeTestNetworkMonitor{}, logger.NOP(), DefaultInterfaceMonitorOptions{
		InterfaceFinder: finder,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = monitor.Start(); err != nil {
		t.Fatal(err)
	}
	m := monitor.(*defaultInterfaceMonitor)
	timer := m.checkUpdateTimer
	if timer == nil {
		t.Fatal("precondition: Start did not schedule the coalesced update timer")
	}
	if err = monitor.Close(); err != nil {
		t.Fatal(err)
	}
	if m.checkUpdateTimer != nil {
		t.Fatal("Close left the coalesced update timer installed")
	}
	if timer.Stop() {
		t.Fatal("Close cleared the timer field without stopping the timer")
	}

	afterClose := finder.updateCalls.Load()
	time.Sleep(1500 * time.Millisecond)

	if got := finder.updateCalls.Load(); got != afterClose {
		t.Fatalf("interface update ran after Close: %d calls at Close, %d after the timer window", afterClose, got)
	}
}

// TestDefaultInterfaceMonitorCloseRefusesLateEmit pins the other half of the
// Close fence: a postCheckUpdate that is already past its entry check must not
// deliver an interface to callbacks after Close.
func TestDefaultInterfaceMonitorCloseRefusesLateEmit(t *testing.T) {
	monitor, err := NewDefaultInterfaceMonitor(closeTestNetworkMonitor{}, logger.NOP(), DefaultInterfaceMonitorOptions{
		InterfaceFinder: &closeTestInterfaceFinder{},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := monitor.(*defaultInterfaceMonitor)
	var delivered atomic.Int64
	m.RegisterCallback(func(*control.Interface, int) {
		delivered.Add(1)
	})
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	m.emit(&control.Interface{Index: 1, Name: "late"}, 0)
	if got := delivered.Load(); got != 0 {
		t.Fatalf("closed monitor delivered %d callback(s)", got)
	}
}

// TestDefaultInterfaceMonitorCloseRefusesLatePublish pins the publish half:
// a refresh that computes an interface before Close must not write it after
// Close, even though it is past postCheckUpdate's entry check.
func TestDefaultInterfaceMonitorCloseRefusesLatePublish(t *testing.T) {
	monitor, err := NewDefaultInterfaceMonitor(closeTestNetworkMonitor{}, logger.NOP(), DefaultInterfaceMonitorOptions{
		InterfaceFinder: &closeTestInterfaceFinder{},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := monitor.(*defaultInterfaceMonitor)
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.publishDefaultInterface(&control.Interface{Index: 1, Name: "late"}, nil); ok {
		t.Fatal("publishDefaultInterface succeeded after Close")
	}
	if got := m.DefaultInterface(); got != nil {
		t.Fatalf("closed monitor published %v", got)
	}
}

// TestDefaultInterfaceMonitorCloseRefusesLateNoRoute pins the no-route half:
// the ErrNoRoute branch must not clear the interface or announce no-route
// after Close.
func TestDefaultInterfaceMonitorCloseRefusesLateNoRoute(t *testing.T) {
	monitor, err := NewDefaultInterfaceMonitor(closeTestNetworkMonitor{}, logger.NOP(), DefaultInterfaceMonitorOptions{
		InterfaceFinder: &closeTestInterfaceFinder{},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := monitor.(*defaultInterfaceMonitor)
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.publishNoRoute(); ok {
		t.Fatal("publishNoRoute succeeded after Close")
	}
	if m.noRoute.Load() {
		t.Fatal("closed monitor announced no-route")
	}
}

// TestDefaultInterfaceMonitorStartAfterClose pins that a closed monitor cannot
// be revived; a Start that loses the race must unregister itself and report the
// closed state instead of reinstalling the callback.
func TestDefaultInterfaceMonitorStartAfterClose(t *testing.T) {
	monitor, err := NewDefaultInterfaceMonitor(closeTestNetworkMonitor{}, logger.NOP(), DefaultInterfaceMonitorOptions{
		InterfaceFinder: &closeTestInterfaceFinder{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = monitor.Close(); err != nil {
		t.Fatal(err)
	}
	if err = monitor.Start(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Start after Close returned %v, want os.ErrClosed", err)
	}
}
