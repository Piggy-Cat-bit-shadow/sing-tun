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
	if err = monitor.Close(); err != nil {
		t.Fatal(err)
	}

	afterClose := finder.updateCalls.Load()
	time.Sleep(1500 * time.Millisecond)

	if got := finder.updateCalls.Load(); got != afterClose {
		t.Fatalf("interface update ran after Close: %d calls at Close, %d after the timer window", afterClose, got)
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
