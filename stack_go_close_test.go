package tun

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

// The composed close wait: a real Go stack, a real dispatcher, a real Flush, and a port that blocks.
//
// Everything below the sing-box layer is the production object graph. The only stand-in is the port
// implementation, which parks in WritePacketBuffers exactly where a MASQUE capsule write parks on a
// peer's stream window, and the device, which is the in-memory Tun rather than a platform interface.
// That is what makes this the composition test the earlier reports could only describe: the layer
// that waits (Go.Close) and the layer that blocks (the port write) are both real, and the wait is
// measured rather than inferred.
func TestGoStackCloseWaitsForABlockedPortWrite(t *testing.T) {
	port := newBlockingBufferPort()
	handler := &blockingPortHandler{port: port}
	memoryTun := NewMemoryTun(MemoryTunOptions{MTU: 1500})
	tunOptions := Options{
		Name:                      "memory",
		MTU:                       1500,
		Inet4Address:              []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
		Inet6Address:              []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")},
		EXP_ExternalConfiguration: true,
		Logger:                    logger.NOP(),
	}
	stack, err := NewGo(StackOptions{
		Context:     context.Background(),
		Tun:         memoryTun,
		TunOptions:  tunOptions,
		Handler:     handler,
		Logger:      logger.NOP(),
		UDPTimeout:  time.Minute,
		ICMPTimeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })

	// A packet leaving the device: the tunnel address is the source, so the stack treats it as a
	// forward flow and hands it to the handler.
	packet := buildReturnPacket(
		netip.MustParseAddrPort("172.19.0.1:34567"),
		netip.MustParseAddrPort("93.184.216.34:443"),
		[]byte("stack-close"),
	)
	if accepted, writeErr := memoryTun.WritePackets([][]byte{packet}); writeErr != nil || accepted != 1 {
		t.Fatalf("the packet was not accepted by the device: %d %v", accepted, writeErr)
	}

	select {
	case <-port.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the stack never reached the port")
	}

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- stack.Close()
	}()
	select {
	case closeErr := <-closeDone:
		t.Fatalf("Close returned (%v) while the port was blocked: the stack does not wait for its engine", closeErr)
	case <-time.After(300 * time.Millisecond):
	}

	close(port.release)
	select {
	case closeErr := <-closeDone:
		if closeErr != nil {
			t.Logf("Close returned %v after the port was released", closeErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close never returned after the port was released")
	}

	received := port.receivedPackets()
	if len(received) != 1 {
		t.Fatalf("the port must have received the one staged packet, got %d", len(received))
	}
	t.Logf("MEASURED: stack.Close waited for the blocked port write and completed once it was released")
}
