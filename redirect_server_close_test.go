//go:build linux

package tun

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type closeTestHandler struct {
	accepted chan struct{}
}

func (h *closeTestHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if h.accepted != nil {
		h.accepted <- struct{}{}
	}
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_, _ = conn.Read(make([]byte, 1))
	_ = conn.Close()
	if onClose != nil {
		onClose(nil)
	}
}

// The platform auto-redirect now closes its redirect server before the session, because a
// listener that is still accepting after the rules are gone hands new connections to a handler
// that is being torn down. That order makes this Close the first step of a shutdown, so it has to
// stop the listener, release the accepted connections and survive being called again by an
// inbound that is closed twice.
//
// The connection is made over the IPv6 loopback because the server resolves an IPv4 peer's
// original destination through SO_ORIGINAL_DST, which only a redirected connection has; an
// externally transparent server takes the local address as the destination instead.
func TestRedirectServerCloseIsRepeatable(t *testing.T) {
	handler := &closeTestHandler{accepted: make(chan struct{}, 1)}
	server := NewRedirectServer(context.Background(), handler, logger.NOP(), netip.IPv6Loopback())
	server.SetExternalTransparent()
	err := server.Start()
	if err != nil {
		t.Fatalf("failed to start the redirect server: %s", err)
	}
	listenAddress := net.JoinHostPort("::1", strconv.Itoa(int(server.Port())))
	conn, err := net.DialTimeout("tcp", listenAddress, time.Second)
	if err != nil {
		_ = server.Close()
		t.Fatalf("failed to connect to the redirect server: %s", err)
	}
	defer conn.Close()
	select {
	case <-handler.accepted:
	case <-time.After(time.Second):
		_ = server.Close()
		t.Fatal("the redirect server did not accept a connection")
	}
	err = server.Close()
	if err != nil {
		t.Fatalf("the first close failed: %s", err)
	}
	if _, err = net.DialTimeout("tcp", listenAddress, time.Second); err == nil {
		t.Fatal("the listener still accepts connections after close")
	}
	// An inbound torn down twice reaches this path again; it must not panic, and the error of
	// the second close is the closed listener, not a second release of the connections.
	_ = server.Close()
}
