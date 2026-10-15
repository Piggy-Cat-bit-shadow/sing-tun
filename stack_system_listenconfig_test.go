package tun

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

// An IPv6-only system stack must be able to re-bind its TCP listener after an unexpected accept
// failure, exactly as an IPv4-only or dual-stack one can.
//
// # The failure this kills
//
// The accept loop re-binds from the configuration start() recorded. That configuration is NOT
// family-specific - the network name and the address are per-family arguments passed to the loop
// separately - but it used to be recorded inside the IPv4 branch only. An IPv6-only stack therefore
// had nothing to re-bind with, recoverListener returned "no listen configuration recorded for tcp6
// ...", and the loop terminated PERMANENTLY.
//
// The listener's port is what the forward path rewrites every new IPv6 SYN onto, and nothing clears
// it when the loop dies: the stack keeps rewriting connections onto a dead port, the OS answers RST,
// and every new IPv6 TCP connection fails until the tunnel is rebuilt - while UDP and QUIC carry on
// working. That is the "browser is dead but Telegram is fine" presentation this fork's accept-loop
// recovery exists to prevent, reintroduced for one family by where a field was assigned.
//
// # Why the existing tests cannot see it
//
// Every test in stack_system_accept_test.go injects system.recreateListener, so the production
// closure - and with it the `listenConfig == nil` check - is never evaluated. Those tests prove the
// loop recovers GIVEN a bind function; they cannot prove the bind function exists. This one drives
// the production closure with no seam, which is the only way the difference is observable.
//
// # What it deliberately does not need
//
// No TUN device: start() needs neither the device nor the forwarding dispatcher, so options.Handler
// and options.Tun are nil here. It DOES bind a real TCP listener, because that is the behaviour under
// test, so the configured address is a wildcard - which is bindable on any host with the family
// enabled and is also how a forwarder is normally configured. An address that is not assigned to an
// interface would make the test depend on the host's addressing rather than on the code.
func TestSystemIPv6OnlyStackRecordsListenConfigAndRecovers(t *testing.T) {
	shrinkRecoveryDelays(t)

	ctx, cancelContext := context.WithCancel(context.Background())
	t.Cleanup(cancelContext)

	// IPv6-ONLY: no Inet4Address at all. This is a legal configuration - NewSystem requires only
	// that ONE of the two families be present.
	stack, err := NewSystem(StackOptions{
		Context:    ctx,
		TunOptions: Options{Name: "tun0", MTU: 1500, Inet6Address: []netip.Prefix{netip.MustParsePrefix("::/126")}},
		UDPTimeout: time.Minute,
		Logger:     logger.NOP(),
	})
	require.NoError(t, err)
	system := stack.(*System)

	require.False(t, system.inet4NextAddress.IsValid(), "precondition: this stack must be IPv6-only")
	require.True(t, system.inet6NextAddress.IsValid())

	require.NoError(t, system.start())
	t.Cleanup(func() {
		// The TCP NAT has no Close: its timeout goroutine ends with the context the cleanup above
		// cancels.
		cancelContext()
		if system.udpNat != nil {
			_ = system.udpNat.Close()
		}
		system.listenerAccess.Lock()
		listeners := []net.Listener{system.tcpListener, system.tcpListener6}
		system.listenerAccess.Unlock()
		for _, listener := range listeners {
			if listener != nil {
				_ = listener.Close()
			}
		}
	})

	// THE ASSERTION. start() must have recorded a bind configuration for an IPv6-only stack. Without
	// the fix this is nil, and the recovery below cannot possibly succeed.
	require.NotNil(t, system.listenConfig,
		"an IPv6-only stack must record the bind configuration, or its accept loop can never recover")

	// The v6 listener is the real bound one, and it is the one the recovery path must publish to.
	// The production dispatch path identifies the family by the network string, so a recovery that
	// published a v6 port into tcpPort would leave every new IPv6 SYN pointing at a dead port.
	system.listenerAccess.Lock()
	initialListener := system.tcpListener6
	initialPort := system.tcpPort6
	require.Nil(t, system.tcpListener, "precondition: no IPv4 listener on an IPv6-only stack")
	system.listenerAccess.Unlock()
	require.NotNil(t, initialListener)
	require.NotZero(t, initialPort)

	require.Zero(t, system.RecoveredListeners(), "precondition: nothing has recovered yet")

	// The unexpected failure: the listener is closed from outside this stack, which is what the
	// shared fd space of an embedding application produces on a fast restart. recoverListener is the
	// production path and uses the recorded configuration - system.recreateListener stays nil.
	require.NoError(t, initialListener.Close())

	recovered, err := system.recoverListener(initialListener, "tcp6", net.JoinHostPort(system.inet6Address.String(), "0"))
	require.NoError(t, err,
		"an IPv6-only stack must be able to re-bind its TCP listener; the pre-fix code failed here "+
			"with 'no listen configuration recorded for tcp6' and the accept loop then exited for good")
	require.NotNil(t, recovered)
	t.Cleanup(func() { _ = recovered.Close() })
	require.Equal(t, uint64(1), system.RecoveredListeners())

	// The new port is published into the IPv6 field, which is what the next IPv6 SYN is rewritten
	// onto, and the IPv4 field is untouched.
	system.listenerAccess.Lock()
	publishedPort6 := system.tcpPort6
	publishedListener6 := system.tcpListener6
	untouchedPort4 := system.tcpPort
	system.listenerAccess.Unlock()
	require.Equal(t, recovered, publishedListener6, "the recovered listener must be the one published")
	require.NotZero(t, publishedPort6)
	require.Zero(t, untouchedPort4,
		"recovering the IPv6 listener must not publish a port into the IPv4 field: the two families "+
			"have separate ports and a crossed publish would point IPv4 at a dead one")
}

// TestSystemDualStackRecordsListenConfigForBothFamilies is the same field, asserted for the
// configuration the IPv4-only branch used to be the only one to cover.
//
// A dual-stack stack must record the configuration regardless of which families are present, and its
// recovery must still publish by family. It is the companion to the IPv6-only test: together they
// pin that the recording is not merely "happens to work when IPv4 is configured".
func TestSystemDualStackRecordsListenConfigForBothFamilies(t *testing.T) {
	shrinkRecoveryDelays(t)

	ctx, cancelContext := context.WithCancel(context.Background())
	t.Cleanup(cancelContext)

	stack, err := NewSystem(StackOptions{
		Context: ctx,
		TunOptions: Options{
			Name:         "tun0",
			MTU:          1500,
			Inet4Address: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/30")},
			Inet6Address: []netip.Prefix{netip.MustParsePrefix("::/126")},
		},
		UDPTimeout: time.Minute,
		Logger:     logger.NOP(),
	})
	require.NoError(t, err)
	system := stack.(*System)

	require.True(t, system.inet4NextAddress.IsValid())
	require.True(t, system.inet6NextAddress.IsValid())

	require.NoError(t, system.start())
	t.Cleanup(func() {
		cancelContext()
		if system.udpNat != nil {
			_ = system.udpNat.Close()
		}
		system.listenerAccess.Lock()
		listeners := []net.Listener{system.tcpListener, system.tcpListener6}
		system.listenerAccess.Unlock()
		for _, listener := range listeners {
			if listener != nil {
				_ = listener.Close()
			}
		}
	})

	require.NotNil(t, system.listenConfig, "a dual-stack stack must record the bind configuration")

	system.listenerAccess.Lock()
	initialListener6 := system.tcpListener6
	initialPort4 := system.tcpPort
	system.listenerAccess.Unlock()
	require.NotNil(t, initialListener6)
	require.NotZero(t, initialPort4)

	require.NoError(t, initialListener6.Close())
	recovered, err := system.recoverListener(initialListener6, "tcp6", net.JoinHostPort(system.inet6Address.String(), "0"))
	require.NoError(t, err)
	require.NotNil(t, recovered)
	t.Cleanup(func() { _ = recovered.Close() })

	system.listenerAccess.Lock()
	publishedPort4 := system.tcpPort
	publishedListener6 := system.tcpListener6
	system.listenerAccess.Unlock()
	require.Equal(t, recovered, publishedListener6)
	require.Equal(t, initialPort4, publishedPort4,
		"recovering the IPv6 listener must leave the IPv4 port exactly as it was")
}
