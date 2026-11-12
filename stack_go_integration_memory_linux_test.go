//go:build linux && !android

package tun

import (
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/sagernet/netlink"

	"golang.org/x/sys/unix"
)

const kernelMaxDatagram = 60000

func kernelAddUnreachableRoute(t *testing.T, interfaceName string, prefix netip.Prefix) bool {
	t.Helper()
	if prefix.Addr().Is4() {
		// The kernel answers a packet it cannot deliver locally only after the
		// forwarding decision, and it takes that decision only when the ingress
		// interface has forwarding enabled. With forwarding off the packet is
		// dropped without an ICMP error, so the unreachable route behaves like a
		// black hole and the dial times out instead of failing. Runners that also
		// run Docker usually inherit net.ipv4.ip_forward=1 from the daemon, which
		// hides the dependency; WSL and a plain distribution kernel leave it off.
		// Enable forwarding on the test interface only, so the kernel still is the
		// one that produces the ICMP unreachable the test asserts.
		enableKernelIPv4Forwarding(t, interfaceName)
	}
	route := &netlink.Route{
		Dst:  &net.IPNet{IP: prefix.Addr().AsSlice(), Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen())},
		Type: unix.RTN_UNREACHABLE,
	}
	err := netlink.RouteAdd(route)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { netlink.RouteDel(route) })
	return true
}

func enableKernelIPv4Forwarding(t *testing.T, interfaceName string) {
	t.Helper()
	path := "/proc/sys/net/ipv4/conf/" + interfaceName + "/forwarding"
	previous, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	value := strings.TrimSpace(string(previous))
	err = os.WriteFile(path, []byte("1"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.WriteFile(path, []byte(value), 0o644)
	})
}
