//go:build linux

package tun

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"testing"

	"github.com/sagernet/netlink"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// Real-kernel verification of the no-auto-route IPv6 instance: two real TUN devices, each with its
// own table, rule and ::/0 route, then closing one must remove only its own rule and route. It needs
// root / CAP_NET_ADMIN and /dev/net/tun, so it skips for ordinary users; the push gate does not run
// it, and the pure computation is covered by tun_linux_test.go.
func privilegedTunOptions(name string, table int) Options {
	return Options{
		Name:               name,
		MTU:                1500,
		AutoRoute:          false,
		Inet6Address:       []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/64")},
		IPRoute2TableIndex: table,
	}
}

func ruleForTun(t *testing.T, name string, table int) bool {
	t.Helper()
	rules, err := netlink.RuleList(netlink.FAMILY_V6)
	require.NoError(t, err)
	for index := range rules {
		rule := &rules[index]
		if rule.Table == table && rule.OifName == name && rule.Family == unix.AF_INET6 {
			return true
		}
	}
	return false
}

func tableHasDefaultIPv6Route(t *testing.T, table int) bool {
	t.Helper()
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
	require.NoError(t, err)
	for index := range routes {
		route := &routes[index]
		if route.Dst == nil {
			return true
		}
		ones, bits := route.Dst.Mask.Size()
		if route.Dst.IP.IsUnspecified() && ones == 0 && bits == 128 {
			return true
		}
	}
	return false
}

func TestPrivilegedDualTunIPv6RuleAndRouteLifecycle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root / CAP_NET_ADMIN and /dev/net/tun")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("no /dev/net/tun")
	}
	pid := os.Getpid()
	baseTable := 23000 + pid%1000*2
	firstName := fmt.Sprintf("p01a%d", pid)
	secondName := fmt.Sprintf("p01b%d", pid)

	first, err := New(privilegedTunOptions(firstName, baseTable))
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = first.Close()
		_ = exec.Command("ip", "link", "del", firstName).Run()
	})
	// NativeTun.Start also registers with the interface monitor; the route/rule work is in start()
	// and a direct call keeps this test independent of the monitor implementation.
	require.NoError(t, first.(*NativeTun).start())
	require.True(t, ruleForTun(t, firstName, baseTable), "first instance has no IPv6 oif rule")
	require.True(t, tableHasDefaultIPv6Route(t, baseTable), "first instance has no ::/0 route in its table")

	second, err := New(privilegedTunOptions(secondName, baseTable+1))
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = second.Close()
		_ = exec.Command("ip", "link", "del", secondName).Run()
	})
	require.NoError(t, second.(*NativeTun).start())
	require.True(t, ruleForTun(t, firstName, baseTable), "second instance removed the first rule")
	require.True(t, ruleForTun(t, secondName, baseTable+1), "second instance has no IPv6 oif rule")
	require.True(t, tableHasDefaultIPv6Route(t, baseTable), "second instance removed the first default route")
	require.True(t, tableHasDefaultIPv6Route(t, baseTable+1), "second instance has no ::/0 route in its table")

	require.NoError(t, first.Close())
	require.False(t, ruleForTun(t, firstName, baseTable), "closing the first instance left its rule")
	require.True(t, ruleForTun(t, secondName, baseTable+1), "closing the first instance removed the second rule")
	require.True(t, tableHasDefaultIPv6Route(t, baseTable+1), "closing the first instance removed the second route")

	require.NoError(t, second.Close())
	require.False(t, ruleForTun(t, secondName, baseTable+1), "closing the second instance left its rule")
}
