//go:build linux

package tun

import (
	"net/netip"
	"testing"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

// The no-auto-route IPv6 path has two properties that used to be wrong together: the rule must not
// shadow rules the instance did not create, and an IPv6 address without a route table entry needs a
// default route or the rule blackholes everything. The pure parts are tested here; the actual
// netlink insertion is exercised by the device/integration matrix, not by this file.

type testTunLink struct {
	attrs netlink.LinkAttrs
}

func (l *testTunLink) Attrs() *netlink.LinkAttrs { return &l.attrs }
func (l *testTunLink) Type() string              { return "tun" }

func testNativeTun(name string, tableIndex int, address netip.Prefix, autoRoute bool) *NativeTun {
	return &NativeTun{options: Options{
		Name:                     name,
		AutoRoute:                autoRoute,
		Inet6Address:             []netip.Prefix{address},
		IPRoute2TableIndex:       tableIndex,
		Inet6RouteExcludeAddress: nil,
	}}
}

func TestNextIPv6RulePriorityStaysAboveOwnedRedirectRules(t *testing.T) {
	if priority := nextIPv6RulePriority(nil); priority != redirectRouteRulePriority+1 {
		t.Fatalf("empty rule table: priority %d, want %d", priority, redirectRouteRulePriority+1)
	}

	onlyRedirect := []netlink.Rule{{Priority: redirectRouteRulePriority}}
	if priority := nextIPv6RulePriority(onlyRedirect); priority != redirectRouteRulePriority+1 {
		t.Fatalf("only redirect rule: priority %d, want %d", priority, redirectRouteRulePriority+1)
	}

	existing := []netlink.Rule{{Priority: redirectRouteRulePriority}, {Priority: 100}, {Priority: 300}, {Priority: 0}}
	if priority := nextIPv6RulePriority(existing); priority != 99 {
		t.Fatalf("priority below the lowest foreign rule: got %d, want 99", priority)
	}

	// A foreign rule exactly at redirectRouteRulePriority+1 must not make the result fall onto the
	// redirect rules, even though it cannot be strictly below it.
	tight := []netlink.Rule{{Priority: redirectRouteRulePriority + 1}}
	if priority := nextIPv6RulePriority(tight); priority != redirectRouteRulePriority+1 {
		t.Fatalf("tight table: priority %d, want %d", priority, redirectRouteRulePriority+1)
	}
}

func TestRoutesAddDefaultIPv6RouteWithoutAutoRoute(t *testing.T) {
	tun := testNativeTun("tun0", 1000, netip.MustParsePrefix("fdfe:dcba:9876::1/64"), false)
	link := &testTunLink{attrs: netlink.LinkAttrs{Index: 7}}
	routes, err := tun.routes(link)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, route := range routes {
		if route.Table != 1000 {
			t.Fatalf("route %v is in table %d, want 1000", route.Dst, route.Table)
		}
		if route.LinkIndex != 7 {
			t.Fatalf("route %v has link index %d, want 7", route.Dst, route.LinkIndex)
		}
		if route.Dst != nil && route.Dst.String() == "::/0" {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("default IPv6 route count = %d, want exactly 1 (routes: %d)", found, len(routes))
	}
}

func TestRoutesKeepExplicitIPv6RouteAddress(t *testing.T) {
	tun := testNativeTun("tun0", 1000, netip.MustParsePrefix("fdfe:dcba:9876::1/64"), false)
	tun.options.Inet6RouteAddress = []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}
	routes, err := tun.routes(&testTunLink{attrs: netlink.LinkAttrs{Index: 7}})
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || routes[0].Dst.String() != "2001:db8::/32" {
		t.Fatalf("explicit route address changed: %v", routes)
	}
}

func TestTwoTunInstancesKeepSeparateRuleAndRouteTables(t *testing.T) {
	first := testNativeTun("tun0", 1000, netip.MustParsePrefix("fdfe:dcba:9876::1/64"), false)
	second := testNativeTun("tun1", 2000, netip.MustParsePrefix("fdfe:dcba:9876:1::1/64"), false)

	// Both instances derive a priority from the same live rule table; that is allowed because the
	// rule identity is (interface, table), not priority.
	priority := nextIPv6RulePriority(nil)
	firstRule := first.ipv6Rule(priority)
	secondRule := second.ipv6Rule(priority)
	if firstRule.Table == secondRule.Table || firstRule.OifName == secondRule.OifName {
		t.Fatalf("instances built the same rule identity: %+v %+v", firstRule, secondRule)
	}
	if firstRule.Family != unix.AF_INET6 || secondRule.Family != unix.AF_INET6 {
		t.Fatal("IPv6 rules must be AF_INET6")
	}

	firstDelete := first.ipv6RuleDelete()
	secondDelete := second.ipv6RuleDelete()
	if firstDelete.Table != firstRule.Table || firstDelete.OifName != firstRule.OifName {
		t.Fatalf("first delete identity %+v does not match its rule %+v", firstDelete, firstRule)
	}
	if secondDelete.Table != secondRule.Table || secondDelete.OifName != secondRule.OifName {
		t.Fatalf("second delete identity %+v does not match its rule %+v", secondDelete, secondRule)
	}
	if firstDelete.Table == secondDelete.Table || firstDelete.OifName == secondDelete.OifName {
		t.Fatal("one instance's cleanup would delete the other instance's rule")
	}

	for _, tun := range []*NativeTun{first, second} {
		routes, err := tun.routes(&testTunLink{attrs: netlink.LinkAttrs{Index: 7}})
		if err != nil {
			t.Fatal(err)
		}
		hasDefault := false
		for _, route := range routes {
			if route.Table != tun.options.IPRoute2TableIndex {
				t.Fatalf("%s route in table %d, want %d", tun.options.Name, route.Table, tun.options.IPRoute2TableIndex)
			}
			if route.Dst != nil && route.Dst.String() == "::/0" {
				hasDefault = true
			}
		}
		if !hasDefault {
			t.Fatalf("%s has no default IPv6 route", tun.options.Name)
		}
	}
}
