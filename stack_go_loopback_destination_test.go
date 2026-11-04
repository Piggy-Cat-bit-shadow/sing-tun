package tun

import (
	"net/netip"
	"testing"
)

// Only the exact address is the device's own. The whole /24 is not, and neither is the address
// next door: taking over a range would silently capture traffic that was never meant to be local,
// which is worse than not answering at all.

func TestIsLoopbackDestinationMatchesTheExactAddress(t *testing.T) {
	t.Parallel()
	inet4 := []netip.Addr{netip.MustParseAddr("10.7.0.1")}
	inet6 := []netip.Addr{netip.MustParseAddr("fdfe:7::1")}
	if !isLoopbackDestination(netip.MustParseAddr("10.7.0.1"), inet4, inet6) {
		t.Fatal("the configured IPv4 address did not match")
	}
	if !isLoopbackDestination(netip.MustParseAddr("fdfe:7::1"), inet4, inet6) {
		t.Fatal("the configured IPv6 address did not match")
	}
}

func TestIsLoopbackDestinationRejectsNeighboursAndOtherLoopbacks(t *testing.T) {
	t.Parallel()
	inet4 := []netip.Addr{netip.MustParseAddr("10.7.0.1")}
	inet6 := []netip.Addr{netip.MustParseAddr("fdfe:7::1")}
	for _, destination := range []string{
		"10.7.0.2",   // the address next door
		"10.7.0.0",   // the network address
		"10.0.0.1",   // another range
		"127.0.0.1",  // the device's own loopback, which is not what this feature answers for
		"fdfe:7::2",  // the IPv6 address next door
		"0.0.0.0",    // unspecified
		"255.255.255.255",
	} {
		if isLoopbackDestination(netip.MustParseAddr(destination), inet4, inet6) {
			t.Fatalf("%s was treated as a loopback destination", destination)
		}
	}
}

func TestIsLoopbackDestinationUnmapsAndStripsZones(t *testing.T) {
	t.Parallel()
	// A packet may carry the mapped spelling of an address the configuration keeps in its plain
	// form; both are the same address to the core's own merge.
	inet4 := []netip.Addr{netip.MustParseAddr("10.7.0.1")}
	if !isLoopbackDestination(netip.MustParseAddr("::ffff:10.7.0.1"), inet4, nil) {
		t.Fatal("the IPv4-mapped spelling did not match the plain configuration")
	}
	inet6 := []netip.Addr{netip.MustParseAddr("fe80::1")}
	if !isLoopbackDestination(netip.MustParseAddr("fe80::1%en0"), inet4, inet6) {
		t.Fatal("a zoned destination did not match the unzoned configuration")
	}
}

func TestIsLoopbackDestinationKeepsTheFamiliesApart(t *testing.T) {
	t.Parallel()
	// The same bytes are not the same address across families: an IPv4 destination must not match
	// an IPv6 entry and vice versa.
	inet4 := []netip.Addr{netip.MustParseAddr("10.7.0.1")}
	inet6 := []netip.Addr{netip.MustParseAddr("fdfe:7::1")}
	if isLoopbackDestination(netip.MustParseAddr("fdfe:7::1"), inet4, nil) {
		t.Fatal("an IPv6 destination matched the IPv4 list")
	}
	if isLoopbackDestination(netip.MustParseAddr("10.7.0.1"), nil, inet6) {
		t.Fatal("an IPv4 destination matched the IPv6 list")
	}
}

func TestIsLoopbackDestinationWithNoConfiguration(t *testing.T) {
	t.Parallel()
	if isLoopbackDestination(netip.MustParseAddr("10.7.0.1"), nil, nil) {
		t.Fatal("an empty configuration matched")
	}
	if isLoopbackDestination(netip.Addr{}, nil, nil) {
		t.Fatal("an invalid destination matched")
	}
}
