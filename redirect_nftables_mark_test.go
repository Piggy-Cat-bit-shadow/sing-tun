//go:build linux

package tun

import (
	"bytes"
	"os"
	"testing"

	"github.com/sagernet/nftables"
	"github.com/sagernet/nftables/binaryutil"
	"github.com/sagernet/nftables/expr"
)

func newMarkTestRedirect() *autoRedirect {
	return &autoRedirect{
		tableName: "sing_tun_mark_test_probe",
		tunOptions: &Options{
			AutoRedirectInputMark:  0x1a2,
			AutoRedirectOutputMark: 0x1a3,
			AutoRedirectResetMark:  0x1a4,
			AutoRedirectTProxyMark: 0x1a5,
		},
	}
}

// markBitwise extracts the single Bitwise expression a mark operation builds, so a test can look
// at the mask and the xor instead of at the register plumbing around them.
func markBitwise(t *testing.T, exprs []expr.Any) *expr.Bitwise {
	t.Helper()
	var found *expr.Bitwise
	for _, expression := range exprs {
		bitwise, isBitwise := expression.(*expr.Bitwise)
		if !isBitwise {
			continue
		}
		if found != nil {
			t.Fatal("a mark operation must contain exactly one Bitwise expression")
		}
		found = bitwise
	}
	if found == nil {
		t.Fatal("a mark operation must contain a Bitwise expression")
	}
	return found
}

// A rule that compares a mark must only look at the bits this package owns: the kernel packet
// mark carries other programs' bits too (policy routing, Android netd's VPN bits, a QoS chain),
// and an unmasked comparison would both match those flows and, before this change, store a value
// that cleared them.
func TestNFTablesMarkMatchMasksForeignBits(t *testing.T) {
	redirect := newMarkTestRedirect()
	mask := redirect.effectiveMarkMask()
	foreign := uint32(0x0e00)
	if foreign&mask != 0 {
		t.Fatalf("the test assumes 0x%x is outside the effective mask 0x%x", foreign, mask)
	}
	testCases := []struct {
		name      string
		conntrack bool
	}{
		{"packet mark", false},
		{"connmark", true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			exprs := redirect.nftablesMarkMatch(testCase.conntrack, expr.CmpOpEq, 0x1a2)
			if len(exprs) != 3 {
				t.Fatalf("expected a load, a mask and a compare, got %d expressions", len(exprs))
			}
			bitwise := markBitwise(t, exprs)
			if !bytes.Equal(bitwise.Mask, binaryutil.NativeEndian.PutUint32(mask)) {
				t.Fatalf("the compare mask is 0x%x instead of the effective mask 0x%x", binaryutil.NativeEndian.Uint32(bitwise.Mask), mask)
			}
			if !bytes.Equal(bitwise.Xor, make([]byte, 4)) {
				t.Fatalf("a compare must not fold a value into the mask, xor is 0x%x", binaryutil.NativeEndian.Uint32(bitwise.Xor))
			}
			compare, isCompare := exprs[2].(*expr.Cmp)
			if !isCompare || compare.Op != expr.CmpOpEq {
				t.Fatalf("the last expression must compare the masked mark for equality, got %T", exprs[2])
			}
			if !bytes.Equal(compare.Data, binaryutil.NativeEndian.PutUint32(0x1a2)) {
				t.Fatalf("the compare value is 0x%x instead of the mark", binaryutil.NativeEndian.Uint32(compare.Data))
			}
		})
	}
}

// Writing a mark has the opposite mask: the bits outside this package's mask are copied from the
// value they already had, and the mark is folded in with xor, so a neighbouring program's bits
// survive the update.
func TestNFTablesMarkSetPreservesForeignBits(t *testing.T) {
	redirect := newMarkTestRedirect()
	mask := redirect.effectiveMarkMask()
	foreign := uint32(0x0e00)
	if foreign&mask != 0 {
		t.Fatalf("the test assumes 0x%x is outside the effective mask 0x%x", foreign, mask)
	}
	testCases := []struct {
		name      string
		conntrack bool
	}{
		{"packet mark", false},
		{"connmark", true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			mark := uint32(0x1a2)
			exprs := redirect.nftablesMarkSet(testCase.conntrack, mark)
			if len(exprs) != 3 {
				t.Fatalf("expected a load, an update and a store, got %d expressions", len(exprs))
			}
			bitwise := markBitwise(t, exprs)
			preservedMask := ^mask
			if !bytes.Equal(bitwise.Mask, binaryutil.NativeEndian.PutUint32(preservedMask)) {
				t.Fatalf("the update mask is 0x%x instead of the complement of the effective mask 0x%x", binaryutil.NativeEndian.Uint32(bitwise.Mask), preservedMask)
			}
			if !bytes.Equal(bitwise.Xor, binaryutil.NativeEndian.PutUint32(mark)) {
				t.Fatalf("the update xor is 0x%x instead of the mark", binaryutil.NativeEndian.Uint32(bitwise.Xor))
			}
			// (value &^ mask) | mark == (value &^ mask) ^ (mark &^ mask) for a mark inside the mask.
			if mark&^mask != 0 {
				t.Fatalf("the test mark 0x%x must fit inside the effective mask 0x%x", mark, mask)
			}
			preserved := foreign & preservedMask
			if preserved != foreign {
				t.Fatalf("a foreign bit 0x%x would be cleared by the update", foreign)
			}
		})
	}
}

// With strict route and a single address family, the route chain must skip the disabled family
// instead of rejecting it: rejecting there also rejected the neighbour discovery and ICMP errors
// the kernel itself needs, which turned the family into a black hole rather than "unreachable".
func TestNFTablesUnreachableFamily(t *testing.T) {
	testCases := []struct {
		name     string
		redirect *autoRedirect
		expected nftables.TableFamily
	}{
		{
			name:     "dual stack has nothing unreachable",
			redirect: &autoRedirect{enableIPv4: true, enableIPv6: true, tunOptions: &Options{StrictRoute: true}},
			expected: nftables.TableFamilyUnspecified,
		},
		{
			name:     "strict route is what makes a family unreachable",
			redirect: &autoRedirect{enableIPv4: true, tunOptions: &Options{StrictRoute: false}},
			expected: nftables.TableFamilyUnspecified,
		},
		{
			name:     "ipv4 only rejects ipv6",
			redirect: &autoRedirect{enableIPv4: true, tunOptions: &Options{StrictRoute: true}},
			expected: nftables.TableFamilyIPv6,
		},
		{
			name:     "ipv6 only rejects ipv4",
			redirect: &autoRedirect{enableIPv6: true, tunOptions: &Options{StrictRoute: true}},
			expected: nftables.TableFamilyIPv4,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if family := testCase.redirect.nftablesUnreachableFamily(); family != testCase.expected {
				t.Fatalf("unreachable family is %d instead of %d", family, testCase.expected)
			}
		})
	}
}

// The probe is what turns a missing kernel module into a bounded fallback instead of a half
// installed ruleset, so its own expressions have to be accepted by a real kernel. The assertions
// here are about the probe being well formed: a table that the kernel rejects for any reason
// other than a missing module means the probe would report a false negative.
func TestNFTablesProbeOnKernel(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("a netfilter probe needs root")
	}
	redirect := newMarkTestRedirect()
	err := redirect.nftablesProbe(nftables.ChainTypeNAT)
	if err != nil {
		t.Skipf("this kernel has no inet nat chain: %s", err)
	}
	err = redirect.nftablesProbe(nftables.ChainTypeFilter, &expr.Reject{Type: 2})
	if err != nil {
		t.Logf("reject in prerouting is unavailable: %s", err)
	}
	err = redirect.nftablesProbe(nftables.ChainTypeFilter,
		&expr.Fib{Register: 1, FlagDADDR: true, ResultADDRTYPE: true},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0x0000000d)},
	)
	if err != nil {
		t.Logf("fib is unavailable: %s", err)
	}
	err = redirect.nftablesProbe(nftables.ChainTypeFilter, &expr.Queue{Num: redirect.effectiveNFQueue(), Flag: expr.QueueFlagBypass})
	if err != nil {
		t.Logf("queue is unavailable: %s", err)
	}
}
