package tun

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/sagernet/sing-tun/internal/winipcfg"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/windows"
)

const (
	kernelConnectionRefused = windows.WSAECONNREFUSED
	kernelConnectionReset   = windows.WSAECONNRESET
)

// allowKernelPacketPort admits inbound UDP for one client port. The kernel packet test
// deliberately sends return datagrams from peers the client never contacted, and the
// Windows firewall is stateful for UDP: without an explicit rule it drops exactly those
// datagrams, which hides the NAT filtering behaviour under test. The test already needs
// administrator rights to create the TUN adapter, so the rule can be installed and
// removed around the client socket.
func allowKernelPacketPort(t *testing.T, port int) {
	t.Helper()
	ruleName := fmt.Sprintf("sing-tun kernel packet mapping %d-%d", os.Getpid(), port)
	output, err := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+ruleName,
		"dir=in",
		"action=allow",
		"protocol=UDP",
		fmt.Sprintf("localport=%d", port),
		"profile=any",
		"enable=yes",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("allow inbound UDP to port %d: %s: %v", port, output, err)
	}
	t.Cleanup(func() {
		_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName).Run()
	})
}

func kernelSetSocketBuffers(descriptor uintptr, size int) error {
	return E.Errors(
		windows.SetsockoptInt(windows.Handle(descriptor), windows.SOL_SOCKET, windows.SO_RCVBUF, size),
		windows.SetsockoptInt(windows.Handle(descriptor), windows.SOL_SOCKET, windows.SO_SNDBUF, size),
	)
}

func configureKernelInterface(t *testing.T, device Tun, options Options) {
	t.Helper()
	luid := winipcfg.LUID(device.(*NativeTun).adapter.LUID())
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		addresses := options.Inet4Address
		if family == windows.AF_INET6 {
			addresses = options.Inet6Address
		}
		err := luid.SetIPAddressesForFamily(family, addresses)
		if err != nil {
			t.Fatal(err)
		}
		row, err := luid.IPInterface(family)
		if err != nil {
			t.Fatal(err)
		}
		row.NLMTU = options.MTU
		row.DadTransmits = 0
		row.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		err = row.Set()
		if err != nil {
			t.Fatal(err)
		}
	}
}
