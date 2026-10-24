//go:build !windows

package tun

import "testing"

// allowKernelPacketPort is only needed on Windows, whose firewall is stateful for UDP.
func allowKernelPacketPort(*testing.T, int) {}
