//go:build darwin && !ios

package tun

import (
	"net/netip"
	"testing"
)

func kernelAddUnreachableRoute(_ *testing.T, _ string, _ netip.Prefix) bool {
	return false
}

// net.inet.udp.maxdgram caps a datagram at 9216 bytes.
const kernelMaxDatagram = 9216
