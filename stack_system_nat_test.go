package tun

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
)

// The system stack's TCP NAT used to release a mapping only when the data timeout elapsed, so a
// closed connection kept a port (and its reverse path) for up to two hours, and a late packet could
// arrive on it. These tests pin the closing state: FIN/FIN or RST moves the session to a short
// closing timeout, and a new SYN on the same four-tuple gets a fresh mapping instead of the dead one.

func newTCPNatWithTimeout(t *testing.T, timeout time.Duration) *TCPNat {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	nat := NewNat(ctx, timeout)
	t.Cleanup(cancel)
	return nat
}

func tcpNatTestAddrs() (netip.AddrPort, netip.AddrPort) {
	return netip.MustParseAddrPort("10.0.0.2:40000"), netip.MustParseAddrPort("93.184.216.34:443")
}

func ageTCPSession(nat *TCPNat, port uint16, age time.Duration) {
	nat.portAccess.RLock()
	session := nat.portMap[port]
	nat.portAccess.RUnlock()
	if session == nil {
		return
	}
	session.Lock()
	session.LastActive = time.Now().Add(-age)
	session.Unlock()
}

func tcpSessionClosed(nat *TCPNat, port uint16) bool {
	nat.portAccess.RLock()
	session := nat.portMap[port]
	nat.portAccess.RUnlock()
	if session == nil {
		return false
	}
	session.Lock()
	defer session.Unlock()
	return session.closed
}

func TestTCPNatClosedSessionExpiresWithoutWaitingForTheDataTimeout(t *testing.T) {
	source, destination := tcpNatTestAddrs()
	nat := newTCPNatWithTimeout(t, time.Hour)

	port := nat.Lookup(source, destination, header.TCPFlagSyn)
	if port == 0 {
		t.Fatal("no NAT port allocated for a new session")
	}

	// One FIN is half a close: the reverse direction can still be carrying data.
	nat.Lookup(source, destination, header.TCPFlagFin)
	ageTCPSession(nat, port, tcpClosingTimeout+time.Second)
	nat.checkTimeout()
	if tcpSessionClosed(nat, port) {
		// Closed means both directions said goodbye; a single FIN must not have set it.
		t.Fatal("a single FIN marked the session closed")
	}
	if nat.LookupBack(port, 0) == nil {
		t.Fatal("a half-closed session was expired after the closing timeout")
	}

	// The reverse FIN completes the close.
	nat.LookupBack(port, header.TCPFlagFin)
	if !tcpSessionClosed(nat, port) {
		t.Fatal("FIN in both directions did not mark the session closed")
	}
	ageTCPSession(nat, port, tcpClosingTimeout+time.Second)
	nat.checkTimeout()
	if nat.LookupBack(port, 0) != nil {
		t.Fatal("a closed session survived the closing timeout because the data timeout is longer")
	}

	// A new connection on the same four-tuple must get a new mapping, not the closed one.
	reused := nat.Lookup(source, destination, header.TCPFlagSyn)
	if reused == 0 {
		t.Fatal("no NAT port allocated after the closed mapping was released")
	}
	if reused == port {
		t.Fatalf("the closed NAT port %d was handed to a new connection", port)
	}
}

func TestTCPNatRstClosesSession(t *testing.T) {
	source, destination := tcpNatTestAddrs()
	nat := newTCPNatWithTimeout(t, time.Hour)
	port := nat.Lookup(source, destination, header.TCPFlagSyn)
	nat.LookupBack(port, header.TCPFlagRst)
	if !tcpSessionClosed(nat, port) {
		t.Fatal("RST did not mark the session closed")
	}
	ageTCPSession(nat, port, tcpClosingTimeout+time.Second)
	nat.checkTimeout()
	if nat.LookupBack(port, 0) != nil {
		t.Fatal("an RST-closed session survived the closing timeout")
	}
}

func TestTCPNatLateSynDoesNotReviveAClosedSession(t *testing.T) {
	source, destination := tcpNatTestAddrs()
	nat := newTCPNatWithTimeout(t, time.Hour)
	port := nat.Lookup(source, destination, header.TCPFlagSyn)
	nat.Lookup(source, destination, header.TCPFlagFin)
	nat.LookupBack(port, header.TCPFlagFin)
	if !tcpSessionClosed(nat, port) {
		t.Fatal("the session is not closed")
	}

	nat.portAccess.RLock()
	closedSession := nat.portMap[port]
	nat.portAccess.RUnlock()

	// The retransmitted SYN arrives before the sweeper has run: it must allocate a fresh mapping
	// and drop the closed one from the port space, not reactivate it.
	reused := nat.Lookup(source, destination, header.TCPFlagSyn)
	if reused == port {
		t.Fatal("the late SYN reused the closed NAT port")
	}
	nat.portAccess.RLock()
	replacement := nat.portMap[reused]
	_, oldStillMapped := nat.portMap[port]
	nat.portAccess.RUnlock()
	if oldStillMapped {
		t.Fatal("the closed mapping stayed in the port space after a new SYN reused the four-tuple")
	}
	if replacement == nil || replacement == closedSession {
		t.Fatal("the late SYN did not install a new session")
	}
	if tcpSessionClosed(nat, reused) {
		t.Fatal("the replacement session inherited the closed state")
	}

	// A late data packet on the old port must not resurrect it either.
	if nat.LookupBack(port, header.TCPFlagAck) != nil {
		t.Fatal("a late data packet found the released mapping")
	}
}

func TestTCPNatSweepDoesNotResurrectOrDoubleRelease(t *testing.T) {
	source, destination := tcpNatTestAddrs()
	nat := newTCPNatWithTimeout(t, time.Hour)

	ports := make([]uint16, 32)
	for index := range ports {
		ports[index] = nat.Lookup(source, netip.AddrPortFrom(destination.Addr(), uint16(40000+index)), header.TCPFlagSyn)
	}
	for index, port := range ports[:16] {
		nat.Lookup(source, netip.AddrPortFrom(destination.Addr(), uint16(40000+index)), header.TCPFlagFin)
		nat.LookupBack(port, header.TCPFlagFin)
		ageTCPSession(nat, port, tcpClosingTimeout+time.Second)
	}

	var wait sync.WaitGroup
	wait.Add(3)
	go func() {
		defer wait.Done()
		for range 200 {
			nat.checkTimeout()
		}
	}()
	go func() {
		defer wait.Done()
		for index := range 200 {
			port := ports[index%len(ports)]
			nat.LookupBack(port, header.TCPFlagAck)
		}
	}()
	go func() {
		defer wait.Done()
		for index := range 200 {
			nat.Lookup(source, netip.AddrPortFrom(destination.Addr(), uint16(50000+index)), header.TCPFlagSyn)
		}
	}()
	wait.Wait()

	// Every remaining mapping must be indexed both ways exactly once; a double delete or a
	// resurrection shows up as a count mismatch.
	nat.portAccess.RLock()
	portCount := len(nat.portMap)
	portSnapshot := make(map[uint16]tcpNatKey, portCount)
	for port, session := range nat.portMap {
		session.Lock()
		portSnapshot[port] = tcpNatKey{Source: session.Source, Destination: session.Destination}
		session.Unlock()
	}
	nat.portAccess.RUnlock()
	nat.addrAccess.RLock()
	addrCount := len(nat.addrMap)
	for key, port := range nat.addrMap {
		if mapped, loaded := portSnapshot[port]; !loaded || mapped != key {
			nat.addrAccess.RUnlock()
			t.Fatalf("addrMap[%v] = %d has no matching session", key, port)
		}
	}
	nat.addrAccess.RUnlock()
	if portCount != addrCount {
		t.Fatalf("portMap has %d entries but addrMap has %d", portCount, addrCount)
	}
}
