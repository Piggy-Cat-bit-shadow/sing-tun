package tun

import (
	"errors"
	"sync"
	"testing"
)

// Go stack only. The gVisor writer is retired and is not touched here.
//
// GoPacketConn.snapshot is the clones of the flow's FIRST datagram, kept so a failed handshake can
// answer the client with ICMP unreachable. It is a heap []byte (slices.Clone), not a reference-counted
// buffer, so "release" means dropping the last reference. These tests pin that every ending drops it:
// handshake success, handshake failure, and Close. The Close case is the one that previously relied on
// the conn becoming unreachable.
func TestGoPacketConnSnapshotReleasedOnEveryEnding(t *testing.T) {
	t.Run("handshake success", func(t *testing.T) {
		conn := &GoPacketConn{snapshot: []byte{0x45, 0, 0, 20}}
		if err := conn.HandshakeSuccess(); err != nil {
			t.Fatalf("HandshakeSuccess: %v", err)
		}
		if len(conn.snapshot) != 0 {
			t.Fatalf("snapshot retained after handshake success: %d bytes", len(conn.snapshot))
		}
		// Idempotent: a second report is not an error and still holds nothing.
		if err := conn.HandshakeSuccess(); err != nil {
			t.Fatalf("second HandshakeSuccess: %v", err)
		}
		if len(conn.snapshot) != 0 {
			t.Fatalf("snapshot retained after second success")
		}
	})

	t.Run("handshake failure", func(t *testing.T) {
		// An invalid IP packet makes BuildICMPError decline, so the reply path is not taken; the
		// property under test is the release, not the reply.
		conn := &GoPacketConn{snapshot: []byte{0x45}}
		if err := conn.HandshakeFailure(errors.New("test failure")); err != nil {
			t.Fatalf("HandshakeFailure: %v", err)
		}
		if len(conn.snapshot) != 0 {
			t.Fatalf("snapshot retained after handshake failure: %d bytes", len(conn.snapshot))
		}
	})

	t.Run("close", func(t *testing.T) {
		conn := &GoPacketConn{
			engine:   &goEngine{stack: &Go{}},
			snapshot: []byte{0x45, 0, 0, 20},
		}
		if err := conn.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if len(conn.snapshot) != 0 {
			t.Fatalf("snapshot retained after Close: %d bytes", len(conn.snapshot))
		}
		if err := conn.Close(); err != nil {
			t.Fatalf("second Close: %v", err)
		}
	})
}

// The three endings can arrive concurrently (the handshake callback races a tunnel teardown). The
// snapshot lock is what keeps the clear from being lost; run under -race this also proves no data
// race on the slice field.
func TestGoPacketConnSnapshotCloseRacesHandshake(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		conn := &GoPacketConn{
			engine:   &goEngine{stack: &Go{}},
			snapshot: []byte{0x45, 0, 0, 20},
		}
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			_ = conn.Close()
		}()
		go func() {
			defer wait.Done()
			_ = conn.HandshakeSuccess()
		}()
		wait.Wait()
		if len(conn.snapshot) != 0 {
			t.Fatalf("iteration %d: snapshot retained after concurrent Close and handshake success", iteration)
		}
	}
}
