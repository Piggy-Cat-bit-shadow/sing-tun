package tun

// UDPNatStats is the read-only view of one UDP NAT instance.
//
// # What these numbers are and are not
//
// Entries is the number of live logical UDP flows in the NAT table; SessionsCreated is cumulative.
// QueuedBytes is what those flows currently hold in their per-session queues, bounded by the NAT-wide
// MaxQueuedBytes and by MaxBytesPerSession. DroppedPackets is process-wide (the existing counter on
// the drop path), not per-NAT.
//
// This is the LOGICAL-FLOW layer. One entry is one flow the tunnel is tracking; it is NOT one socket,
// one TLS session or one QUIC stream. Those are counted by their owners in the physical and
// steady-state layers, and the separation is deliberate: the same 1000 entries can map to 1 session
// (AnyTLS coalescing) or 1000 (plain per-flow TLS).
type UDPNatStats struct {
	Entries            int
	MaxEntries         int
	SessionsCreated    uint64
	QueuedBytes        int64
	MaxQueuedBytes     int64
	MaxBytesPerSession int
	DroppedPackets     uint64
}

// Stats reads the NAT's counters. Entries comes from the cache's own length (the same structure the
// datapath consults); the rest are atomics, so the snapshot is cheap but not a single linearizable
// instant across all seven values. Treat it as a diagnostic sample, not as a transaction.
func (s *UDPNat) Stats() UDPNatStats {
	if s == nil {
		return UDPNatStats{}
	}
	return UDPNatStats{
		Entries:            s.cache.Len(),
		MaxEntries:         s.maxSize,
		SessionsCreated:    s.sessionsCreated.Load(),
		QueuedBytes:        s.queuedBytes.Load(),
		MaxQueuedBytes:     s.maxQueuedBytes,
		MaxBytesPerSession: s.maxBytesPerSession,
		DroppedPackets:     udpNatDroppedPackets.Load(),
	}
}
