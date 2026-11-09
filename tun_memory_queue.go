package tun

import (
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
)

type OutboundQueue struct {
	tun        *MemoryTun
	handler    func(packets []*buf.Buffer)
	access     sync.Mutex
	control    goPacketRing
	datagram   goPacketRing
	data       goPacketRing
	dataTurn   bool
	dataQueued atomic.Int32
	// queuedBytes is what this queue holds of the device byte budget (see
	// MemoryTun.maxQueuedBytes). It is under access like the rings it describes.
	queuedBytes      int64
	transmitInterest bool
	writableQueued   bool
	closed           atomic.Bool
	readerWake       goSignal
	closeSignal      chan struct{}
}

func (t *MemoryTun) NewOutboundQueue(handler func(packets []*buf.Buffer)) *OutboundQueue {
	queue := &OutboundQueue{
		tun:         t,
		handler:     handler,
		control:     newGoPacketRing(2 * t.batchSize),
		datagram:    newGoPacketRing(2 * t.batchSize),
		data:        newGoPacketRing(2 * t.batchSize),
		readerWake:  make(goSignal, 1),
		closeSignal: make(chan struct{}),
	}
	go queue.loopHandle()
	return queue
}

func (q *OutboundQueue) WriteBuffers(buffers []*buf.Buffer) {
	q.access.Lock()
	if q.closed.Load() || q.tun.closed.Load() {
		q.access.Unlock()
		buf.ReleaseMulti(buffers)
		return
	}
	wasEmpty := q.emptyLocked()
	for _, buffer := range buffers {
		if buffer.IsEmpty() || q.datagram.full() || !q.reserveBytesLocked(buffer) {
			buffer.Release()
			continue
		}
		q.pushLocked(&q.datagram, buffer, nil, 0)
	}
	notify := wasEmpty && !q.emptyLocked()
	q.access.Unlock()
	if notify {
		q.readerWake.notify()
	}
}

func (q *OutboundQueue) Close() error {
	q.access.Lock()
	if q.closed.Swap(true) {
		q.access.Unlock()
		return nil
	}
	q.releaseRingLocked(&q.control)
	q.releaseRingLocked(&q.datagram)
	q.releaseRingLocked(&q.data)
	q.dataQueued.Store(0)
	q.queuedBytes = 0
	q.transmitInterest = false
	q.access.Unlock()
	close(q.closeSignal)
	q.tun.queueWritable(q)
	return nil
}

func (q *OutboundQueue) loopHandle() {
	packets := make([]*buf.Buffer, q.tun.batchSize)
	for {
		count := q.drain(packets)
		if count > 0 {
			q.handler(packets[:count])
			clear(packets[:count])
			continue
		}
		select {
		case <-q.readerWake:
		case <-q.closeSignal:
			return
		}
	}
}

func (q *OutboundQueue) drain(buffers []*buf.Buffer) int {
	q.access.Lock()
	count := 0
	for count < len(buffers) {
		buffer, owner, segmentEnd := q.popLocked()
		if buffer == nil {
			break
		}
		if owner != nil {
			owner.frameDequeued(buffer.Len(), segmentEnd)
		}
		buffers[count] = buffer
		count++
	}
	writable := q.transmitInterest && !q.data.full()
	if writable {
		q.transmitInterest = false
	}
	q.access.Unlock()
	if writable {
		q.tun.queueWritable(q)
	}
	return count
}

func (q *OutboundQueue) emptyLocked() bool {
	return q.control.empty() && q.datagram.empty() && q.data.empty()
}

func (q *OutboundQueue) popLocked() (*buf.Buffer, *GoConn, uint64) {
	if !q.control.empty() {
		packet, owner, segmentEnd := q.control.pop()
		q.releaseBytesLocked(int64(packet.Cap()))
		return packet, owner, segmentEnd
	}
	if !q.datagram.empty() && (q.data.empty() || !q.dataTurn) {
		q.dataTurn = true
		packet, owner, segmentEnd := q.datagram.pop()
		q.releaseBytesLocked(int64(packet.Cap()))
		return packet, owner, segmentEnd
	}
	if !q.data.empty() {
		q.dataTurn = false
		q.dataQueued.Add(-1)
		packet, owner, segmentEnd := q.data.pop()
		q.releaseBytesLocked(int64(packet.Cap()))
		return packet, owner, segmentEnd
	}
	return nil, nil, 0
}

func (q *OutboundQueue) enqueue(packet *buf.Buffer, fragments [][]byte, class goOutboundClass, owner *GoConn, segmentEnd uint64) error {
	q.access.Lock()
	ring := &q.control
	switch class {
	case goOutboundDatagram:
		ring = &q.datagram
	case goOutboundData:
		ring = &q.data
	}
	var err error
	switch {
	case q.closed.Load() || q.tun.closed.Load():
		// The device is gone: a caller-owned queue stops admitting NEW datagrams, while
		// what it already holds stays its own to release (see OutboundQueue.Close).
		err = errGoFrameDropped
	case ring.full() && class == goOutboundData:
		err = errGoTransmitBlocked
	case ring.capacity-ring.count < max(len(fragments), 1):
		err = errGoFrameDropped
	}
	if err == nil && fragments == nil && !q.reserveBytesLocked(packet) {
		if class == goOutboundData {
			// A TCP segment blocked only by the device byte budget is backpressure, not a
			// drop: the writer must be armed and retried when the queue drains or the
			// reader frees the budget. UDP keeps the drop policy.
			q.transmitInterest = true
			err = errGoTransmitBlocked
		} else {
			err = errGoFrameDropped
		}
	}
	if err == nil && fragments != nil {
		// Reserve the whole frame group before allocating any of it: a partial group
		// would hand the caller a "dropped" error while some fragments were queued.
		var fragmentsBytes int64
		for _, fragment := range fragments {
			fragmentsBytes += int64(q.tun.headroom + len(fragment) + q.tun.rearSpace)
		}
		if !q.reserveBytesExactLocked(fragmentsBytes) {
			if class == goOutboundData {
				q.transmitInterest = true
				err = errGoTransmitBlocked
			} else {
				err = errGoFrameDropped
			}
		}
	}
	if err != nil {
		q.access.Unlock()
		packet.Release()
		return err
	}
	wasEmpty := q.emptyLocked()
	if fragments == nil {
		q.pushLocked(ring, packet, owner, segmentEnd)
	} else {
		for _, fragment := range fragments {
			fragmentPacket := q.tun.newOutboundPacket(len(fragment))
			common.Must1(fragmentPacket.Write(fragment))
			q.pushLocked(ring, fragmentPacket, owner, segmentEnd)
		}
		packet.Release()
	}
	q.access.Unlock()
	if wasEmpty {
		q.readerWake.notify()
	}
	return nil
}

// reserveBytesLocked reserves the packet's capacity against the device byte budget.
// Caller holds q.access.
func (q *OutboundQueue) reserveBytesLocked(packet *buf.Buffer) bool {
	return q.reserveBytesExactLocked(int64(packet.Cap()))
}

// reserveBytesExactLocked reserves n bytes against the device byte budget and this
// queue's share. Caller holds q.access.
func (q *OutboundQueue) reserveBytesExactLocked(n int64) bool {
	if n <= 0 {
		return true
	}
	if !q.tun.reserveQueuedBytes(n) {
		return false
	}
	q.queuedBytes += n
	return true
}

// releaseBytesLocked returns a packet's capacity to the device byte budget and this
// queue's share. Caller holds q.access.
func (q *OutboundQueue) releaseBytesLocked(n int64) {
	if n <= 0 {
		return
	}
	q.queuedBytes -= n
	if q.queuedBytes < 0 {
		q.queuedBytes = 0
	}
	q.tun.releaseQueuedBytes(n)
}

// QueuedBytes reports the bytes this queue currently holds.
func (q *OutboundQueue) QueuedBytes() int {
	q.access.Lock()
	defer q.access.Unlock()
	return int(q.queuedBytes)
}

func (q *OutboundQueue) pushLocked(ring *goPacketRing, packet *buf.Buffer, owner *GoConn, segmentEnd uint64) {
	if owner != nil {
		owner.frameEnqueued(packet.Len())
	}
	if ring == &q.data {
		q.dataQueued.Add(1)
	}
	ring.push(packet, owner, segmentEnd)
}

const goPacketRingInitialSize = 16

type goPacketRing struct {
	entries  []goPacketEntry
	capacity int
	head     int
	count    int
}

type goPacketEntry struct {
	packet     *buf.Buffer
	owner      *GoConn
	segmentEnd uint64
}

func newGoPacketRing(capacity int) goPacketRing {
	return goPacketRing{capacity: capacity}
}

func (r *goPacketRing) empty() bool {
	return r.count == 0
}

func (r *goPacketRing) full() bool {
	return r.count == r.capacity
}

func (r *goPacketRing) push(packet *buf.Buffer, owner *GoConn, segmentEnd uint64) {
	if r.count == len(r.entries) {
		entries := make([]goPacketEntry, min(max(2*len(r.entries), goPacketRingInitialSize), r.capacity))
		copied := copy(entries, r.entries[r.head:])
		copy(entries[copied:], r.entries[:r.head])
		r.entries = entries
		r.head = 0
	}
	r.entries[(r.head+r.count)%len(r.entries)] = goPacketEntry{packet: packet, owner: owner, segmentEnd: segmentEnd}
	r.count++
}

func (r *goPacketRing) pop() (*buf.Buffer, *GoConn, uint64) {
	entry := r.entries[r.head]
	r.entries[r.head] = goPacketEntry{}
	r.head = (r.head + 1) % len(r.entries)
	r.count--
	return entry.packet, entry.owner, entry.segmentEnd
}

// releaseRingLocked drops a ring's packets and returns their byte reservation, so a
// closed queue leaves no charge on the device budget. Caller holds q.access.
func (q *OutboundQueue) releaseRingLocked(ring *goPacketRing) {
	for !ring.empty() {
		packet, owner, segmentEnd := ring.pop()
		if owner != nil {
			owner.frameDequeued(packet.Len(), segmentEnd)
		}
		q.releaseBytesLocked(int64(packet.Cap()))
		packet.Release()
	}
}

func (r *goPacketRing) releaseAll() {
	for !r.empty() {
		packet, owner, segmentEnd := r.pop()
		if owner != nil {
			owner.frameDequeued(packet.Len(), segmentEnd)
		}
		packet.Release()
	}
}
