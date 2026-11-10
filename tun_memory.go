package tun

import (
	"errors"
	"os"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing/common/buf"
)

const (
	memoryTunDefaultBatchSize = 128
	memoryTunMaxPacketSize    = 65535
)

type MemoryTunOptions struct {
	MTU       int
	Headroom  int
	RearSpace int
	BatchSize int
	// MaxQueuedBytes caps the bytes the device has queued across its inbound ring and
	// every outbound queue (the packet counts alone allow 4 x batch x 64 KiB, which is
	// tens of MiB for one device). Zero selects DefaultMemoryTunMaxQueuedBytes.
	MaxQueuedBytes int
	Outbound       func(packets []*buf.Buffer)
	Route          func(packet []byte) *OutboundQueue
}

// DefaultMemoryTunMaxQueuedBytes is the device-wide queued-byte budget: the packet-count
// rings stay as they are (they bound latency and the ring structure), this bounds the
// memory those packets represent. 8 MiB is a few thousand MTU-sized packets, far above a
// normal burst and far below what the packet counts alone permit.
const DefaultMemoryTunMaxQueuedBytes = 8 << 20

// packetWriteHook is a test seam for the room-check/reservation window: tests set it to
// take a competing reservation between the check and the CAS, which is the interleaving the
// blocking write must tolerate.
var packetWriteHook func()

// errFrameExceedsByteBudget is the defined result for a blocking write whose single frame
// can never fit the device byte budget: parking would never make room, so the writer is
// told instead.
var errFrameExceedsByteBudget = errors.New("tun: frame exceeds the device byte budget")

type MemoryTun struct {
	mtu              atomic.Int32
	headroom         int
	rearSpace        int
	batchSize        int
	route            func(packet []byte) *OutboundQueue
	maxQueuedBytes   int64
	queuedBytes      atomic.Int64
	attached         atomic.Bool
	closed           atomic.Bool
	inboundAccess    sync.Mutex
	inbound          goPacketRing
	inboundWritable  *sync.Cond
	inboundHeadroom  atomic.Int32
	inboundRearSpace atomic.Int32
	outbound         *OutboundQueue
	// queues is the device registry of every outbound queue (the default one and the
	// caller-owned ones): the byte budget is shared, so any release may have to wake a
	// waiter parked in a DIFFERENT queue.
	queuesAccess    sync.Mutex
	queues          map[*OutboundQueue]struct{}
	writableAccess  sync.Mutex
	writable        []*OutboundQueue
	writablePending atomic.Bool
	engineWake      goSignal
	closeSignal     chan struct{}
}

func NewMemoryTun(options MemoryTunOptions) *MemoryTun {
	batchSize := options.BatchSize
	if batchSize <= 0 {
		batchSize = memoryTunDefaultBatchSize
	}
	memoryTun := &MemoryTun{
		headroom:    options.Headroom,
		rearSpace:   options.RearSpace,
		batchSize:   batchSize,
		route:       options.Route,
		inbound:     newGoPacketRing(4 * batchSize),
		engineWake:  make(goSignal, 1),
		closeSignal: make(chan struct{}),
	}
	outboundHandler := options.Outbound
	if outboundHandler == nil {
		outboundHandler = buf.ReleaseMulti
	}
	memoryTun.inboundWritable = sync.NewCond(&memoryTun.inboundAccess)
	memoryTun.queues = make(map[*OutboundQueue]struct{})
	maxQueuedBytes := options.MaxQueuedBytes
	if maxQueuedBytes <= 0 {
		maxQueuedBytes = DefaultMemoryTunMaxQueuedBytes
	}
	memoryTun.maxQueuedBytes = int64(maxQueuedBytes)
	memoryTun.outbound = memoryTun.NewOutboundQueue(outboundHandler)
	memoryTun.mtu.Store(int32(options.MTU))
	return memoryTun
}

func (t *MemoryTun) Name() (string, error) {
	return "memory", nil
}

func (t *MemoryTun) Start() error {
	return nil
}

func (t *MemoryTun) UpdateRouteOptions(tunOptions Options) error {
	return nil
}

func (t *MemoryTun) MTU() int {
	return int(t.mtu.Load())
}

func (t *MemoryTun) UpdateMTU(mtu int) {
	t.mtu.Store(int32(mtu))
}

func (t *MemoryTun) Read(p []byte) (int, error) {
	return 0, os.ErrInvalid
}

func (t *MemoryTun) Write(p []byte) (int, error) {
	packets := [1][]byte{p}
	_, err := t.WritePackets(packets[:])
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (t *MemoryTun) WritePackets(packets [][]byte) (int, error) {
	return t.writePackets(packets, false)
}

func (t *MemoryTun) WaitWritePackets(packets [][]byte) error {
	_, err := t.writePackets(packets, true)
	return err
}

func (t *MemoryTun) writePackets(packets [][]byte, wait bool) (int, error) {
	t.inboundAccess.Lock()
	if t.closed.Load() {
		t.inboundAccess.Unlock()
		return 0, os.ErrClosed
	}
	if !t.attached.Load() {
		t.inboundAccess.Unlock()
		return 0, nil
	}
	headroom := int(t.inboundHeadroom.Load())
	rearSpace := int(t.inboundRearSpace.Load())
	accepted := 0
	notify := false
	for _, packet := range packets {
		if len(packet) == 0 || len(packet) > memoryTunMaxPacketSize {
			continue
		}
		var frameBytes int64
		if wait {
			// Park while either the packet ring or the device byte budget has no room,
			// and RESERVE inside the loop: the room check and the CAS are not atomic with
			// each other, so another queue can take the room in between. Skipping the
			// frame there would lose a blocking write silently; the loop simply parks and
			// retries instead.
			for {
				if t.closed.Load() {
					t.inboundAccess.Unlock()
					return accepted, os.ErrClosed
				}
				if !t.attached.Load() {
					t.inboundAccess.Unlock()
					return accepted, nil
				}
				headroom = int(t.inboundHeadroom.Load())
				rearSpace = int(t.inboundRearSpace.Load())
				frameBytes = int64(headroom + len(packet) + rearSpace)
				if frameBytes > t.maxQueuedBytes {
					// No release can ever fit this frame: parking would wait forever.
					t.inboundAccess.Unlock()
					return accepted, errFrameExceedsByteBudget
				}
				if !t.inbound.full() && t.hasQueuedByteRoom(frameBytes) {
					if packetWriteHook != nil {
						packetWriteHook()
					}
					if t.reserveQueuedBytes(frameBytes) {
						break
					}
				}
				if notify {
					notify = false
					t.engineWake.notify()
				}
				t.inboundWritable.Wait()
			}
		} else {
			if t.inbound.full() {
				continue
			}
			headroom = int(t.inboundHeadroom.Load())
			rearSpace = int(t.inboundRearSpace.Load())
			frameBytes = int64(headroom + len(packet) + rearSpace)
			if packetWriteHook != nil {
				packetWriteHook()
			}
			if !t.reserveQueuedBytes(frameBytes) {
				continue
			}
		}
		if t.inbound.empty() {
			notify = true
		}
		buffer := buf.NewSize(int(frameBytes))
		buffer.Resize(headroom, 0)
		buffer.Write(packet)
		t.inbound.push(buffer, nil, 0)
		accepted++
	}
	t.inboundAccess.Unlock()
	if notify {
		t.engineWake.notify()
	}
	return accepted, nil
}

func (t *MemoryTun) Close() error {
	if t.closed.Swap(true) {
		return nil
	}
	t.inboundAccess.Lock()
	for !t.inbound.empty() {
		frame, _, _ := t.inbound.pop()
		t.releaseQueuedBytesLocked(int64(frame.Cap()))
		frame.Release()
	}
	t.inboundWritable.Broadcast()
	t.inboundAccess.Unlock()
	// The default queue is the device's own: closing it releases its rings. Caller-owned
	// queues are closed by their owners; until they are, their datagrams still exist and
	// the device total must keep saying so instead of pretending the memory was returned.
	t.outbound.Close()
	close(t.closeSignal)
	return nil
}

func (t *MemoryTun) queueWritable(queue *OutboundQueue) {
	t.writableAccess.Lock()
	if queue.writableQueued {
		t.writableAccess.Unlock()
		return
	}
	queue.writableQueued = true
	t.writable = append(t.writable, queue)
	t.writablePending.Store(true)
	t.writableAccess.Unlock()
	t.engineWake.notify()
}

func (t *MemoryTun) takeWritable(spare []*OutboundQueue) []*OutboundQueue {
	if !t.writablePending.Swap(false) {
		return spare
	}
	t.writableAccess.Lock()
	queues := t.writable
	t.writable = spare
	for _, queue := range queues {
		queue.writableQueued = false
	}
	t.writableAccess.Unlock()
	return queues
}

// reserveQueuedBytes adds n to the device-wide queue budget, or reports false when the
// budget would be exceeded. The CAS loop makes the cap a hard bound on the writer path
// without taking the ring lock for the accounting.
func (t *MemoryTun) reserveQueuedBytes(n int64) bool {
	if n <= 0 {
		return true
	}
	for {
		current := t.queuedBytes.Load()
		if current+n > t.maxQueuedBytes {
			return false
		}
		if t.queuedBytes.CompareAndSwap(current, current+n) {
			return true
		}
	}
}

// hasQueuedByteRoom reports whether n more bytes fit without reserving them.
func (t *MemoryTun) hasQueuedByteRoom(n int64) bool {
	if n <= 0 {
		return true
	}
	return t.queuedBytes.Load()+n <= t.maxQueuedBytes
}

// releaseQueuedBytes returns n to the device-wide budget and wakes the writers parked on
// it. The notification is what connects an OUTBOUND queue's release to an INBOUND waiter:
// both draw from the same device budget, and a waiter that only ever hears about its own
// ring's space would sleep until Close.
func (t *MemoryTun) releaseQueuedBytes(n int64) {
	if n <= 0 {
		return
	}
	t.releaseQueuedBytesLocked(n)
	t.notifyByteWaiters()
	// The same release may unblock a data writer parked in ANY outbound queue: the budget
	// is one device-wide number, so the wake cannot be scoped to the releasing queue.
	t.notifyOutboundByteWaiters()
}

// releaseQueuedBytesLocked returns n to the device-wide budget without notifying. Callers
// that already hold inboundAccess (the read path, the Close drain) broadcast themselves.
func (t *MemoryTun) releaseQueuedBytesLocked(n int64) {
	if n <= 0 {
		return
	}
	for {
		current := t.queuedBytes.Load()
		next := current - n
		if next < 0 {
			next = 0
		}
		if t.queuedBytes.CompareAndSwap(current, next) {
			return
		}
	}
}

// notifyOutboundByteWaiters hands a byte-blocked outbound queue to the engine. Every
// registered queue is considered, because the released bytes belong to the device and any
// queue may have been the one waiting for them. The size check uses the queue's recorded
// blocked frame: a partial release that cannot fit a blocked frame must leave the queue
// armed (the next release re-checks) instead of waking it into another refusal.
// Callers must not hold the inbound lock or the queue lock (see readBurst).
func (t *MemoryTun) notifyOutboundByteWaiters() {
	t.queuesAccess.Lock()
	queues := make([]*OutboundQueue, 0, len(t.queues))
	for queue := range t.queues {
		queues = append(queues, queue)
	}
	t.queuesAccess.Unlock()
	for _, queue := range queues {
		if queue.closed.Load() {
			continue
		}
		needed := queue.byteBlocked.Load()
		if needed <= 0 {
			needed = 1
		}
		if !t.hasQueuedByteRoom(needed) {
			continue
		}
		// transmitInterest is atomic precisely so this cross-queue notification does not
		// take another queue's access lock (release paths hold their own queue's lock).
		if queue.transmitInterest.CompareAndSwap(true, false) {
			t.queueWritable(queue)
		}
	}
}

// notifyByteWaiters wakes writers parked on the device byte budget. The broadcast happens
// under inboundAccess, the same mutex the waiters check their condition under, so a
// release cannot land between a waiter's check and its Wait.
func (t *MemoryTun) notifyByteWaiters() {
	t.inboundAccess.Lock()
	t.inboundWritable.Broadcast()
	t.inboundAccess.Unlock()
}

// QueuedBytes reports the bytes this device currently has queued (inbound ring plus all
// outbound queues).
func (t *MemoryTun) QueuedBytes() int {
	return int(t.queuedBytes.Load())
}

// MaxQueuedBytes reports the device-wide byte cap.
func (t *MemoryTun) MaxQueuedBytes() int {
	return int(t.maxQueuedBytes)
}

func (t *MemoryTun) newOutboundPacket(length int) *buf.Buffer {
	packet := buf.NewSize(t.headroom + length + t.rearSpace)
	packet.Resize(t.headroom, 0)
	return packet
}
