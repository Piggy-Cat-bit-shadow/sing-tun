package tun

import (
	"os"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

type goMemoryIO struct {
	stack         *Go
	tun           *MemoryTun
	timer         *time.Timer
	handed        []*buf.Buffer
	blocked       map[*OutboundQueue]*goBlockedWriters
	writableSpare []*OutboundQueue
}

func (o *goMemoryIO) start() error {
	o.tun.attached.Store(true)
	return nil
}

func (o *goMemoryIO) inboundReady() (bool, error) {
	if o.tun.closed.Load() {
		return false, os.ErrClosed
	}
	o.tun.inboundAccess.Lock()
	defer o.tun.inboundAccess.Unlock()
	return !o.tun.inbound.empty(), nil
}

func (o *goMemoryIO) wait(timeout time.Duration, events []goSocketEvent) (bool, int, error) {
	ready, err := o.inboundReady()
	if ready || err != nil || timeout == 0 {
		return ready, 0, err
	}
	if timeout < 0 {
		select {
		case <-o.tun.engineWake:
		case <-o.tun.closeSignal:
		}
	} else {
		if o.timer == nil {
			o.timer = time.NewTimer(timeout)
		} else {
			o.timer.Reset(timeout)
		}
		select {
		case <-o.tun.engineWake:
			o.timer.Stop()
		case <-o.tun.closeSignal:
			o.timer.Stop()
		case <-o.timer.C:
		}
	}
	ready, err = o.inboundReady()
	return ready, 0, err
}

func (o *goMemoryIO) registerSocket(socket *goSocket, token uint32, interest uint8) error {
	return nil
}

func (o *goMemoryIO) updateSocket(socket *goSocket, interest uint8) error {
	return nil
}

func (o *goMemoryIO) unregisterSocket(socket *goSocket) {
}

func (o *goMemoryIO) readBurst(frames []goFrame, options N.ReadWaitOptions) (int, bool, error) {
	o.releaseReadBuffers()
	if o.tun.closed.Load() {
		return 0, false, os.ErrClosed
	}
	o.tun.inboundHeadroom.Store(int32(options.FrontHeadroom))
	o.tun.inboundRearSpace.Store(int32(options.RearHeadroom))
	o.tun.inboundAccess.Lock()
	count := 0
	for count < len(frames) && !o.tun.inbound.empty() {
		buffer, _, _ := o.tun.inbound.pop()
		// The frame's bytes leave the device queue here, whether the buffer is handed to
		// the caller or copied out: the reservation made by writePackets is returned so the
		// device byte budget tracks what is still queued.
		o.tun.releaseQueuedBytesLocked(int64(buffer.Cap()))
		if options.NeedHeadroom() {
			buffer = options.Copy(buffer)
			options.PostReturn(buffer)
		}
		o.handed = append(o.handed, buffer)
		frames[count] = goFrame{buffer: buffer}
		count++
	}
	remainEmpty := o.tun.inbound.empty()
	if count > 0 {
		// Broadcast, not Signal: byte-budget waiters must also see the release.
		o.tun.inboundWritable.Broadcast()
	}
	o.tun.inboundAccess.Unlock()
	if count > 0 {
		// The frames just left the device queue, so the shared byte budget has room: a data
		// writer parked on it in an outbound queue may now proceed. (Called after the
		// inbound lock is released: the notification takes the queue lock, and the queue
		// path takes the inbound lock, so the order is always inbound -> queue.)
		o.tun.notifyOutboundByteWaiters()
	}
	return count, remainEmpty, nil
}

func (o *goMemoryIO) releaseReadBuffers() {
	buf.ReleaseMulti(o.handed)
	o.handed = o.handed[:0]
}

type goOutboundClass uint8

const (
	goOutboundControl goOutboundClass = iota
	goOutboundDatagram
	goOutboundData
)

func (o *goMemoryIO) enqueue(segments [][]byte, class goOutboundClass, owner *GoConn, segmentEnd uint64) error {
	if o.tun.closed.Load() || !o.tun.attached.Load() {
		return os.ErrClosed
	}
	length := 0
	for _, segment := range segments {
		length += len(segment)
	}
	packet := o.tun.newOutboundPacket(length)
	for _, segment := range segments {
		common.Must1(packet.Write(segment))
	}
	queue := o.tun.outbound
	if o.tun.route != nil {
		routed := o.tun.route(packet.Bytes())
		if routed != nil {
			queue = routed
		}
	}
	if owner != nil {
		owner.outboundQueue.Store(queue)
	}
	var fragments [][]byte
	mtu := o.tun.MTU()
	if length > mtu {
		var fragmentsBuilt bool
		fragments, fragmentsBuilt = goFragmentPacket(&o.stack.fragmentIdentification, packet.Bytes(), mtu)
		if !fragmentsBuilt {
			packet.Release()
			return errGoFrameDropped
		}
	}
	return queue.enqueue(packet, fragments, class, owner, segmentEnd)
}

func (o *goMemoryIO) writeFrame(frame [][]byte, meta ForwardFrameMeta) error {
	return o.enqueue(frame, goOutboundControl, nil, 0)
}

func (o *goMemoryIO) writePacket(packet []byte, meta ForwardFrameMeta) error {
	segments := [1][]byte{packet}
	return o.enqueue(segments[:], goOutboundControl, nil, 0)
}

func (o *goMemoryIO) writeDatagram(packet []byte, meta ForwardFrameMeta) error {
	segments := [1][]byte{packet}
	return o.enqueue(segments[:], goOutboundDatagram, nil, 0)
}

func (o *goMemoryIO) writeData(frame [][]byte, meta ForwardFrameMeta, owner *GoConn, segmentEnd uint64) error {
	return o.enqueue(frame, goOutboundData, owner, segmentEnd)
}

func (o *goMemoryIO) writePacketBatch(frames []goUDPFrame) error {
	var writeErr error
	for index := range frames {
		frame := &frames[index]
		segments := [2][]byte{frame.header[:frame.length], frame.payload}
		writeErr = E.Errors(writeErr, o.enqueue(segments[:], goOutboundDatagram, nil, 0))
	}
	return writeErr
}

func (o *goMemoryIO) transmitBacklogBelowBatch(conn *GoConn) bool {
	queue := conn.outboundQueue.Load()
	if queue == nil {
		queue = o.tun.outbound
	}
	return int(queue.dataQueued.Load()) < o.tun.batchSize
}

func (o *goMemoryIO) flush() {
}

func (o *goMemoryIO) mtu() int {
	return o.tun.MTU()
}

func (o *goMemoryIO) supportsSockets() bool {
	return false
}

func (o *goMemoryIO) transmitPrefix() int {
	return 0
}

func (o *goMemoryIO) transmitChecksumOffload() bool {
	return false
}

func (o *goMemoryIO) transmitSegmentOffload() bool {
	return false
}

func (o *goMemoryIO) armTransmitWritable(conn *GoConn) (*goBlockedWriters, error) {
	queue := o.tun.outbound
	if conn != nil {
		routed := conn.outboundQueue.Load()
		if routed != nil {
			queue = routed
		}
	}
	queue.access.Lock()
	// The packet ring OR the device byte budget can be what blocks a data write; both arm
	// the writer, and both are retried when the queue drains or the budget is released.
	// byteBlocked covers the case where a release consumed the interest between the failed
	// reservation and this arm: the writer is still blocked even though interest is false.
	armed := !queue.closed.Load() && (queue.data.full() || queue.transmitInterest.Load() || queue.byteBlocked.Load() > 0)
	if armed {
		queue.transmitInterest.Store(true)
	}
	queue.access.Unlock()
	if !armed {
		return nil, nil
	}
	waiters := o.blocked[queue]
	if waiters == nil {
		waiters = new(goBlockedWriters)
		o.blocked[queue] = waiters
	}
	// Re-observe the budget AFTER publishing the interest and registering the group: a
	// release that happened inside that window queued the queue before this group existed,
	// so it must be re-queued now that the group can be delivered. The size check keeps a
	// partial release from spinning the writer.
	if needed := queue.byteBlocked.Load(); needed > 0 && !queue.data.full() && o.tun.hasQueuedByteRoom(needed) {
		o.tun.queueWritable(queue)
	}
	return waiters, nil
}

func (o *goMemoryIO) takeTransmitWritable(writable []*goBlockedWriters) []*goBlockedWriters {
	queues := o.tun.takeWritable(o.writableSpare)
	for _, queue := range queues {
		waiters := o.blocked[queue]
		if waiters == nil {
			continue
		}
		if queue.closed.Load() {
			delete(o.blocked, queue)
		}
		writable = append(writable, waiters)
	}
	clear(queues)
	o.writableSpare = queues[:0]
	return writable
}

func (o *goMemoryIO) wake() {
	o.tun.engineWake.notify()
}

func (o *goMemoryIO) close() error {
	o.releaseReadBuffers()
	o.tun.attached.Store(false)
	o.tun.inboundAccess.Lock()
	// The detach empties the inbound ring: every frame still queued has to return its
	// device byte reservation, exactly like the normal read and the device Close do.
	// releaseAll alone popped the frames and released only the buffers, so the quota
	// outlived the stack: the next attach was refused and the device Close kept a residue.
	for !o.tun.inbound.empty() {
		frame, _, _ := o.tun.inbound.pop()
		o.tun.releaseQueuedBytesLocked(int64(frame.Cap()))
		frame.Release()
	}
	o.tun.inboundWritable.Broadcast()
	o.tun.inboundAccess.Unlock()
	// The drained frames return device bytes, so a data writer parked on the shared
	// budget in any outbound queue must be handed to the engine as well.
	o.tun.notifyOutboundByteWaiters()
	if o.timer != nil {
		o.timer.Stop()
	}
	clear(o.blocked)
	return nil
}
