//go:build linux && !android

package tun

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

func TestGoKernelWindowClamp(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	cases := []struct {
		window int
		mss    int
		loss   bool
	}{
		{window: 2048},
		{window: 4096, mss: 512},
		{window: 16384, loss: true},
	}
	for _, scenario := range cases {
		t.Run(fmt.Sprintf("window=%d/mss=%d/loss=%v", scenario.window, scenario.mss, scenario.loss), func(configTest *testing.T) {
			size := 256 << 10
			config := kernelStackConfig{mtu: 9000, socketBuffer: 4096, upstreamSocketBuffer: 4096, gso: scenario.loss, multiQueue: scenario.loss}
			config.dialer = net.Dialer{Control: func(_, _ string, rawConn syscall.RawConn) error {
				var optionErr error
				err := rawConn.Control(func(descriptor uintptr) {
					optionErr = unix.SetsockoptInt(int(descriptor), unix.SOL_SOCKET, unix.SO_RCVBUF, 4096)
					if optionErr != nil {
						return
					}
					optionErr = unix.SetsockoptInt(int(descriptor), unix.IPPROTO_TCP, unix.TCP_WINDOW_CLAMP, scenario.window)
					if optionErr != nil || scenario.mss == 0 {
						return
					}
					optionErr = unix.SetsockoptInt(int(descriptor), unix.IPPROTO_TCP, unix.TCP_MAXSEG, scenario.mss)
				})
				return E.Errors(err, optionErr)
			}}
			if scenario.loss {
				size = 1 << 20
				config.upstreamSocketBuffer = 64 << 10
				config.configure = func(test *testing.T, options Options) {
					configureKernelNetem(test, options, "delay", "2ms")
				}
			}
			var traffic *kernelTCPHarness
			config.handshake = func(conn *GoConn) error {
				if scenario.loss {
					traffic.setFilter(conn, kernelBidirectionalDataLoss())
				}
				return conn.HandshakeSuccess()
			}
			fixture, traffic := newKernelTCPFixture(configTest, config, kernelTCPConfig{})
			if scenario.loss {
				configTest.Cleanup(func() {
					traffic.access.Lock()
					defer traffic.access.Unlock()
					for key, flow := range traffic.flows {
						if flow.faults != 2 {
							configTest.Errorf("flow %v observed %d targeted data drops, expected 2", key, flow.faults)
						}
					}
				})
			}
			for _, ipv6 := range []bool{false, true} {
				for _, mode := range []string{"write", "buffer", "splice"} {
					configTest.Run(fmt.Sprintf("ipv6=%v/mode=%s", ipv6, mode), func(test *testing.T) {
						test.Parallel()
						kernelBackpressure(test, fixture, ipv6, mode, size)
					})
				}
			}
		})
	}
}

func TestGoKernelReceiveWindowUpdateLoss(t *testing.T) {
	fixture, traffic := newKernelTCPFixture(t, kernelStackConfig{mtu: 1500, socketBuffer: 4096}, kernelTCPConfig{})
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(test *testing.T) {
			client, server := fixture.pair(test, ipv6)
			payload := kernelPayload(512<<10, 131)
			written := make(chan error, 1)
			go func() {
				_, err := client.Write(payload)
				if err == nil {
					err = client.CloseWrite()
				}
				written <- err
			}()
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				if server.receiveEdge.Load()-server.receiveAvailable.Load() < 1<<server.localWindowShift {
					break
				}
				time.Sleep(time.Millisecond)
			}
			available := server.receiveAvailable.Load() - 1
			if available == 0 || server.receiveEdge.Load()-server.receiveAvailable.Load() >= 1<<server.localWindowShift {
				test.Fatal("Go receive window did not close")
			}
			windowUpdate := func(event kernelTCPEvent) bool {
				return event.outgoing && event.flags == header.TCPFlagAck && event.window > 0
			}
			traffic.setFilter(server, func(event kernelTCPEvent) kernelTCPAction {
				return kernelTCPAction{drop: windowUpdate(event)}
			})
			data := make([]byte, len(payload))
			_, err := io.ReadFull(server, data[:available])
			if err != nil {
				test.Fatal(err)
			}
			traffic.await(test, server, "drop Go receive-window update", func(flow kernelTCPFlow) bool {
				return slices.ContainsFunc(flow.events, func(event kernelTCPEvent) bool { return event.dropped && windowUpdate(event) })
			})
			traffic.setFilter(server, nil)
			server.SetReadDeadline(time.Now().Add(4 * time.Second))
			_, err = io.ReadFull(server, data[available:])
			if err != nil {
				test.Fatal("recover Go receive window:", err)
			}
			if !bytes.Equal(data, payload) {
				test.Fatal("receive window recovery corrupted the stream")
			}
			_, err = server.Read(data[:1])
			if err != io.EOF {
				test.Fatalf("stream end: %v", err)
			}
			err = kernelTCPResult(test, written, "upload after receive-window update loss")
			if err != nil {
				test.Fatal(err)
			}
		})
	}
}

func TestGoKernelSACKReneging(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(test *testing.T) {
			test.Parallel()
			fixture, traffic := newKernelTCPFixture(test, kernelStackConfig{mtu: 1500}, kernelTCPConfig{})
			client, server := fixture.pair(test, ipv6)
			traffic.setFilter(server, func(event kernelTCPEvent) kernelTCPAction {
				return kernelTCPAction{drop: event.outgoing && event.sequence == 1 && event.end > event.sequence}
			})
			mss := int(server.effectiveMSS.Load())
			payload := kernelPayload(8*mss, 137)
			_, err := server.Write(payload)
			if err != nil {
				test.Fatal(err)
			}
			retained := goSackBlock{start: uint64(mss + 1), end: uint64(len(payload) + 1)}
			traffic.await(test, server, "kernel SACK of queued out-of-order data", func(flow kernelTCPFlow) bool {
				return slices.ContainsFunc(flow.events, func(event kernelTCPEvent) bool {
					return !event.outgoing && slices.Contains(event.sacks, retained)
				})
			})
			err = client.SetReadBuffer(512)
			if err != nil {
				test.Fatal(err)
			}
			traffic.setFilter(server, nil)
			traffic.await(test, server, "kernel reneging on its SACK interval", func(flow kernelTCPFlow) bool {
				return slices.ContainsFunc(flow.events, func(event kernelTCPEvent) bool {
					return !event.outgoing && event.ack >= retained.start && event.ack < retained.end
				})
			})
			err = client.SetReadBuffer(64 << 10)
			if err != nil {
				test.Fatal(err)
			}
			client.SetReadDeadline(time.Now().Add(4 * time.Second))
			data := make([]byte, len(payload))
			n, err := io.ReadFull(client, data)
			if err != nil || !bytes.Equal(data, payload) {
				test.Fatalf("SACK reneging: received=%d/%d: %v", n, len(payload), err)
			}
			err = server.CloseWrite()
			if err != nil {
				test.Fatal(err)
			}
			_, err = client.Read(data[:1])
			if err != io.EOF {
				test.Fatalf("stream end after SACK reneging: %v", err)
			}
		})
	}
}

func TestGoKernelZeroWindowHalfClose(t *testing.T) {
	config := kernelStackConfig{mtu: 9000, socketBuffer: 512}
	config.dialer = net.Dialer{Control: func(_, _ string, rawConn syscall.RawConn) error {
		var optionErr error
		err := rawConn.Control(func(descriptor uintptr) {
			optionErr = unix.SetsockoptInt(int(descriptor), unix.SOL_SOCKET, unix.SO_RCVBUF, 512)
			if optionErr == nil {
				optionErr = unix.SetsockoptInt(int(descriptor), unix.IPPROTO_TCP, unix.TCP_WINDOW_CLAMP, 1024)
			}
		})
		return E.Errors(err, optionErr)
	}}
	// The peer socket deliberately keeps a tiny receive buffer, so the sender has to
	// stop in the middle of a stream and wait for the application to read before it can
	// deliver the rest and the FIN. The closed window is a property of the peer's buffer,
	// not of a stalled write, so every phase below waits for the state it verifies.
	t.Run("blocked-data", func(scenario *testing.T) {
		for _, ipv6 := range []bool{false, true} {
			scenario.Run(fmt.Sprintf("ipv6=%v", ipv6), func(test *testing.T) {
				test.Parallel()
				fixture, traffic := newKernelTCPFixture(test, config, kernelTCPConfig{})
				client, server := fixture.pair(test, ipv6)
				payload := kernelPayload(8<<10, 139)
				_, err := server.Write(payload)
				if err != nil {
					test.Fatal(err)
				}
				unacked, permit := waitClosedWindow(test, server, uint64(len(payload)+1))
				if server.sentTail.Load() != unacked || server.bufferedTail.Load() != uint64(len(payload)+1) {
					test.Fatalf("data crossed the closed window: unacked=%d sent=%d buffered=%d permit=%d", unacked, server.sentTail.Load(), server.bufferedTail.Load(), permit)
				}
				finEnd, finDropped := dropFinAcknowledgement(traffic, server)
				err = server.CloseWrite()
				if err != nil {
					test.Fatal(err)
				}
				// The FIN is behind data that the closed window still holds back, so it
				// must not be sent on its own.
				time.Sleep(50 * time.Millisecond)
				if flow := traffic.snapshot(server.key); flow.fin != 0 {
					test.Fatalf("FIN sent at %d while %d bytes of data were blocked by the closed window", flow.fin, server.bufferedTail.Load()-unacked)
				}
				verifyZeroWindowHalfClose(test, client, server, traffic, make([]byte, len(payload)), payload, finEnd, finDropped)
			})
		}
	})
	// A FIN occupies sequence space, so when the peer's window closes exactly at the end
	// of the data the FIN has to wait for a window update instead of being sent beyond
	// the advertised right edge.
	t.Run("fin-at-window-edge", func(scenario *testing.T) {
		for _, ipv6 := range []bool{false, true} {
			scenario.Run(fmt.Sprintf("ipv6=%v", ipv6), func(test *testing.T) {
				test.Parallel()
				fixture, traffic := newKernelTCPFixture(test, config, kernelTCPConfig{})
				client, server := fixture.pair(test, ipv6)
				const windowProbe = 0x5a
				_, err := server.Write([]byte{windowProbe})
				if err != nil {
					test.Fatal(err)
				}
				// The SYN carries the peer's initial window; the first acknowledgement
				// advertises the window the peer will actually honour. Size the payload
				// from that value so it fills the window exactly.
				traffic.await(test, server, "peer window after the first byte", func(flow kernelTCPFlow) bool {
					return server.sendUnacked.Load() >= 2 && server.sendPermit.Load()&^goPermitWindowBit > server.sendUnacked.Load()
				})
				unacked := server.sendUnacked.Load()
				permit := server.sendPermit.Load() &^ goPermitWindowBit
				window := permit - unacked
				if window == 0 || window > 1<<20 {
					test.Fatalf("unexpected peer window %d", window)
				}
				payload := kernelPayload(int(window), 139)
				_, err = server.Write(payload)
				if err != nil {
					test.Fatal(err)
				}
				deadline := time.Now().Add(2 * time.Second)
				for time.Now().Before(deadline) {
					if server.sendUnacked.Load() == permit && server.sendPermit.Load()&^goPermitWindowBit == permit && server.sentTail.Load() == permit && server.bufferedTail.Load() == permit {
						break
					}
					time.Sleep(time.Millisecond)
				}
				if server.sendUnacked.Load() != permit || server.sendPermit.Load()&^goPermitWindowBit != permit || server.sentTail.Load() != permit || server.bufferedTail.Load() != permit {
					test.Fatalf("window did not close at the end of the data: unacked=%d sent=%d buffered=%d permit=%d", server.sendUnacked.Load(), server.sentTail.Load(), server.bufferedTail.Load(), server.sendPermit.Load()&^goPermitWindowBit)
				}
				if flow := traffic.snapshot(server.key); flow.peerWindow != 0 {
					test.Fatalf("peer window is %d, expected the buffer to be full", flow.peerWindow)
				}
				finEnd, finDropped := dropFinAcknowledgement(traffic, server)
				err = server.CloseWrite()
				if err != nil {
					test.Fatal(err)
				}
				time.Sleep(50 * time.Millisecond)
				if flow := traffic.snapshot(server.key); flow.fin != 0 {
					test.Fatalf("FIN sent at sequence %d outside the zero receive window; the advertised right edge is %d", flow.fin, permit)
				}
				stream := make([]byte, 1+len(payload))
				expected := make([]byte, len(stream))
				expected[0] = windowProbe
				copy(expected[1:], payload)
				verifyZeroWindowHalfClose(test, client, server, traffic, stream, expected, finEnd, finDropped)
			})
		}
	})
}

// waitClosedWindow waits until the peer's window stops the sender in the middle of the
// buffered stream.
func waitClosedWindow(t *testing.T, conn *GoConn, buffered uint64) (uint64, uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		unacked := conn.sendUnacked.Load()
		permit := conn.sendPermit.Load() &^ goPermitWindowBit
		closed := permit == unacked && conn.bufferedTail.Load() == buffered &&
			unacked > 1 && unacked < buffered && conn.sentTail.Load() == unacked
		if closed {
			return unacked, permit
		}
		time.Sleep(time.Millisecond)
	}
	unacked := conn.sendUnacked.Load()
	permit := conn.sendPermit.Load() &^ goPermitWindowBit
	t.Fatalf("receive window did not close: unacked=%d sent=%d buffered=%d permit=%d", unacked, conn.sentTail.Load(), conn.bufferedTail.Load(), permit)
	return 0, 0
}

// dropFinAcknowledgement drops the acknowledgement of the FIN so the recovery path that
// retransmits it is exercised. The FIN starts at the first sequence past the buffered data.
func dropFinAcknowledgement(traffic *kernelTCPHarness, conn *GoConn) (uint64, func(kernelTCPFlow) bool) {
	finSequence := conn.bufferedTail.Load()
	finAck := func(event kernelTCPEvent) bool {
		return !event.outgoing && event.flags&header.TCPFlagAck != 0 && event.ack == finSequence+1
	}
	traffic.setFilter(conn, func(event kernelTCPEvent) kernelTCPAction {
		if finAck(event) {
			return kernelTCPAction{drop: true}
		}
		return kernelTCPAction{}
	})
	return finSequence + 1, func(flow kernelTCPFlow) bool {
		return slices.ContainsFunc(flow.events, func(event kernelTCPEvent) bool {
			return event.dropped && finAck(event)
		})
	}
}

func verifyZeroWindowHalfClose(test *testing.T, client *net.TCPConn, server *GoConn, traffic *kernelTCPHarness, stream []byte, expected []byte, finEnd uint64, finDropped func(kernelTCPFlow) bool) {
	test.Helper()
	if err := client.SetReadBuffer(64 << 10); err != nil {
		test.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(4 * time.Second))
	_, err := io.ReadFull(client, stream)
	if err != nil {
		test.Fatal("zero-window data:", err)
	}
	if !bytes.Equal(stream, expected) {
		test.Fatal("zero-window data corrupted the stream")
	}
	traffic.await(test, server, "FIN sent after the receive window reopened", func(flow kernelTCPFlow) bool {
		return flow.fin == finEnd
	})
	traffic.await(test, server, "drop FIN acknowledgement", finDropped)
	_, err = client.Read(stream[:1])
	if err != io.EOF {
		test.Fatalf("zero-window stream end: %v", err)
	}
	traffic.setFilter(server, nil)
	traffic.await(test, server, "recover lost FIN acknowledgement", func(flow kernelTCPFlow) bool {
		return flow.acked >= flow.fin
	})
	err = client.CloseWrite()
	if err != nil {
		test.Fatal(err)
	}
	server.SetReadDeadline(time.Now().Add(4 * time.Second))
	_, err = server.Read(stream[:1])
	if err != io.EOF {
		test.Fatalf("peer FIN: %v", err)
	}
}
func TestGoKernelWindowLimitedRecovery(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(test *testing.T) {
			test.Parallel()
			fixture := newKernelStackFixture(test, kernelStackConfig{mtu: 9000})
			client, server := fixture.pair(test, ipv6)
			err := client.SetReadBuffer(4096)
			if err != nil {
				test.Fatal(err)
			}
			output, err := kernelCommand("tc", "qdisc", "add", "dev", fixture.options.Name, "root", "netem", "delay", "50ms")
			if err != nil {
				test.Fatalf("delay ACKs: %s: %v", output, err)
			}
			payload := kernelPayload(8<<20, 223)
			initial := 4 * int(server.effectiveMSS.Load())
			_, err = server.Write(payload[:initial])
			if err != nil {
				test.Fatal(err)
			}
			deadline := time.Now().Add(time.Second)
			for time.Now().Before(deadline) {
				if server.sendPermit.Load()&^goPermitWindowBit == server.sendUnacked.Load() && server.sentTail.Load() > server.sendUnacked.Load()+2*uint64(server.effectiveMSS.Load()) {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if server.sendPermit.Load()&^goPermitWindowBit != server.sendUnacked.Load() || server.sentTail.Load() <= server.sendUnacked.Load()+2*uint64(server.effectiveMSS.Load()) {
				test.Fatal("window did not shrink below outstanding data")
			}
			completed := make(chan kernelIOResult, 1)
			server.SetWriteDeadline(time.Now().Add(2 * time.Second))
			go func() {
				n, writeErr := server.Write(payload[initial:])
				completed <- kernelIOResult{n: n + initial, err: writeErr}
			}()
			deadline = time.Now().Add(time.Second)
			for server.writerWaiting.Load() == 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if server.writerWaiting.Load() == 0 {
				test.Fatal("write did not block at the closed window")
			}
			server.SetWriteDeadline(time.Now())
			var accepted int
			select {
			case result := <-completed:
				if !errors.Is(result.err, os.ErrDeadlineExceeded) || result.n <= 0 || result.n >= len(payload) {
					test.Fatalf("interrupt blocked write: %+v", result)
				}
				accepted = result.n
			case <-time.After(time.Second):
				test.Fatal("write did not react to deadline")
			}
			output, err = kernelCommand("tc", "qdisc", "del", "dev", fixture.options.Name, "root")
			if err != nil {
				test.Fatalf("restore ACKs: %s: %v", output, err)
			}
			err = client.SetReadBuffer(4 << 20)
			if err != nil {
				test.Fatal(err)
			}
			rawConn, err := client.SyscallConn()
			if err != nil {
				test.Fatal(err)
			}
			var optionErr error
			err = rawConn.Control(func(descriptor uintptr) {
				optionErr = unix.SetsockoptInt(int(descriptor), unix.IPPROTO_TCP, unix.TCP_WINDOW_CLAMP, 6144)
			})
			if err != nil || optionErr != nil {
				test.Fatalf("limit receive window: %v %v", err, optionErr)
			}
			server.SetWriteDeadline(time.Now().Add(4 * time.Second))
			client.SetReadDeadline(time.Now().Add(4 * time.Second))
			go func() {
				n, writeErr := server.Write(payload[accepted:])
				if writeErr == nil {
					writeErr = server.CloseWrite()
				}
				completed <- kernelIOResult{n: n + accepted, err: writeErr}
			}()
			data, err := io.ReadAll(client)
			if err != nil || !bytes.Equal(data, payload) {
				test.Fatalf("window-limited recovery: received=%d/%d accepted=%d: %v", len(data), len(payload), accepted, err)
			}
			select {
			case result := <-completed:
				if result.err != nil || result.n != len(payload) {
					test.Fatalf("resume blocked write: %+v", result)
				}
			case <-time.After(time.Second):
				test.Fatal("write remained blocked after recovery")
			}
		})
	}
}

func TestGoKernelZeroWindow(t *testing.T) {
	fixture, traffic := newKernelTCPFixture(t, kernelStackConfig{mtu: 9000}, kernelTCPConfig{})
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(test *testing.T) {
			client, server := fixture.pair(test, ipv6)
			err := client.SetReadBuffer(4096)
			if err != nil {
				test.Fatal(err)
			}
			output, err := kernelCommand("tc", "qdisc", "replace", "dev", fixture.options.Name, "root", "netem", "delay", "50ms")
			if err != nil {
				test.Fatalf("tc qdisc replace: %s: %v", output, err)
			}
			payload := kernelPayload(32768, 107)
			_, err = server.Write(payload)
			if err != nil {
				test.Fatal(err)
			}
			deadline := time.Now().Add(time.Second)
			for time.Now().Before(deadline) {
				if server.sendPermit.Load()&^goPermitWindowBit == server.sendUnacked.Load() && server.sentTail.Load() == server.bufferedTail.Load() {
					break
				}
				time.Sleep(time.Millisecond)
			}
			unacked := server.sendUnacked.Load()
			if server.sendPermit.Load()&^goPermitWindowBit != unacked || server.sentTail.Load() != uint64(len(payload)+1) || unacked <= 1 || unacked >= server.sentTail.Load() {
				test.Fatalf("window did not close with only outstanding data: unacked=%d sent=%d buffered=%d permit=%d", unacked, server.sentTail.Load(), server.bufferedTail.Load(), server.sendPermit.Load()&^goPermitWindowBit)
			}
			windowUpdate := func(event kernelTCPEvent) bool {
				return !event.outgoing && event.flags == header.TCPFlagAck && event.window > 0
			}
			traffic.setFilter(server, func(event kernelTCPEvent) kernelTCPAction {
				return kernelTCPAction{drop: windowUpdate(event)}
			})
			output, err = kernelCommand("tc", "qdisc", "del", "dev", fixture.options.Name, "root")
			if err != nil {
				test.Fatalf("tc qdisc del: %s: %v", output, err)
			}
			err = client.SetReadBuffer(4 << 20)
			if err != nil {
				test.Fatal(err)
			}
			data := make([]byte, len(payload))
			_, err = io.ReadFull(client, data[:unacked-1])
			if err != nil {
				test.Fatal(err)
			}
			traffic.await(test, server, "drop kernel receive-window update", func(flow kernelTCPFlow) bool {
				return slices.ContainsFunc(flow.events, func(event kernelTCPEvent) bool { return event.dropped && windowUpdate(event) })
			})
			traffic.setFilter(server, nil)
			client.SetReadDeadline(time.Now().Add(4 * time.Second))
			_, err = io.ReadFull(client, data[unacked-1:])
			if err != nil {
				test.Fatal("recover lost window update:", err)
			}
			if !bytes.Equal(data, payload) {
				test.Fatal("zero-window recovery corrupted the stream")
			}
		})
	}
}
