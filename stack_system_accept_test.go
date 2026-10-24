package tun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// The system stack's TCP accept loop must not die permanently on one unexpected accept error.
//
// # The failure these tests kill
//
// The listener is bound to the stack's own address and its port is what the forward path rewrites
// every new SYN onto. The loop used to return on ANY accept error, and nothing cleared that port:
// the stack kept rewriting new connections onto a port nobody was listening on, the OS answered
// RST, and the RST was translated back to the application. Every new TCP connection then failed
// instantly until the tunnel was rebuilt, while existing connections, UDP and QUIC carried on
// working - which is why this presents as "the browser is dead but Telegram is fine" rather than
// as a stack failure.
//
// The listener can be closed from outside this stack (the fd space is shared with the embedding
// application, and a fast restart is the observed trigger), so that error says nothing about
// whether the stack is finished. An unexpected error must therefore be treated as recoverable,
// while an orderly Close must still end the loop immediately and for good.
//
// These tests drive the loop with injected accept failures and injected re-binds, so they need no
// TUN device and no network.

func TestSystemAcceptLoopRecoversFromUnexpectedAcceptError(t *testing.T) {
	shrinkRecoveryDelays(t)

	handler := &recordingHandler{accepted: make(chan acceptedFlow, 1)}
	system := &System{ctx: context.Background(), logger: logger.NOP(), handler: handler}
	tcpNat, cancelNat := newTestNat()
	t.Cleanup(cancelNat)

	first := newFakeListener()
	second := newFakeListener()
	system.recreateListener = func() (net.Listener, error) { return second, nil }

	done := runAcceptLoop(system, first, tcpNat)

	// One unexpected failure, of the kind a foreign close produces.
	first.failNext(errors.New("accept tcp4: use of closed network connection"))
	waitFor(t, func() bool { return system.RecoveredListeners() == 1 },
		"the loop must re-create the listener after an unexpected accept error")
	require.GreaterOrEqual(t, first.closeCalls.Load(), int64(1),
		"the listener the loop cannot accept on must be closed before it is replaced")

	// A new flow arriving on the restored listener must be accepted and dispatched, not refused.
	// LookupBack matches on the source port, so the fake connection reports the NAT-allocated
	// local address, which is what a real accepted connection reports.
	session := tcpNat.Lookup(netip.MustParseAddrPort("10.0.0.2:40000"), netip.MustParseAddrPort("93.184.216.34:443"))
	require.NotZero(t, session)
	conn, peer := net.Pipe()
	t.Cleanup(func() {
		_ = conn.Close()
		_ = peer.Close()
	})
	second.push(
		&addressedConn{Conn: conn, remote: net.TCPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), session))},
	)

	select {
	case flow := <-handler.accepted:
		// The handler is handed the ORIGINAL flow's endpoints, recovered from the NAT session the
		// listener port was matched back to - which is what a real TCP connection needs to be
		// routed. Accepting the connection without finding its session would be a different bug.
		require.Equal(t, netip.MustParseAddr("10.0.0.2"), flow.source.Addr)
		require.Equal(t, uint16(40000), flow.source.Port)
		require.Equal(t, netip.MustParseAddr("93.184.216.34"), flow.destination.Addr)
		require.Equal(t, uint16(443), flow.destination.Port)
	case <-time.After(2 * time.Second):
		t.Fatal("the restored listener did not accept and dispatch a new connection; " +
			"the pre-fix loop had already exited and every new TCP flow would fail until restart")
	}

	// Close closes the listener it currently owns, which is what unblocks a parked Accept.
	require.NoError(t, second.Close())
	closeSystemAndWait(t, system, done)
}

func TestSystemAcceptLoopBackoffIsBoundedWhenRebindKeepsFailing(t *testing.T) {
	originalDelays := acceptRecoveryDelays
	acceptRecoveryDelays = []time.Duration{time.Millisecond, 2 * time.Millisecond, 5 * time.Millisecond}
	t.Cleanup(func() { acceptRecoveryDelays = originalDelays })

	var attempts atomic.Int64
	system := &System{ctx: context.Background(), logger: logger.NOP(), handler: &recordingHandler{}}
	system.recreateListener = func() (net.Listener, error) {
		attempts.Add(1)
		return nil, errors.New("bind: address already in use")
	}
	tcpNat, cancelNat := newTestNat()
	t.Cleanup(cancelNat)

	listener := newFakeListener()
	done := runAcceptLoop(system, listener, tcpNat)
	listener.failNext(errors.New("accept tcp4: bad file descriptor"))

	// A bounded number of attempts in the observation window, not a hot loop: an unbounded
	// `continue` on the same listener, or a zero backoff, would run thousands of times here.
	time.Sleep(150 * time.Millisecond)
	observed := attempts.Load()
	require.Greater(t, observed, int64(0), "a failed re-bind must be retried")
	require.Less(t, observed, int64(50),
		"re-bind attempts must be spaced by the backoff; %d attempts in 150ms is a spin", observed)
	require.Zero(t, system.RecoveredListeners(),
		"a failed re-bind must not be counted as a recovery")

	// Close must return promptly and stop the retry loop: no attempt may run after it.
	closeSystemAndWait(t, system, done)
	afterClose := attempts.Load()
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, afterClose, attempts.Load(),
		"re-bind attempts continued after Close; recovery must not resurrect the listener during shutdown")
}

func TestSystemAcceptLoopCloseStopsRecovery(t *testing.T) {
	shrinkRecoveryDelays(t)

	var attempts atomic.Int64
	system := &System{ctx: context.Background(), logger: logger.NOP(), handler: &recordingHandler{}}
	system.recreateListener = func() (net.Listener, error) {
		attempts.Add(1)
		return nil, errors.New("bind failed")
	}
	tcpNat, cancelNat := newTestNat()
	t.Cleanup(cancelNat)

	listener := newFakeListener()
	done := runAcceptLoop(system, listener, tcpNat)

	// Fail, let the loop enter its recovery backoff, then Close.
	listener.failNext(errors.New("accept tcp4: use of closed network connection"))
	waitFor(t, func() bool { return attempts.Load() > 0 }, "recovery must have started")

	start := time.Now()
	system.closing.Store(true)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not interrupt the recovery backoff; shutdown would hang")
	}
	require.Less(t, time.Since(start), time.Second)
}

func TestSystemAcceptLoopIsQuietOnOrderlyClose(t *testing.T) {
	shrinkRecoveryDelays(t)

	var attempts atomic.Int64
	recorder := &levelRecordingLogger{}
	system := &System{ctx: context.Background(), logger: recorder, handler: &recordingHandler{}}
	system.recreateListener = func() (net.Listener, error) {
		attempts.Add(1)
		return newFakeListener(), nil
	}
	tcpNat, cancelNat := newTestNat()
	t.Cleanup(cancelNat)

	listener := newFakeListener()
	done := runAcceptLoop(system, listener, tcpNat)

	// The orderly shutdown: the flag goes up first (as Close does), then the listener reports
	// closed.
	system.closing.Store(true)
	listener.failNext(net.ErrClosed)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("an orderly close must end the accept loop")
	}
	require.Zero(t, attempts.Load(), "an orderly close must not trigger a re-bind")
	require.Zero(t, system.RecoveredListeners())
	require.Zero(t, recorder.warnings.Load(),
		"an orderly close must stay silent; a warning here means the recovery path mistook shutdown for a fault")
	require.Zero(t, recorder.errors.Load())
}

// newTestNat builds a TCP NAT whose timeout goroutine ends with the test.
func newTestNat() (*TCPNat, func()) {
	ctx, cancel := context.WithCancel(context.Background())
	return NewNat(ctx, time.Minute), cancel
}

// runAcceptLoop starts the accept loop under test and returns a channel closed when it returns.
func runAcceptLoop(system *System, listener net.Listener, tcpNat *TCPNat) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		system.acceptLoop(listener, tcpNat, "tcp4", "10.0.0.1:0")
	}()
	return done
}

// closeSystemAndWait marks the stack closing the way Close does and waits for the loop to end.
//
// It sets the flag first and then closes the listener the loop is parked on, which is the order
// System.Close uses. Closing the listener is what actually unblocks a parked Accept; the flag is
// what stops the loop from treating that close as a fault to recover from.
func closeSystemAndWait(t *testing.T, system *System, done <-chan struct{}) {
	t.Helper()
	system.closing.Store(true)
	system.listenerAccess.Lock()
	listener := system.tcpListener
	system.listenerAccess.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the accept loop did not exit after Close")
	}
}

func shrinkRecoveryDelays(t *testing.T) {
	t.Helper()
	originalDelays := acceptRecoveryDelays
	acceptRecoveryDelays = []time.Duration{time.Millisecond, 2 * time.Millisecond}
	t.Cleanup(func() { acceptRecoveryDelays = originalDelays })
}

func waitFor(t *testing.T, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal(message)
}

// fakeListener is a listener whose accept behaviour a test drives directly.
type fakeListener struct {
	access      sync.Mutex
	incoming    chan net.Conn
	failures    []error
	closeCalls  atomic.Int64
	closeSignal chan struct{}
	closeOnce   sync.Once
}

func newFakeListener() *fakeListener {
	return &fakeListener{
		incoming:    make(chan net.Conn, 8),
		closeSignal: make(chan struct{}),
	}
}

func (l *fakeListener) Accept() (net.Conn, error) {
	l.access.Lock()
	if len(l.failures) > 0 {
		err := l.failures[0]
		l.failures = l.failures[1:]
		l.access.Unlock()
		return nil, err
	}
	l.access.Unlock()
	select {
	case conn := <-l.incoming:
		return conn, nil
	case <-l.closeSignal:
		return nil, net.ErrClosed
	}
}

func (l *fakeListener) Close() error {
	l.closeCalls.Add(1)
	l.closeOnce.Do(func() { close(l.closeSignal) })
	return nil
}

func (l *fakeListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4zero} }

// failNext queues an accept error for the next Accept call.
func (l *fakeListener) failNext(err error) {
	l.access.Lock()
	l.failures = append(l.failures, err)
	l.access.Unlock()
}

// push queues a connection to be returned by a later Accept call.
func (l *fakeListener) push(conn net.Conn) {
	l.incoming <- conn
}

type addressedConn struct {
	net.Conn
	remote net.Addr
}

func (c *addressedConn) RemoteAddr() net.Addr { return c.remote }

// acceptedFlow is the routing information the handler was given for one accepted connection.
type acceptedFlow struct {
	source      M.Socksaddr
	destination M.Socksaddr
}

// recordingHandler records the flow of each accepted connection.
type recordingHandler struct {
	Handler
	accepted chan acceptedFlow
}

func (h *recordingHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if h.accepted != nil {
		h.accepted <- acceptedFlow{source: source, destination: destination}
	}
	_ = conn.Close()
}

// levelRecordingLogger counts warnings and errors, so a test can assert that an orderly shutdown
// produced neither.
type levelRecordingLogger struct {
	logger.ContextLogger
	warnings atomic.Int64
	errors   atomic.Int64
}

func (l *levelRecordingLogger) Warn(args ...any)  { l.warnings.Add(1) }
func (l *levelRecordingLogger) Error(args ...any) { l.errors.Add(1) }
func (l *levelRecordingLogger) WarnContext(ctx context.Context, args ...any) {
	l.warnings.Add(1)
}
func (l *levelRecordingLogger) ErrorContext(ctx context.Context, args ...any) {
	l.errors.Add(1)
}

var (
	_ net.Listener = (*fakeListener)(nil)
	_ Handler      = (*recordingHandler)(nil)
)
