# Fork notice — TCP accept-loop self-healing

This repository is a fork of [`SagerNet/sing-tun`](https://github.com/SagerNet/sing-tun),
maintained by `Piggy-Cat-bit-shadow` for use by
[`Piggy-Cat-bit-shadow/sing-box`](https://github.com/Piggy-Cat-bit-shadow/sing-box).

sing-tun is licensed under the GNU General Public License v3.0 (see `LICENSE`, unchanged).
This fork is distributed under the same licence.

## Why this fork exists

The system stack's TCP accept loop ends permanently on any unexpected `listener.Accept`
error:

```go
conn, err := listener.Accept()
if err != nil {
    return
}
```

The listener is bound to the stack's own address, and its port is what the forward path
rewrites every new SYN onto. Nothing clears that port when the loop exits, so the stack
keeps rewriting new connections onto a port nobody is listening on: the OS answers RST,
the RST is translated back to the application, and **every new TCP connection fails
instantly until the tunnel is rebuilt** — while existing connections, UDP and QUIC carry
on working. The listener can be closed from outside the stack (the fd space is shared
with the embedding application; a fast restart is the observed trigger), so the error does
not mean the stack is finished.

## Modification

`stack_system.go` only. The accept loop now classifies its error:

- an orderly shutdown (`System.Close` has set its `closing` flag, or the error is
  `net.ErrClosed` / a canceled or expired context) ends the loop quietly, exactly as
  before;
- any other error is treated as recoverable: it is logged with the full error text, the
  unusable listener is closed, and a new listener is bound on the same address. The new
  port is published under a lock so the forwarding path reads it coherently, and a
  recovery counter is incremented for telemetry;
- re-binding is retried with a bounded backoff (`acceptRecoveryDelays`: 10 ms → 1 s cap),
  and `Close` interrupts the wait immediately and prevents any further attempt. If
  re-binding keeps failing the loop ends, which is no worse than the behaviour it
  replaces.

The same change was made independently in
[`Leadaxe/sing-box-lx`](https://github.com/Leadaxe/sing-box-lx) (task
`SPECS/TASKS/040-SINGTUN_ACCEPTLOOP_SELFHEAL`) inside a fork of sing-tun. This fork keeps
the same failure-mode reasoning but is based on this repository's own pinned upstream
revision, contains **only** this change, and carries its own regression tests. It does not
take any other patch from that project.

## Provenance

| | |
| --- | --- |
| Upstream | `https://github.com/SagerNet/sing-tun` |
| Base commit | `d769a7080ca203f63735ba93e95014e363e25d62` (2026-10-06, "Rework forward NAT with UDP mapping and fragment support") |
| Base module version | `v0.9.7-0.20261006124248-d769a7080ca2` (the version this fork replaces) |
| Upstream status at fork time | `dev` @ `7539c9855f` (2026-10-07) still had the unrecoverable loop; no upstream fix available |
| Changed files | `stack_system.go` (the loop, `Close`, the recorded bind arguments, the locked port accessor), `stack_system_accept_test.go` (new) |

## Tests

`stack_system_accept_test.go` drives the loop with injected accept failures and injected
re-binds, so it needs no TUN device and no network:

- `TestSystemAcceptLoopRecoversFromUnexpectedAcceptError` — one unexpected error, then a
  new flow must be accepted and dispatched to the handler with the original flow's
  endpoints (red on the base commit: the loop had already exited);
- `TestSystemAcceptLoopBackoffIsBoundedWhenRebindKeepsFailing` — repeated failures must be
  spaced by the backoff, not spun, and must stop at `Close`;
- `TestSystemAcceptLoopCloseStopsRecovery` — `Close` interrupts the backoff;
- `TestSystemAcceptLoopIsQuietOnOrderlyClose` — an orderly shutdown produces no re-bind
  and no warning.

Verified red/green by reverting only the loop body: three of the four tests fail on the
base commit and all four pass with the change.

## Removal condition

This fork is deleted when upstream sing-tun makes the accept loop recover from an
unexpected accept error (or replaces the system stack's mechanics), and sing-box can pin
upstream again without losing the behaviour.
