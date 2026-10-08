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
the same failure-mode reasoning, contains **only** this change, and carries its own
regression tests. It does not take any other patch from that project.

## Branches

| Branch | Contents |
| --- | --- |
| `dev` | a mirror of `SagerNet/sing-tun` `dev`, never modified |
| `fix/acceptloop-selfheal` | the original fork, based on `d769a7080ca2` (2026-10-06). Superseded: it was based on an upstream revision that upstream has since rewritten out of `dev`, so the sing-box tree no longer pins it. Kept as history. |
| `sync/go-stack-plus-040` | the branch sing-box pins. `SagerNet/sing-tun` `dev` @ `7539c9855f19` (2026-10-07, "Rework forward NAT with UDP mapping and fragment support") with the 040 change and its regression test applied and nothing else. |

## Provenance (`sync/go-stack-plus-040`)

| | |
| --- | --- |
| Upstream | `https://github.com/SagerNet/sing-tun` |
| Upstream base commit | `7539c9855f19bb51a75f0908ecf6ae1d2d749490` (`dev` HEAD at the time of writing, 2026-10-07) |
| Base module version | `v0.9.7-0.20261007151655-7539c9855f19` (the version sing-box requires) |
| 040 change | `stack_system.go` (the loop, `Close`, the recorded bind arguments, the locked port accessor) |
| 040 regression test | `stack_system_accept_test.go` (new, 348 lines) |
| Derived from | `fix/acceptloop-selfheal` @ `665fbe204ce76c691ff40f58e9e33020af5e44f1`, cherry-picked onto the new base with no conflict |
| Upstream status at fork time | every `SagerNet/sing-tun` branch (`dev`, `main`, `stable`, `dev-firewalld`, `draft-windows-auto-redirect`, `codex/propose-fix-for-docker-firewall-policy-bypass`) still contains the unrecoverable loop; no upstream fix exists |
| Changed files vs upstream base | `FORK.md`, `README.md` (this notice), `stack_system.go`, `stack_system_accept_test.go` — no other file |

## Tests

`stack_system_accept_test.go` drives the loop with injected accept failures and injected
re-binds, so it needs no TUN device and no network:

- `TestSystemAcceptLoopRecoversFromUnexpectedAcceptError` — one unexpected error, then a
  new flow must be accepted and dispatched to the handler with the original flow's
  endpoints;
- `TestSystemAcceptLoopBackoffIsBoundedWhenRebindKeepsFailing` — repeated failures must be
  spaced by the backoff, not spun, and must stop at `Close`;
- `TestSystemAcceptLoopCloseStopsRecovery` — `Close` interrupts the backoff;
- `TestSystemAcceptLoopIsQuietOnOrderlyClose` — an orderly shutdown produces no re-bind
  and no warning.

Verified red/green against the exact base revision: a behavioral probe written against the
pre-fix API (`System.acceptLoop(listener, tcpNat)`) that injects one unexpected accept
error and then offers a new connection fails on `7539c9855f19` with
"the accept loop exited permanently after one unexpected accept error", and the four tests
above pass with the change applied.

## Removal condition

This fork is deleted when upstream sing-tun makes the accept loop recover from an
unexpected accept error (or replaces the system stack's mechanics), and sing-box can pin
upstream again without losing the behaviour.
