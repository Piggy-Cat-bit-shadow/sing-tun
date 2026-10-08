# Fork notice — TCP accept-loop self-healing and the Go stack Start/Close handshake

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

A second reason is the Go stack's `Start`/`Close` race described under Modification 2: a
stop landing on a starting stack concurrently reads the resources that start publishes. The
race detector reports it on a shipped path, and because the engine slice is published
before it is filled it can dereference a nil engine and panic. Upstream has not fixed it.

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

## Modification 2 — the Go stack's Start/Close handshake

`stack_go.go`. At upstream `7539c9855f19` (and at every revision that still carries
`stack_go.go`), `(*Go).Start` writes the stack's published resources while holding
`s.access` — `s.udpNats` at line 140 and `s.engines` at line 144, with the slice filled at
line 146 — but `(*Go).Close` releases `s.access` at line 347 and then reads those same
fields at lines 348, 354 and 358. `Start` never checked `s.closed`, so a `Start` that won
the lock after `Close` had published its decision resurrected a closed stack on top of the
teardown `Close` had already done, and the reads were unordered with the writes:

```
WARNING: DATA RACE
Write at 0x00c0002a00d8 by goroutine 15:
  github.com/sagernet/sing-tun.(*Go).Start()   stack_go.go:140
Previous read at 0x00c0002a00d8 by goroutine 16:
  github.com/sagernet/sing-tun.(*Go).Close()   stack_go.go:354
WARNING: DATA RACE
Write at 0x00c0002a0160 by goroutine 15:
  github.com/sagernet/sing-tun.(*Go).Start()   stack_go.go:144
Previous read at 0x00c0002a0160 by goroutine 16:
  github.com/sagernet/sing-tun.(*Go).Close()   stack_go.go:348
```

It is not only a detector complaint. `s.engines` is published as a slice of nil elements
before the fill loop runs, so a `Close` that reads it in that window dereferences a nil
engine: `stack_go.go:359` panics with `invalid memory address or nil pointer dereference`.
The reproducer in `stack_go_startclose_test.go` reaches that panic on the base revision.

The change defines the ownership rather than papering over the access:

- **Start owns the started resources** (`s.udpNats`, `s.dispatcher`, `s.engines`, the sized
  directory map). It is the only writer; it publishes them under `s.access`, and it
  publishes all of them before it creates any engine goroutine, so every goroutine `Start`
  creates observes the complete state.
- **Close owns the started state.** It sets `s.closed` under `s.access` and snapshots the
  published resources in that same critical section. It then releases the lock — it must,
  because the wait for engine exit cannot hold the publish lock — and works only from the
  snapshot.
- **Close wins.** `Start` checks `s.closed` in the critical section in which it would
  publish, so a `Start` that loses the race creates nothing (the check is before the queue
  factory) and nothing can start again after `Close` returns. A duplicate `Start` is a
  no-op rather than a second publish that would leak the first engine set.
- No deadlock: `postMessage` is a lock-free push plus a non-blocking wake and never takes
  `s.access`, so `Close` holds the lock only across the snapshot and the posting; there is
  no ordering in which `Close` waits on an engine while `Start` waits on `Close`.

## Branches

| Branch | Contents |
| --- | --- |
| `dev` | a mirror of `SagerNet/sing-tun` `dev`, never modified |
| `fix/acceptloop-selfheal` | the original fork, based on `d769a7080ca2` (2026-10-06). Superseded: it was based on an upstream revision that upstream has since rewritten out of `dev`, so the sing-box tree no longer pins it. Kept as history. |
| `sync/go-stack-plus-040` | `SagerNet/sing-tun` `dev` @ `7539c9855f19` (2026-10-07, "Rework forward NAT with UDP mapping and fragment support") with the 040 change and its regression test applied and nothing else. |
| `sync/go-stack-plus-040-and-race` | the branch sing-box pins. `sync/go-stack-plus-040` plus the Go stack Start/Close handshake (`stack_go.go`) and its regression test (`stack_go_startclose_test.go`), and nothing else. |

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

## Provenance (`sync/go-stack-plus-040-and-race`)

| | |
| --- | --- |
| Upstream | `https://github.com/SagerNet/sing-tun` |
| Upstream base commit | `7539c9855f19bb51a75f0908ecf6ae1d2d749490` (`dev` HEAD, 2026-10-07) |
| Base module version | `v0.9.7-0.20261007151655-7539c9855f19` (the version sing-box requires) |
| 040 patch commit | `46cfb7ff31fea7c2015b02f8126aae12af2baf4c` (`sync/go-stack-plus-040`) |
| 040 change / test | `stack_system.go` / `stack_system_accept_test.go` |
| This change / test | `stack_go.go` (the `s.access` publish/close handshake) / `stack_go_startclose_test.go` (new) |
| Upstream status at fork time | `dev` HEAD is `7539c9855f19` itself — upstream has not moved past the racy revision. `main`, `stable`, `dev-firewalld`, `draft-windows-auto-redirect` and `codex/propose-fix-for-docker-firewall-policy-bypass` do not contain `stack_go.go` at all; only the older `wip` (2026-09-07, pre-`access`-lock) has a Go stack, and it carries the same class of bug with no synchronisation whatsoever. No upstream fix exists. |
| Changed files vs upstream base | `FORK.md`, `README.md` (the 040 notice), `stack_system.go`, `stack_system_accept_test.go`, `stack_go.go`, `stack_go_startclose_test.go` — no other file |

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

`stack_go_startclose_test.go` builds a device-free Go stack over a `MemoryTun` (the same
construction `TestGoUDPReceiveBudget` uses), so it needs no TUN device and no privileges.
It drives the handshake with barriers and channels only — no sleeps — and observes the
closed bit, the memory tun's attached bit, each engine's exit signal, and whether `Start`
reached the queue factory:

- `TestGoStackStartAndCloseConcurrently` — `Start || Close`, 200 iterations;
- `TestGoStackStartCloseStartConcurrently` — `Start || Close || Start`, 200 iterations;
- `TestGoStackStartCloseRepeat100` / `TestGoStackStartCloseRepeat1000` — the same shape
  repeated 100 and 1000 times, each followed by a refused `Start` after `Close`;
- `TestGoStackCloseBeforeStartCompletes` — `Close` is issued while `Start` is held inside
  `s.access`, before anything is built; `Close` must not return until the publish finished;
- `TestGoStackCloseImmediatelyAfterPublish` — `Close` is issued at the publish boundary,
  after the queues exist and before `Start` assigns `s.engines`; the engine `Start`
  produced must still be stopped;
- `TestGoStackStartAfterCloseIsRefused` — `Close` before `Start`, idempotent second
  `Close`, then three `Start` attempts that must all return `os.ErrClosed` without reaching
  the queue factory.

Red on `7539c9855f19`: race reports on `stack_go.go:140`/`:144`/`:146` against `:348`/`:354`
plus a nil-pointer panic at `stack_go.go:359`, and the semantic assertions
(`Start` after `Close` returning `nil`, the queue still attached, engines still running).
Green on this branch under `-race`, including `-count=3`.

## Removal condition

This fork is deleted when upstream sing-tun makes the accept loop recover from an
unexpected accept error (or replaces the system stack's mechanics), and makes the Go
stack's Start/Close a published handshake, and sing-box can pin upstream again without
losing either behaviour.
