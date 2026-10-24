# sing-tun

Simple transparent proxy library.

For Linux, Windows, macOS and iOS.

## License

```
Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
```
---

This is a fork of SagerNet/sing-tun. It differs from upstream in exactly two behavioural
changes:

- **the system stack's TCP accept loop self-heals** after an unexpected accept error instead
  of ending permanently, so a listener closed from outside the stack cannot leave every new
  TCP connection failing while UDP and QUIC keep working;
- **the Go stack's `Start`/`Close` is a published handshake**, so a `Close` racing a `Start`
  cannot leave engines running, half-published resources behind, or a `Start` reviving a
  stopped stack.

Both are carried on top of upstream `9ffa5391a2ad`, clean cherry-picks with no conflicts, and
neither touches upstream's own hairpin-batching work in `stack_go_engine.go`,
`stack_go_io_darwin.go` or `stack_go_memory_arena.go`. See [FORK.md](FORK.md) for the failure
modes, the provenance of the branch sing-box pins, and the removal condition.
