# dbgscope ![Build Status](https://github.com/glslang/dbgscope/actions/workflows/ci.yml/badge.svg) [![codecov](https://codecov.io/gh/glslang/dbgscope/branch/main/graph/badge.svg)](https://codecov.io/gh/glslang/dbgscope) [![Dependency status](https://deps.rs/repo/github/glslang/dbgscope/status.svg)](https://deps.rs/repo/github/glslang/dbgscope)

`dbgscope` is a Rust 2024 library giving typed access to a WinDbg/DbgEng debug session, and
allocator walkers built on top of one. It is two layers, and the split is worth knowing before
reading further.

`dbgeng` is the **session driver**. It opens a target — a live kernel over KD, a local kernel, a
launched or attached user-mode process, a crash dump, or a TTD trace — and answers in values
rather than in the text `r`, `lm` and `bl` print: `register_values`, `modules`, `breakpoints`,
stack frames carrying the module each belongs to, bug checks as fields. It also *drives* the
target, which is the half that takes care. DbgEng sets a run state and returns; nothing moves
until a `WaitForEvent` pumps it, so execution control here is a bounded wait with a watchdog
behind it rather than a command send, and a forced break at the bound is reported as one instead
of passing for a stop.

`pool` and `heap` are **allocator archaeology** on that session — the kernel pool and the
user-mode Segment Heap. They share their page-segment, LFH, VS, backend and large-allocation
decoding, because the two allocators are the same machinery either side of the ring boundary.
The pool walker is also exposed to WinDbg directly as the `!dbgscope.poolmap` extension command.

## Scope

Reads and drives a debug session; it does not exploit one. Everything here is analysis —
walking allocator metadata, resolving symbols, stepping a target. Corrupt or unreadable
allocator metadata is reported conservatively rather than treated as an exploitable condition.

## Requirements

- Windows x86_64 or Windows ARM64.
- Rust stable for normal builds and nightly for Miri.
- MSVC build tools.
- Optional local test runner: `cargo nextest`.

The crate is Windows-only in practice because the public surface calls Windows APIs directly.

Symbols must be on the **debugger** host — PDBs are never fetched from a target over KD — and
resolving them at all needs `msdia140.dll` beside the engine (`symsrv.dll` finds a PDB, that one
parses it). Without it every module reports `Symbol Type: EXPORT - PDB not found`, and on a
kernel dump it presents not as missing symbols but as a memory read failing, since virtual
addresses are translated through structures the engine locates with `nt`'s symbols.

## Build and Test

```bash
# Build for the active Windows target.
cargo build --verbose

# Match the CI formatter gate.
cargo fmt --all -- --check

# Preferred test runner.
cargo nextest run --verbose

# Fallback test runner.
cargo test

# Nightly unsafe-code check used by CI.
cargo miri test --verbose
```

## WinDbg Pool Map Extension

Building the library for the native x64 MSVC target produces both the normal Rust
library and `target\debug\dbgscope.dll`:

```powershell
rustup target add x86_64-pc-windows-msvc
cargo build --lib
```

Run that command from an x64 MSVC Rust host. If an explicit
`--target x86_64-pc-windows-msvc` is supplied instead, the DLL is written to
`target\x86_64-pc-windows-msvc\debug\dbgscope.dll` and the `.load` path must use
that target-qualified directory.

The pool walker assumes Windows 10 19H1 or later allocator algorithms and requires
full private/public type information for `nt`. Configure a Microsoft symbol-server
path, break into the kernel target, and force-load kernel symbols before using it:

```text
.symfix
.reload /f nt
.load C:\path\to\dbgscope\target\debug\dbgscope.dll
!dbgscope.help
```

The primary command is:

```text
!dbgscope.poolmap -tag Pipe
!dbgscope.poolmap -tag ABC -paged
!dbgscope.poolmap -tag Test -nonpaged -refresh
!dbgscope.poolmap ffff800012345678
```

`-tag` accepts one through four ASCII bytes, or the **raw form** — `0x` and the four
bytes as hex, in memory order, so it reads in the same direction as the printed tag
(`Tgsm` is `0x5467736d`). Internally the tag remains the exact four-byte raw
little-endian value; printable display text is only a rendering, and a lossy one: every
byte that does not print becomes `.`, and so does a literal `.`. A tag shown with a `.`
in it therefore names no particular tag, and passing that rendering to `-tag` asks about
literal `.` bytes rather than about what was displayed — which is why output prints the
raw form instead wherever the rendering would be ambiguous. Query that. The two forms
cannot be confused: the raw form is exactly ten characters and a printed tag is at most
four, so `0x2e` is still the four-byte tag `0x2e`. The tag map retains nearby unrelated
allocations and holes. `-paged` and `-nonpaged`
filter exact pool identities and cannot be combined. An address query prints detail
for the allocation or hole containing that address. `-refresh` discards a complete
cached snapshot and walks again.

“Snapshot” is literal: the extension examines current allocations, reusable frees,
and cached/delay-free spans while the target is stopped. It does not install
allocation breakpoints or reconstruct allocation history. The cache is invalidated
when execution resumes or the debugger session changes, and incomplete or
Ctrl+C-interrupted walks are never cached.

A walk is thousands of debugger reads plus every committed pool page, so over a live
KDNET link it can run for minutes. `!dbgscope.poolmap` lets it run to completion —
you are at the prompt and can Ctrl+Break. The programmatic API in `pool::query`
cannot assume that, because nothing else sets that flag, so its walks carry a
wall-clock budget (`PoolWalk`, defaulting to `DEFAULT_WALK_BUDGET`). A walk that runs
out of it is not an error: it returns the chunks it reached with `complete` cleared
and a diagnostic saying how much of the pool it got through. As everywhere else here,
“the walk did not see it” is reported as exactly that and never as “it is not there”.

Against a live kernel a walk is **normally incomplete**, and that is the target being
honest rather than the walker being broken: paged pool is partly out on disk, and a
page the memory manager has paged out cannot be read through the debugger either. Such
ranges come back as `sparse virtual range` diagnostics and the chunks inside them are
absent from the snapshot, so `complete` is cleared. Expect a live walk to carry
thousands of diagnostics too, and read them by shape (`PoolDiagnostics::shapes`, which
counts each distinct complaint) rather than by how many lines were kept — one stale
list pointer or one paged-out region yields one message per node.

When WinDbg accepts DML, map cells have colors and clickable address-detail links.
The same rows use meaningful ASCII glyphs and include a legend when DML is stripped
or plain-text output is captured.

Pool walking is x64-only because the allocator encodings consulted here are specific
to x64. The rest of the crate remains buildable
for ARM64. Per-session paged heaps are excluded from the initial pool-map scope and
the command reports that limitation. Corrupt or unreadable allocator metadata is
shown conservatively rather than treated as an exploitable condition.

## Modules

| Module | Purpose |
|---|---|
| `dbgeng` | Debug sessions, execution control, breakpoints, symbols, modules, dumps, and traces. |
| `pool` | Kernel pool walking, tag search, and the `!dbgscope.poolmap` extension behind it. |
| `heap` | Version-aware queries over user-mode Segment Heaps. |
| `allocator` | Layout provenance and VS semantic families shared by the two walkers. |

## Usage Sketches

```rust
use dbgscope::dbgeng::DebugEngine;

let engine = DebugEngine::new();
engine.open_dump(r"C:\dumps\MEMORY.DMP")?;
for module in engine.modules()? {
    println!("{} {:#x}", module.name, module.base);
}
```

```rust
use dbgscope::pool::query;

// `false` converts into a PoolWalk meaning "reuse any snapshot cached for this
// target"; `true` rebuilds. Either picks up DEFAULT_WALK_BUDGET.
let answer = query::find_tag(&engine, "Pipe", None, false)?;
println!(
    "{} spans, complete={}",
    answer.found.len(),
    answer.walk.coverage.complete()
);
```

For a debugger smoke test, see `examples/kdtest.rs`:

```bash
cargo run --example kdtest -- "net:port=50000,key=w.x.y.z"
```

## CI

The repository uses Windows-only GitHub Actions workflows:

| Workflow | What it does |
|---|---|
| `ci.yml` | Runs `cargo fmt --all -- --check`, `cargo build --verbose`, and `cargo nextest run --verbose` on `windows-latest` and `windows-11-arm`. |
| `coverage.yml` | Runs instrumented `cargo test`, generates LCOV with `grcov`, and uploads to Codecov. |
| `miri.yml` | Runs `cargo miri test --verbose` on nightly with `-Zmiri-disable-isolation -Zmiri-ignore-leaks`. |

## Contributing

Use `rustfmt` defaults and keep unsafe Windows FFI blocks small. Add focused unit tests next to the code under `#[cfg(test)]`; existing test names use `test_*`. Commit subjects use lowercase prefixes such as `fix:`, `feat:`, `docs:`, `style:`, `refactor:`, `test:`, `perf:`, and `chore:`.
