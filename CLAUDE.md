# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`dbgscope` is a Rust library (edition 2024) giving typed access to a WinDbg/DbgEng debug session, and allocator walkers built on one. Two layers: `dbgeng` opens and drives a target (live kernel over KD, local kernel, launched or attached user-mode process, crash dump, TTD trace) and answers in values rather than in `r`/`lm`/`bl` text; `pool` and `heap` walk the kernel pool and the user-mode Segment Heap on top of that session, sharing their page-segment/LFH/VS/backend decoding.

The library is Windows-only by design: `src/lib.rs` exports `allocator`, `dbgeng`, `heap` and `pool` unconditionally, and they call the `windows` crate APIs directly without `#[cfg]` gating. It is not designed to compile on other platforms.

The exploitation half of this crate — shellcode, ROP, process injection, win32k wrappers, pool spraying — left for `win-kexp`. Nothing here depends on it, and nothing here should grow back toward it: this crate reads and drives a debug session, it does not exploit one.

## Commands

```bash
# Build
cargo build --verbose

# Format check (required by CI)
cargo fmt --all -- --check

# Auto-format
cargo fmt --all

# Run tests (preferred — matches CI)
cargo nextest run --verbose

# Run a single test by name
cargo nextest run test_find_gadget_offset

# Standard test runner (alternative)
cargo test
```

## Architecture

### Module Map

| Module | Purpose |
|---|---|
| `src/lib.rs` | Crate root; declares the public modules below |
| `src/dbgeng.rs` | Windows Debug Engine (DbgEng) integration — see below |
| `src/pool.rs`, `src/pool/` | Kernel pool walking: decode, index, layout, query, render, snapshot |
| `src/heap.rs` | Version-aware queries over user-mode Segment Heaps |
| `src/allocator.rs` | Layout provenance and VS semantic families shared by both walkers |
| `src/pool_extension.rs` | The `!dbgscope.poolmap` WinDbg extension exports; this is what `crate-type = ["cdylib"]` is for |

### Debug Engine (`src/dbgeng.rs`)

`DebugEngine` wraps the DbgEng COM interfaces (`IDebugClient6`, `IDebugControl4`, `IDebugDataSpaces4`, `IDebugSymbols3`). It can either create and own its own session (`DebugEngine::new` / `Default`, via `DebugCreate`) or borrow an existing WinDbg client (`from_windbg_client` / `from_client_interface`). The `owns_session` flag governs whether `Drop` ends the session — a borrowed WinDbg client is never torn down. Errors are modeled with `DbgEngError` (`thiserror`).

Key capabilities:
- **Kernel debugging**: `attach_local_kernel`, `attach_kernel(connection_string)`.
- **Live targets**: `launch_process` (launches with `DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE`), `attach_process(pid)`. `CREATE_NEW_CONSOLE` is deliberate — a console target must not inherit the host's stdout, which may be an MCP/JSON-RPC channel.
- **Post-mortem**: `open_dump(path)`, `open_trace(path)`.
- **Commands & events**: `execute_command`, `wait_for_event`, `execute_and_wait`; output is captured through `OutputCallbacks` (an `IDebugOutputCallbacks` impl).
- **Symbols/memory**: `set_symbol_path`, `reload_symbols`, `read_memory`, `registers`.
- **Breakpoints**: the `Breakpoint<'a>` RAII type (borrows the engine), plus `BreakpointCallback` and `DebugEventContextCallbacks` for event-driven breakpoint handling.
- **Scope**: `scope()` / `set_scope()` and the `ScopeGuard<'a>` RAII type, over `IDebugSymbols3::GetScope`/`SetScope` — for running a command that moves the debugger's scope (measured: `!analyze -v` leaves it at the target's default, discarding a frame or `.ecxr` context the caller had selected) without the session ending up somewhere else. `GetScope` does **not** report the size of the context blob it wants: it rejects a buffer smaller than the target's `CONTEXT` and accepts any larger one, so the ask walks `SCOPE_CONTEXT_SIZES` upward. A scope carries the target identity it was read from and is refused rather than applied to a later target. `examples/scope_restore.rs` re-validates all of it against a dump.
- **Opening a target is two steps, not one**: each of the four openers above is a thin `x_begin()? .wait()`. `x_begin` performs only the side effect that creates or claims the target and hands back a `PendingTarget` guard; `PendingTarget::wait` completes the initial break. The split exists so a caller can tell "nothing happened, retry is clean" from "the target exists and only the wait failed" — opposite recoveries, since re-running the second spawns a second process, attaches twice, or re-dials a live KD link. **Deferred input buffers belong to the engine, not the guard** (`DebugEngine::deferred_inputs`). `CreateProcessWide` defers the spawn and reads the command line at the *next* `WaitForEvent` — whichever call makes it — and a kernel dial behaves the same way, so a buffer owned by `PendingTarget` would be a use-after-free the moment the guard was dropped without waiting, which `#[must_use]` cannot prevent. Parking them on the engine instead makes dropping a guard safe and **non-blocking**: it forfeits the initial-break wait but cancels nothing, and the target still materializes at the next wait. Driving the wait from `Drop` instead was tried and rejected — on a kernel attach whose link is still coming up it can block with *no* bound, since `SetInterrupt` cannot cancel that wait. The buffers are released only once `end_session` confirms teardown. `examples/split_open.rs` re-validates the user-mode paths, including a guard dropped before the engine is pumped.

When touching this module, mind the `owns_session` invariant, the stdout-isolation rationale, and `PendingTarget`'s buffer ownership above — all three are load-bearing and documented inline.

## Conventions

### Rust

- `snake_case` for functions/variables, `PascalCase` for types/structs
- Custom error types use `thiserror`; prefer `Result`/`Option` over panics in library code
- Windows API via the `windows` crate (currently `0.62.2`); add required feature flags in `Cargo.toml` under `[dependencies.windows]`
- `unsafe` is expected at Windows FFI boundaries; keep unsafe blocks minimal and localized
- Key dependencies: `windows`/`windows-core` (FFI), `thiserror` (errors), `hex`

### Git Commit Prefixes

`fix:`, `feat:`, `perf:`, `docs:`, `style:`, `refactor:`, `test:`, `chore:` — lowercase, concise summary line.

## CI

Three workflows run on **Windows runners only**:
- **ci.yml**: fmt check → build → `cargo nextest run` on both `windows-latest` (x64) and `windows-11-arm` (ARM64) with stable Rust
- **coverage.yml**: grcov + LLVM instrumentation → Codecov upload
- **miri.yml**: `cargo miri nextest run` on nightly with `MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-ignore-leaks"`, plus a `cargo miri test --doc` step for the doctests nextest cannot run. **It does not run on pull requests** — it is the longest job here by a wide margin (9 minutes median against ci.yml's 1) and had never failed in a hundred runs, so it runs on the merge to `main`, weekly for toolchain drift, and on `workflow_dispatch` for a branch worth checking before it lands. A green PR therefore says nothing about Miri; run it by hand when a change is one Miri would have something to say about. The workflow's own header records why a path filter was measured and rejected

There is no build script and no assembler step: both left with the exploitation half.

## Related Docs

- `README.md` — user-facing overview, the `!dbgscope.poolmap` extension, and usage sketches
- `.cursor/rules/*.mdc` — Cursor editor rules; they defer to this file for build commands and the module map
