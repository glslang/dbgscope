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
- **Commands & events**: `execute_command`, `wait_for_event`, `execute_and_wait`, `settle`; output is captured through `OutputCallbacks` (an `IDebugOutputCallbacks` impl).
- **Nothing runs on an engine with no debuggee, and that is a safety property rather than a policy.** Driving DbgEng with no target faults *inside* it — a `STATUS_ACCESS_VIOLATION`, which is a structured exception `catch_unwind` cannot trap, so it takes the host process down instead of failing the call. Measured twice on dbgeng 10.0.26100.1: on an engine whose debuggee had just exited, and on a **fresh** one that never had a target, which is what says the trigger is the missing debuggee rather than the departure. So `refuse_without_a_debuggee` guards every road in — `execute_command`, `execute_command_bounded`, `execute_and_wait`, `run_to_address` — and it cannot be narrowed to text that looks like execution control, because an alias, a `.if` branch and `dx …ExecuteCommand("g")` all reach execution without saying so. The one exception is `execute_fixed_command`, for this crate's own literals: `sxe ibp` arms the initial break *before* a target exists, so guarding it would refuse every `launch_process` and `attach_process` on the machine. Nothing a caller supplied may go through it.
- **A target that ends is not a failure.** A debuggee running to completion during a wait leaves `WaitForEvent` answering `E_UNEXPECTED` ("Catastrophic failure", which names nothing) and `GetExecutionStatus` reading `DEBUG_STATUS_NO_DEBUGGEE` — with `GetNumberProcesses`, `GetCurrentProcessSystemId` and `GetExitCode` all failing beside it and `.lastevent` answering `<no event>`, so the status is the only one of them that says anything. `execute_and_wait` and `settle` report it as `CommandRun::target_gone` and `run_to_address` as `RunToOutcome::TargetGone`, each **keeping the output the run captured**: the pump is where the module loads, the breakpoint banner and an embedded script's prints arrive, and on the run that ends the target there is no successor to print them again.
- **Symbols/memory**: `set_symbol_path`, `reload_symbols`, `read_memory`, `registers`.
- **Where the debugger is**: `instruction_pointer`, `current_thread_system_id` and `current_processor` — the three facts a stop is reported by, typed rather than parsed out of `~.`, whose text is one shape for a user-mode thread and another for a kernel processor. `current_processor` answers `None` for *no processor number applies here* — a user-mode target, a dump of one and a TTD trace have none by construction, which is the whole of the common case, and a kernel target answers `None` only if the engine will not map its current thread to any processor it says it has; `is_kernel_target` is what separates the two. It is **not** an answer about the register context: `.thread` and `.trap` change which context the debugger displays without changing which processor it is stopped on, so this still names that processor — which is the honest answer, since the CPU is where the break is. It resolves through `GetThreadIdByProcessor` rather than reading the current thread index as a processor number: in kernel mode the two coincide, but that is an inference about the very mapping being asked about. The index is *tried first* — one call in the ordinary case, since the scan's cost over a KD wire is DbgEng's business and this runs after every stop — and it is that same call which confirms it, so a wrong guess falls through to the scan rather than being believed.
- **Breakpoints**: the `Breakpoint<'a>` RAII type (borrows the engine), plus `BreakpointCallback` and `DebugEventContextCallbacks` for event-driven breakpoint handling.
- **Scope**: `scope()` / `set_scope()` and the `ScopeGuard<'a>` RAII type, over `IDebugSymbols3::GetScope`/`SetScope` — for running a command that moves the debugger's scope (measured: `!analyze -v` leaves it at the target's default, discarding a frame or `.ecxr` context the caller had selected) without the session ending up somewhere else. `GetScope` does **not** report the size of the context blob it wants: it rejects a buffer smaller than the target's `CONTEXT` and accepts any larger one, so the ask walks `SCOPE_CONTEXT_SIZES` upward. A scope carries the target identity it was read from and is refused rather than applied to a later target. `examples/scope_restore.rs` re-validates all of it against a dump.
- **Ending a session is three different things, and the choice is per *process*, not per session.** `end_session` (and `Drop`, which mirrors it) ends passively — which for a process this engine *launched* means the kernel takes it, since a passive end destroys the debug port and `DebugSetProcessKillOnExit` defaults to true. Two exceptions. A **live kernel** is resumed and actively detached, or it stays frozen at its last break with one CPU halted and the rest spinning. And every user-mode process this engine **attached** to is detached individually (`DetachCurrentProcess`) *before* the session ends, or the same passive end kills it — somebody else's service, taken down by a debugger that was only looking. **Per process because DbgEng holds several user-mode targets at once** (`|` lists them, and says `attach` or `create` against each): `EndSession` takes one flag for the whole session, so no choice of flag can both keep an attached process and take a launched one. Provenance is a set of pids the openers record (`claim_attached`), because the API cannot be asked — `GetDebuggeeType` answers `DEBUG_CLASS_USER_WINDOWS` / `DEBUG_USER_WINDOWS_PROCESS` for a launch and an attach alike, and `|` knows but that is text. The walk is by engine id from `GetProcessIdsByIndex`, so a recorded pid the session no longer holds simply does not match and needs no separate staleness check; `session_processes` answers empty with no debuggee, because `GetNumberProcesses` fails `E_UNEXPECTED` there and would turn "the program had already finished" into a failed teardown. Failures are per process and **reported without stopping the teardown**, because this is what a client's disconnect runs: a session that will not close is worse than a debuggee that was killed, and a caller told "released" would never go and look. `bc *` first, or an `int3` this engine patched in stays patched in a process that goes on running.
- **Opening a target is two steps, not one**: each of the four openers above is a thin `x_begin()? .wait()`. `x_begin` performs only the side effect that creates or claims the target and hands back a `PendingTarget` guard; `PendingTarget::wait` completes the initial break. The split exists so a caller can tell "nothing happened, retry is clean" from "the target exists and only the wait failed" — opposite recoveries, since re-running the second spawns a second process, attaches twice, or re-dials a live KD link. **Deferred input buffers belong to the engine, not the guard** (`DebugEngine::deferred_inputs`). `CreateProcessWide` defers the spawn and reads the command line at the *next* `WaitForEvent` — whichever call makes it — and a kernel dial behaves the same way, so a buffer owned by `PendingTarget` would be a use-after-free the moment the guard was dropped without waiting, which `#[must_use]` cannot prevent. Parking them on the engine instead makes dropping a guard safe and **non-blocking**: it forfeits the initial-break wait but cancels nothing, and the target still materializes at the next wait. Driving the wait from `Drop` instead was tried and rejected — on a kernel attach whose link is still coming up it can block with *no* bound, since `SetInterrupt` cannot cancel that wait. The buffers are released only once `end_session` confirms teardown. `examples/split_open.rs` re-validates the user-mode paths, including a guard dropped before the engine is pumped.

When touching this module, mind the `owns_session` invariant, the stdout-isolation rationale, `PendingTarget`'s buffer ownership, the per-opener teardown and the no-debuggee guard above — all five are load-bearing and documented inline.

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

- `examples/session_fuzz.rs` — randomised command sequences against a live session, checking after every step that the engine either still holds a target and answers or says it holds none. Seeded, so a failing sequence replays. Run it after touching anything in the wait/settle/guard seam: at seed 1 it finds the pre-fix half-dead session in 4 rounds of 8, and 150 rounds of 14 steps are clean on the fix
- `README.md` — user-facing overview, the `!dbgscope.poolmap` extension, and usage sketches
- `.cursor/rules/*.mdc` — Cursor editor rules; they defer to this file for build commands and the module map
