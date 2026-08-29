# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `DebugEngine::current_thread_system_id` and `DebugEngine::current_processor` — which thread the
  engine's answers are about, and which of a kernel target's processors it is on. Typed rather
  than parsed out of `~.`, whose text is one shape for a user-mode thread, another for a kernel
  processor, and a third when there is no thread context at all. `current_processor` answers
  `None` for *no processor number applies here*, which a user-mode target and a kernel target
  pointed at an arbitrary `ETHREAD` both are; it resolves through `GetThreadIdByProcessor` rather
  than reading the current thread index as a processor number, so nothing is inferred about the
  mapping it is asking about. Exercised beside `~.` in `examples/typed_context.rs`.

## [0.1.0] - 2026-08-29

First release. `dbgscope` gives typed access to a WinDbg/DbgEng debug session, and kernel-pool
and user-heap walkers built on one. The organising rule, and the thing to know before reading
the API, is that every answer carries what the answering cost — see
[Unknown, not absent](docs/unknown-not-absent.md).

### Added — debug sessions

- `DebugEngine` over `IDebugClient6` / `IDebugControl4` / `IDebugDataSpaces4` /
  `IDebugSymbols3`, owning its own session (`new`, `Default`) or borrowing an existing WinDbg
  client (`from_windbg_client`, `from_client_interface`, and their `try_` forms). `owns_session`
  governs teardown, so a borrowed client is never ended.
- Openers for every target DbgEng handles: `attach_kernel`, `attach_local_kernel`,
  `launch_process`, `attach_process`, `open_dump`, `open_trace`. The two post-mortem openers
  commit the session and leave the pump to the caller: the engine has no current process or
  thread — and `GetNumberRegisters` answers `0x8000FFFF` — until `wait_for_event` has run.
- `connect(remote_options)` for an existing debugging server, so an extension can load out of
  process.
- **Two-step opening** on the four *live* openers, each a thin `x_begin()?.wait()`. `x_begin`
  performs only the side effect that creates or claims the target and returns a `PendingTarget`;
  `wait` completes the initial break. The split lets a caller distinguish "nothing happened,
  retry is clean" from "the target exists and only the wait failed" — opposite recoveries, since
  re-running the second spawns a second process, attaches twice, or re-dials a live KD link.
  Dropping a guard is safe and non-blocking: deferred input buffers are parked on the engine
  rather than the guard, because `CreateProcessWide` reads the command line at the *next*
  `WaitForEvent`.
- **Per-process teardown.** DbgEng holds several user-mode targets at once and `EndSession`
  takes one flag for the whole session, so provenance is recorded per pid at open time. A
  process this engine *attached* to is detached individually before the session ends — otherwise
  a passive end kills somebody else's service. A live kernel is resumed and actively detached,
  or it stays frozen at its last break with one CPU halted. Failures are per process and
  reported without stopping the teardown.
- `launch_process` uses `DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE`, so a console target
  cannot inherit a host's stdout — which may be a JSON-RPC channel.

### Added — execution control

- `execute_command_bounded`, `execute_and_wait`, `settle` and `run_to_address`: bounded waits
  with a condition-variable watchdog behind them. The watchdog stops the moment it is disarmed
  rather than at the end of a poll interval, so a bound costs nothing until it is reached.
- `CommandRun { output, cut_short, target_gone }` — the output *and* whether the command
  finished. A `String` alone cannot answer "did this run?", and an `Err` would discard the
  output, which on an interrupted search is all there was.
- `Interruption::Deadline { after_ms }` distinguished from `Interruption::OnRequest`, because
  the advice differs and only the first needs saying. The origin is decided by the watchdog's
  own flag, not by the shared interrupt bit that the watchdog also sets.
- `RunToOutcome` names four endings — `Hit`, `StoppedElsewhere { stopped_at }`, `Timeout`,
  `TargetGone` — rather than a boolean.
- `InterruptHandle`: a `Send + Sync` handle that Ctrl+Breaks an engine from another thread, over
  `SetInterrupt`, the one DbgEng call documented as safe there. It holds an owned interface
  reference, so it may outlive the `DebugEngine` it came from.
- **A target that ends is an ending, not a failure.** A debuggee running to completion is
  reported as `CommandRun::target_gone` / `RunToOutcome::TargetGone`, each keeping the output the
  run captured — the module loads, the breakpoint banner, an embedded script's prints, none of
  which a successor will print again. It is terminal, and callers are told so.
- **Nothing runs on an engine with no debuggee.** Driving DbgEng without a target faults inside
  it with a `STATUS_ACCESS_VIOLATION` that `catch_unwind` cannot trap, so `execute_command`,
  `execute_command_bounded`, `execute_and_wait` and `run_to_address` all refuse first.

### Added — typed session state

- `register_values` returning `RegisterValue`, decoded once from `DEBUG_VALUE`'s own tag:
  `Int`, `Float`, `Bytes` for x87 and vector registers that no `f64` can hold, and
  `Unavailable` for state a minidump does not carry — which is not `0`.
- `register_descriptions` for the whole register description rather than one flag of it.
- `modules`, `unloaded_modules`, `module`, `module_at`, `module_identity`, `module_pdb`,
  `module_symbol_file`. `SymbolKind` keeps `Deferred` separate from `None` and preserves an
  unrecognised provider as `Other(u32)`; `has_type_info()` answers the narrow question the pool
  walker actually asks.
- `stack_frames`, `bug_check` as the engine's five values, `breakpoints` as `BreakpointInfo`,
  `disassemble` as `Instruction` records with a line the split does not recognise kept whole
  rather than guessed at.
- Scope save and restore: `scope`, `set_scope`, `scope_guard` and the `ScopeGuard` RAII type,
  for running a command that moves the debugger's scope — measured: `!analyze -v` discards a
  frame or `.ecxr` context the caller had selected. A `Scope` carries the target identity it was
  read from and is refused rather than applied to a later target.
- Memory and symbols: `read_memory`, `valid_virtual_region`, `symbol_offset`, `type_id`,
  `type_size`, `field_offset`, `field_type_and_offset`, `field_names`, `set_symbol_path`,
  `append_symbol_path`, `reload_symbols`.
- Breakpoints: the `Breakpoint<'a>` RAII type, `BreakpointCallback`, and
  `DebugEventContextCallbacks` for event-driven handling.

### Added — kernel pool

- `pool::query`: `find_tag`, `chunk_at` with immediate neighbours, `tag_census`,
  `snapshot_report`, and cache invalidation hooks for a host that resumes or replaces a target.
- `PoolAnswer<T>` pairs every answer with the `PoolSnapshotReport` of the walk it came from, so
  a count and a coverage figure can never be drawn from two different walks — which is what
  happens otherwise, since an incomplete walk is deliberately not cached.
- `WalkCoverage { Complete, BudgetExpired, Partial }`, computed in one place from the walk's own
  two bits. Not a `bool`, because a walk that ran out of time reaches more of the pool if given
  more, and one that met unreadable regions reports the same gaps however long it runs.
- `PoolWalk` with `cached()`, `refreshed()`, `within(Duration)` and `unbounded()`, plus
  `impl From<bool>` so existing `refresh: bool` call sites are unchanged and pick up
  `DEFAULT_WALK_BUDGET` (120s). A walk that runs out of its budget is not an error: it returns
  the chunks it reached with the coverage saying so.
- `PoolDiagnostics` groups complaints by shape — the message with every number standing in for
  itself — keeping `DIAGNOSTIC_EXAMPLES` (8) verbatim per shape and the totals as numbers.
  `emitted()` describes the walk; `examples().len()` describes the struct, and on a busy target
  the two differ by two orders of magnitude.
- `WalkStalls`, `refused_chunks` and `unplaced_bytes` size what conservative decoding cost, so a
  refusal to guess is auditable rather than invisible.
- Both tag forms: one to four ASCII bytes, or the raw form `0x` plus eight hex digits in memory
  order, so it reads in the same direction as the printed tag (`Tgsm` is `0x5467736d`). The two
  cannot collide — the raw form is exactly ten characters and a printed tag at most four.
  `display_is_ambiguous` and `display_round_trips` separate the two distinct ways a rendering
  fails, and `tag_label` is the one rule every output site prints through.
- `PoolKind`'s eight variants are not collapsed to paged/nonpaged, because crossing one of those
  boundaries creates false holes. `PoolState::Unreadable` is distinct from allocated and from
  the two free states, and `chunk_at` returns `Ok(None)` for "not covered by the snapshot",
  which is a different answer from "it is a free hole".
- `find_tag` indexes allocated chunks only: a freed chunk's tag is not reliably preserved by the
  allocator, so returning freed chunks by tag would be inventing information.

### Added — user-mode Segment Heap

- `heap`: `list`, `allocations`, `chunk_at`, `census`, `diagnostics`, `diagnostics_for_heap`,
  with `HeapWalk` mirroring `PoolWalk` and `HeapAnswer<T>` mirroring `PoolAnswer<T>`.
- `HeapScope` names the roots that were skipped and why — `nt_heaps_skipped`,
  `unknown_heaps_skipped`, `unreadable_heaps_skipped` — rather than reporting only the ones that
  worked.
- Shared page-segment, LFH, VS, backend and large-allocation decoding with the pool walker,
  because the two allocators are the same machinery either side of the ring boundary.
- `allocator::LayoutProvenance` carries the image, PDB and a fingerprint of every resolved type
  size and field offset actually used — deliberately with no build-number policy in it.
- `requested_size` is `Option<u64>`, set only where allocator metadata validates it, rather than
  guessed from capacity.

### Added — WinDbg extension

- `!dbgscope.poolmap`, built from the `cdylib` crate type, over the same walker and the same
  caches as `pool::query`, so the interactive and programmatic entry points cannot drift apart.
- `-tag` (either form), `-paged` / `-nonpaged`, `-refresh`, and an address argument for detail
  on the allocation or hole containing it.
- DML colours and clickable address links where WinDbg accepts DML; meaningful ASCII glyphs and
  a legend where it is stripped or the output is captured as plain text.
- The extension lets a walk run to completion, because there is an operator at a prompt who can
  Ctrl+Break. `pool::query` cannot assume anyone is watching the clock, which is why its walks
  carry a budget — and a host that *is* watching can cancel one through `interrupt_handle()`,
  which the walk polls and reports as `PoolQueryError::Interrupted`.

### Known limitations

- **Windows only.** The public surface calls Windows APIs with no `#[cfg]` gating; the crate is
  not designed to build elsewhere. docs.rs is configured for the MSVC targets accordingly.
- **Pool walking is x64 only**, because the allocator encodings it consults are. The rest of the
  crate builds for ARM64, and CI covers both.
- **Windows 10 19H1 or later** allocator algorithms, and full private type information for `nt`.
  Symbols must be on the debugger host — PDBs are never fetched from a target over KD — and
  resolving them needs `msdia140.dll` beside the engine. Without it, a kernel dump presents not
  as missing symbols but as memory reads failing.
- **A live-kernel walk is normally incomplete.** Paged pool is partly on disk, and a page the
  memory manager has paged out cannot be read through the debugger either.
- **`KERNEL_ATTACH_WAIT_MS` bounds less than it looks like.** The watchdog works by
  `SetInterrupt`, which only reaches a target that has *connected*, so it caps a
  connected-but-unresponsive target and nothing else. One that never dials in — powered off,
  wrong key, not booted with `bcdedit /debug on` — blocks past the bound indefinitely.
- **Snapshots are snapshots.** The walkers examine current allocations, reusable frees and
  cached/delay-free spans while the target is stopped. They install no allocation breakpoints
  and reconstruct no history.
- **Per-session paged heaps** are outside the initial pool-map scope, and the command says so.
- **Pre-1.0.** The `dbgeng` surface is large and expected to change; breaking changes may land
  in any `0.x` release.

[Unreleased]: https://github.com/glslang/dbgscope/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/glslang/dbgscope/releases/tag/v0.1.0
