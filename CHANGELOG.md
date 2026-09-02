# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Breakpoints can be **set**, not only listed. `DebugEngine::set_breakpoint` and
  `set_breakpoint_bounded` take a `BreakpointSpec` — a location (`BreakpointAt::Address` or
  `::Expression`), an optional command, match thread, pass count, one-shot flag, and a `DataWatch`
  that makes it a data breakpoint (`ba`) — and answer with a `BreakpointSet` carrying the new
  breakpoint **as the engine holds it**, read back through the same getters `breakpoints()` uses.
  `remove_breakpoint` and `enable_breakpoint` take an id, as `bc`/`be`/`bd` do. Previously the only
  write path was the `execute` text hatch, so a caller building `bp <expr> "<command>"` had to
  escape a quoted string inside a `;`-separated command line and then screen the operand for both
  characters; a command now arrives as a parameter, and `examples/breakpoint_probe.rs` checks that
  one containing both survives byte-identical.
- `set_breakpoint_bounded` bounds the **location resolve**, the one step that can block: a symbolic
  location is evaluated eagerly, so on a module whose PDB is not local it is a symbol-server fetch
  with the engine held. Measured on dbgeng 10.0.29547.1002 — 2445 ms for a cold
  `KERNELBASE!CreateFileW` against an empty store, 151 ms warm, 0 ms for an address, and 0 ms to
  defer when the module is absent. `SetInterrupt` reaches it, so the bound is real; and because a
  break is otherwise **silent** — it returns `Ok` with a breakpoint, having abandoned the symbol
  load and left the module on export symbols for the rest of the session — the result carries
  `cut_short` rather than being a bare `Result<(), _>`.
- `OnExisting` says what to do about breakpoints already at the resolved address. The engine
  deduplicates nothing: three typed sets on one address leave three breakpoints. What deduplicates
  is the command layer — `bp` and `bu` resolve and then remove whatever is there, printing
  `breakpoint N redefined` — keyed by the resolved address, so a *deferred* expression duplicates
  freely. `OnExisting::Replace` reproduces that as a value, reporting the removed ids as
  `BreakpointSet::replaced`; `Add` is the default, since a primitive should not destroy what the
  caller did not name. Worth choosing deliberately: duplicates at one address stop the target
  **once** but activate every breakpoint there, so each one's command runs, and removing one by id
  leaves the address armed by the others. Nothing is removed until the replacement is fully
  configured and certain to be armed, so a call that fails part-way leaves the caller's existing
  breakpoints alone rather than handing them an error and an address they had already lost.
- `BreakpointInfo::data` reports a data breakpoint's watched region — what access, over how many
  bytes — read through `GetDataParameters`. The read side could previously say a breakpoint *was* a
  data breakpoint and not what it watched, which left the new read-back unable to confirm the half
  of a spec most worth confirming. `DataAccess::Other` keeps an access combination this build does
  not name rather than folding it into a plausible neighbour, as `BreakpointKind::Other` does.
- `examples/breakpoint_probe.rs`, the record behind all of the above.

### Removed

- The public `Breakpoint<'a>` type, which had no caller in `src/` or `examples/` and was a trap for
  anyone who found it: built on the v1 `IDebugBreakpoint` where the read path uses v2, offering no
  setter but `set_offset_expression`, and panicking in three of its four methods — `enable`'s
  message was a copy of `set_offset_expression`'s. A breakpoint is created *disabled and at address
  zero*, so its documented use left a breakpoint on the null page that never fired, and the method
  that would have armed it was one of the three that panicked. Superseded by `set_breakpoint` and
  the id-taking `remove_breakpoint`/`enable_breakpoint`; the private `ScopedBreakpoint` is now the
  only wrapper over a raw breakpoint object, so there is one answer to who removes a breakpoint and
  when rather than two that disagreed.

### Changed

- `launch_process` launches with `CREATE_NO_WINDOW` instead of `CREATE_NEW_CONSOLE`, so a launched
  console target no longer opens a window on the desktop and takes the foreground with it. The
  guarantee the old flag was there for is unchanged and is what `CREATE_NO_WINDOW` also provides:
  the target gets a console of its **own**, so its prints cannot reach the launching process's
  stdout — which for an MCP host is its JSON-RPC channel. Measured with a `STARTUPINFO` carrying no
  `STARTF_USESTDHANDLES`, the shape DbgEng uses: with no flag at all the target's `echo` lands in
  the launching process's stdout, and with either console flag it does not, `bInheritHandles` either
  way. What is lost is a debuggee's console output being readable on the desktop — it was never
  captured, and a caller that wants it can redirect (`cmd.exe /c prog > file`) rather than have
  every launch open a window on the chance someone is looking. A driver launching targets
  repeatedly made the machine unusable ([#129](https://github.com/glslang/dbgscope/issues/129)).
  `test_a_launched_target_has_a_console_of_its_own_and_no_window` asserts three things: that the
  target's console is not this process's, that it *has* one (`mode con` in the target has to report
  `Status for device CON`, which is what separates this flag from `DETACHED_PROCESS`), and that it
  owns no visible window. The last is a negative, so it is calibrated against a control the test
  spawns with `CREATE_NEW_CONSOLE`; a host where that control shows no window either fails the test
  rather than skipping the check, since by then the other two have been made.

### Fixed

- A **user-mode open now waits for its own target**, rather than for one event. `launch_process`
  and `attach_process` completed on a single `WaitForEvent`, which is one event and not necessarily
  theirs: `CreateProcessWide` defers the spawn into that wait, and an engine already holding a
  target can return from it on *that* target's event instead. Measured
  (`examples/deferred_arrival.rs`, 40 rounds under CPU load): an `AttachProcess` break-in whose
  injected thread is slow to be scheduled lands a whole wait late, and the `launch_process` after
  it spends its only wait on that break — returning `Ok` with its process absent from the session,
  3 times in 40, and 0 in 40 on a quiet machine. `PendingTarget::wait` now pumps until the event it
  stopped on belongs to the process the open created or claimed, within the same `LIVE_WAIT_MS`
  bound for the whole open; the event is queued rather than lost, so it arrived on the very next
  wait every time it was observed. **Membership in the session is not the terminal condition** —
  `cpr` is an ignored filter, so a process is registered when its create event is processed and its
  initial breakpoint arrives later, and a competing break in between would leave the open's process
  listed but not where the open promised to leave it — so the pump waits for the process to have
  **stopped**. That is read from a record the engine keeps (`stopped_on`, written by both waits
  from `GetLastEventInformation`, by engine id, which
  `test_the_last_event_names_its_process_by_engine_id` pins against `session_processes`) rather
  than from that call in the moment: it is a single session-wide slot every later event
  overwrites, so read directly it answers the same way for a target still coming and for one that
  stopped before its guard was waited on. A wait that cannot evaluate its own postcondition — a
  snapshot that would not read, a status or process list that would not answer — returns as it did
  before, and only a process demonstrably not in the session by the bound answers the new
  `DbgEngError::LiveTargetTimeout`; one that is there but was never seen to stop ends the wait
  `Ok`, because "not observed to stop" is not "never arrived". A session holding *nothing* is
  absence rather than a question that could not be put, which is a mapping and not a road: a wait
  with no debuggee fails (`E_UNEXPECTED`, 200µs) instead of expiring, so an open never reaches its
  bound holding nothing — measured, and pinned alongside the mapping so that an engine which
  starts expiring instead fails a test rather than a caller. The record is cleared when the session
  is replaced *and* when it is ended, since the next session hands engine ids out from zero again
  — two `attach_process` calls to one pid on one engine would otherwise have the second inherit
  the first's answer. With the fix, 0 short in 40 rounds under the same load. Reported as
  [dbgscope#128](https://github.com/glslang/dbgscope/issues/128), where it had been failing
  `test_a_mixed_session_comes_apart_by_where_each_process_came_from` on CI's coverage job.
- A `PendingTarget` **waited after something else pumped its target in** no longer waits for the
  next event. The guard's own docs describe dropping one and letting the target materialize at the
  next `WaitForEvent` from any source; a guard still held when that happened made its wait anyway,
  which resumes an arrived target and waits out whatever comes next. Measured across the fix:
  **29.36s and `E_UNEXPECTED`** — the debuggee outran the bound and took the session with it —
  against **8.6µs and `Ok`**. Neither opener lists its process before the wait that completes it
  (measured), so the ordinary open still waits exactly once. The same measurement with a *second*
  target arrived since — which overwrites the one slot recording where the engine stopped — is
  29.4s and `E_UNEXPECTED` when the ask reads that slot against single-digit µs when it reads the
  record, and is the argument for `stopped_on` existing at all.
- `a_watchdog_disarmed_before_its_deadline_costs_nothing` measured the machine rather than the
  watchdog, and failed on the coverage job of a docs-only PR. Three things were wrong with it, and
  the first meant it was not testing the property at all: armed and disarmed back to back, the
  watchdog's thread usually had not run yet, so it saw the flag at the top of its loop and returned
  without ever reaching a wait — **the test passed with the condvar reverted**. The timing is now
  taken on a watchdog whose deadline has passed, after its own counter says it fired, so the parked
  thread is a **reading rather than an assumption** (a fixed sleep only makes an unparked thread
  unlikely, and a runner slow enough to matter is where that assumption fails). It bounds the
  disarm by `WATCHDOG_REPEAT` — the poll interval the condvar replaced — halved, rather than by an
  absolute 50ms, and takes the **median** of five rounds: the maximum measures the machine, and the
  minimum lets one stray round excuse a regression. The never-fires half is asserted separately, on
  a watchdog 30s from its deadline, where no handshake is available. Checked both ways: 0.13s
  green, and red against the reverted condvar with all five rounds at 177-182ms.
- `BreakpointInfo::expression`'s documentation described only what `bp` does. A breakpoint whose
  location was set through `SetOffsetExpression` **keeps** its expression beside a resolved address,
  where one set by `bp` has the text discarded once it resolves — so `None` there is not the
  universal case for a live breakpoint. `deferred` is the field that answers whether a breakpoint
  has an address yet.
- `breakpoints()` reads through `GetBreakpointByIndex2`, putting the whole breakpoint path on
  `IDebugBreakpoint2` rather than mixing the two interface versions.
- `examples/session_fuzz.rs` no longer forces its seed odd, which had silently halved what
  `--seed` can name: `Rng::new` did `seed | 1`, so `42` and `43` were one run and `6` and `7` were
  one run. The flag exists so a failing sequence can be reproduced and then *varied*, and a seed
  that aliases another looks like a new sequence while covering nothing new. The forbidden state
  for xorshift64* is zero rather than "even", so that is now the only case handled, and the
  clock-derived default is taken as it comes instead of being forced odd as well. Measured over
  the first 512 seeds, ten corpus draws each: **256** distinct walks before, **512** after. Seeds
  that were already odd — including the `1` this example's notes are written against — walk
  exactly what they walked. Found downstream in
  [windbg-mcp#268](https://github.com/glslang/windbg-mcp/pull/268), which ported this example to
  drive that server's tool surface, where the seed is a small integer someone types while
  scanning.

### Added

- Pool tag queries accept an optional nonzero match threshold. A new walk stops immediately after
  that many in-scope allocated chunks, reports the fired threshold separately from deadline and
  diagnostic truncation, and never caches the intentionally partial snapshot. A complete cached
  snapshot still answers exhaustively without being discarded.

### Added

- `DebugEngine::current_thread_system_id` and `DebugEngine::current_processor` — which thread the
  engine's answers are about, and which of a kernel target's processors it is on. Typed rather
  than parsed out of `~.`, whose text is one shape for a user-mode thread, another for a kernel
  processor, and a third when there is no thread context at all. `current_processor` answers
  `None` for *no processor number applies here* — a user-mode target, a dump of one and a TTD trace,
  by construction — and it is not an answer about the register context, since `.thread` and `.trap`
  change what the debugger displays without changing which processor it is stopped on. It resolves
  through `GetThreadIdByProcessor` rather
  than reading the current thread index as a processor number, so nothing is inferred about the
  mapping it is asking about — the index is tried first, and confirmed by that same call, so the
  ordinary case costs one call rather than one per processor. A lookup that **fails** is not a
  processor that does not match: a match wins whatever else failed, and no match with a failure
  among the lookups is an `Err` rather than an `Ok(None)` that would report absence where the truth
  is unknown. Exercised beside `~.` in `examples/typed_context.rs`.

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
