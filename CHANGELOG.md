# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Exception events are readable as values.** `DebugEngine::last_event` returns a `DebugEvent` —
  kind, engine process and thread, and, when the event carried one, an `ExceptionRecord` with the
  code, flags, faulting address and parameters. That is `.exr -1` typed, and it is the user-mode
  counterpart to `bug_check`: on a target stopped by a fault it is the record that stopped it.
  `ExceptionRecord::parameters` arrives already cut to the record's own `NumberParameters` (and
  clamped to the fifteen slots there are), because the count is the field that tells the two shapes
  of a `0xc0000409` apart — one parameter is the CRT's `abort`, three is WIL's, whose second is the
  `HRESULT` — and a leftover read as a parameter would answer the question wrongly rather than
  cosmetically.
- `DebugEngine::stored_event` returns the event a dump was **written for**, with the register
  context it was written with, as an opaque `ThreadContext`. Unlike `last_event` it does not move:
  it still answers after a caller has stepped, gone, or changed threads. `Ok(None)` where there is
  no stored event — every live target, and every dump not written for a fault, including kernel
  crash dumps, whose bug check `ReadBugCheckData` reads instead. That is read off the engine's own
  refusal (`E_UNEXPECTED`, measured on both) rather than probed for, so a genuine failure still
  reaches the caller as one.
- `DebugEngine::stack_frames_from` walks the stack a recorded context was in, which is what
  `.ecxr; k` produces without `.ecxr`'s effect on the session: the caller's selected thread and
  frame are left exactly where they were, so a triage built on it is still a read. **What makes it
  differ from `stack_frames` is the selected thread and only that** — measured on a two-thread
  fail-fast dump, after `~1s` the other walk returns the parked thread's six frames while this one
  still returns the crash's twelve, while `.frame`, `.cxr` and `.ecxr` move neither, since they
  change the symbol scope and `GetStackTrace` walks from the thread's registers.
- `examples/stored_event_probe.rs`, the measurements behind the three. It also caught the one that
  would otherwise have shipped: `GetStoredEventInformation` does **not** refuse a context buffer
  that is too small the way `GetScope` does. It truncates — offered 716 bytes for an x64 dump it
  writes 716, reports 716 and returns success, and the damage surfaces three calls later when
  `GetContextStackTrace` rejects the truncated context with `E_INVALIDARG`. So the context ladder
  here starts *above* every real `CONTEXT` rather than below it, and grows only on the one signal
  the call gives that there was more to write.
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

- **`unsafe impl Send` and `unsafe impl Sync` for `DebugEngine`** (#136 stage 4). They asserted
  the opposite of what this crate says about its own threading: `SetInterrupt` is the one DbgEng
  call documented as safe from any thread *because the rest of the engine is
  single-thread-affine*, so `Sync` promised concurrent `&self` calls into an engine that cannot
  take them and `Send` promised a move to another thread, which is the same claim one step
  weaker. Neither carried a safety comment, and neither could have been given a true one.

  **Semver-visible, and measured against both consumers before it was made**: removing each and
  building leaves this crate (`--all-targets`, tests and examples included) and windbg-mcp
  compiling unchanged, because both already create the engine on the thread that uses it. A
  consumer that did move an engine between threads is the case this breaks, and it was relying
  on an unsound impl to do it.

  `InterruptHandle` is untouched and is now the crate's only `Send + Sync` type — one
  `SetInterrupt` from anywhere, and nothing else. `deferred_inputs` becomes a `RefCell` rather
  than a `Mutex`, since `&self` now implies one thread. And
  `test_the_engine_does_not_cross_threads_and_the_handle_does` asserts all four bounds, because
  re-adding an `unsafe impl` is one line that compiles and reads as a fix for whatever error it
  silences.

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

- **An arrival is delivered to the open waiting for it, instead of broadcast into a set every
  guard polls.** An opener registers what it is waiting for (`Registered`), the pump routes a stop
  to the first open that wants it and has nothing yet (`Arrivals`), and the entry dies with its
  guard. Stage 3 of [#136](https://github.com/glslang/dbgscope/issues/136).

  What it replaces, `stopped_on`, was an engine-wide set of every `(engine id, system pid)` the
  engine had ever stopped on. Because it outlived the opens that read it, it needed a lifecycle of
  its own — pruned at both openers for pid reuse, cleared where a session is replaced, and cleared
  again where one is ended — and each of those three arrived as a review finding on
  [#133](https://github.com/glslang/dbgscope/pull/133) rather than as a design. None of them is
  needed now: nothing outlives its reader, so nothing can go stale.
  `prune_processes_that_left` is down to the attachment record, which is about the teardown
  decision rather than about an open.

  **Two launches pending at once are told apart**, which `Arrival` documented as an accepted
  ambiguity: a launch is identified by elimination, so the first arrival was new to both snapshots
  and ended both waits. An arrival is now *claimed* by the open it is delivered to, so the second
  launch is still waiting when the next one comes. That fix was weighed and rejected at the time
  because it needed "new engine-wide state, cleared everywhere a session is replaced and pruned for
  pid reuse" — which was the cost of the record it would have joined, and is the cost this shape
  does not have.

  **A claim outlives the open that made it**, for as long as anything is still waiting: when a
  guard goes, the process it was given is inherited by the opens that remain. Without it the
  ambiguity above is closed only while both guards are held: the first launch's target stops
  again, nobody has it claimed any more, and it is absent from the second launch's snapshot because
  it did not exist when that snapshot was taken. Not a lifecycle creeping back in: the claim goes
  when the opens holding it do, where the record this replaces lived for the whole session.

  **The state is per client rather than per wrapper**, in a new `ClientState` held by `Arc` and
  keyed by client pointer in a `Weak` map. Two `DebugEngine`s can be live around one
  `IDebugClient6`, and a `wait_for_event` through one used to complete an open held by the other in
  its own copy of the record alone — the other then read `Listed`, waited again, and spent its
  whole bound on an event that had already happened. That was written down as a known gap for two
  releases; the interrupt scope from stage 2 had the mirror of it and moves into the same `Arc`,
  because it is the same field. A `Weak` map needs no equivalent of `reissue_identity`: a dead entry
  identifies itself, where a stale *identity* costs only a re-read and a stale *arrival* would
  answer `Arrived` for a target that never stopped.

  **`attached_processes` moves with them**, which was not planned and is the sharper of the two
  gaps that placement had. Delivery reads it to keep an attach's process from being claimed by a
  pending launch, and a pump through a second wrapper read an empty set; but an `end_session`
  through a wrapper that did not perform the attach also saw no attachment to detach, so its
  passive end **killed** somebody else's process — the exact failure that record exists to
  prevent, reached through the wrapper boundary. The sentence that used to defend the old
  placement argued that sharing would put the decision "behind an eviction policy" -- true of the
  identity cache, and not of a `Weak` map whose entry dies with the last wrapper holding it.

  **Two more from review, one of them pre-existing.** "Somebody else has this process" is now one
  rule in `Pending::wants`, so `presence` applies it as well as `deliver` did. A second launch was
  otherwise told `Listed` on the strength of a process the first had been given, and `Listed` is
  not `Absent`, so an interrupted wait answered `Ok(())` instead of `LiveTargetInterrupted`.

  And `prune_processes_that_left` no longer drops an attachment that has not joined yet.
  `AttachProcess` joins its process at the next `WaitForEvent`, so between `attach_process_begin`
  and that wait the pid is recorded and the session does not list it. An opener pruning in that
  window dropped the record — after which the teardown treats somebody else's process as one this
  engine launched, and takes it. An attachment now carries whether it has been seen
  (`Attachment::Deferred` / `Joined`), promoted wherever the engine lists the session on its own
  account: the prune, and the pump.

  And a third round on the state that introduced: `Deferred` is kept because a deferred attach has
  not arrived and so cannot have left, but only a listing promotes one — so an `AttachProcess` the
  engine accepted for a process that then exited before the first `WaitForEvent` left a pid
  recorded for the life of the session, where the prune used to bound it. A live open that waits
  out `LIVE_WAIT_MS` and never sees its process now retires the record, which is the only party
  that can say the attach cannot join. Not on an *interrupted* open, which says nothing about
  whether the attach is still coming.

  And a fourth round, both halves of it about the register being shared where it used to be a
  field. `Drop` tears the session down inline rather than calling `end_session`, so it never
  inherited the line that forgets the pending opens — which cost nothing while each wrapper had its
  own register and leaves a stale entry now, first in line for the next launch's stop through a
  wrapper that outlived the owner. And a **claim** now stops excluding once its process leaves the
  session: engine ids are handed back immediately, so a `.detach` and a reattach of the same pid
  reproduce a pair exactly, and a stale claim made the reattach refuse its own stop as somebody
  else's. That is the reuse the old record was pruned for, arriving from the opposite side — where
  a stale entry there made a new open read `Arrived` for a target that had not stopped, a stale
  claim makes it read `Absent` for one that had.

  A fifth round on the retirement above: it covered the *bound* and not the ending the scenario
  actually takes. When the target exits before the first `WaitForEvent` the session holds nothing,
  so the pump **fails** rather than expiring and the open returns through its `?` without ever
  reaching the bound. The error ending retires too, on the narrower condition that the session
  holds nothing at all — at the bound an open has pumped for `LIVE_WAIT_MS`, so a pid still not
  listed is not coming, where on a failed pump it may have pumped nothing and the same reading
  would retire an attach the engine had not yet had a chance to process.

  No public API changes. Two tests are gone rather than passing, and the constructions that make
  them unreachable are named where they were:
  `test_ending_a_session_forgets_which_processes_it_stopped_on` had no record to forget, and
  `test_a_process_that_left_takes_its_stop_with_it` is now
  `test_reclaiming_an_engine_id_does_not_reclaim_its_arrival`, which asserts the property
  end to end instead of the guard that used to hold it.

- **A break request names the operation it is for.** `InterruptHandle::interrupt` answers a
  `BreakRequest` — `Raised { operation }` or `NothingRunning` — instead of `Result<(), _>`, and
  files the request against the bounded operation the engine is running **under the same lock it
  delivers `SetInterrupt` on**. `DebugEngine::begin_operation` opens one; its guard discards an
  unread request when it drops. Stage 2 of
  [#136](https://github.com/glslang/dbgscope/issues/136), closing
  [#135](https://github.com/glslang/dbgscope/issues/135).

  What it replaced was an engine-wide `AtomicBool` answering *has an interrupt been requested*,
  where every reader wanted *was **this** operation asked to stop*. Six operations cleared it as
  they opened, so a request lodged between an operation's clear and its wait was **erased while its
  break was still on the way** — and the synthetic Ctrl+Break that arrived next was then reported
  as the target's own stop, up to and including being recorded in `stopped_on` as a target's
  initial break, which is the exact misattribution that record's gate exists to prevent, reached
  around it rather than through it. That is #135 half A. Half B — a request outliving the wait it
  ended — was closed by stage 1, which made every pump *take* what it read.

  **The lock is the fix, not the identity.** A generation counter does not close it: if
  `interrupt()` bumps and the operation samples after the bump but before `SetInterrupt`, the
  request is erased exactly as before. The window is between two writes, not between two values, so
  what closes it is making the record and the operation boundary mutually exclusive. The id earns
  its place elsewhere — operations **nest**, since `wait_for_kernel_break_in` holds one across an
  `absorb_initial_break_artifact` that runs a whole `execute_and_wait`, so `running` is a stack and
  `asked` a set and a `bool` could not express either.

  Two consequences. **Delivery stays engine-wide and only attribution is scoped**: `SetInterrupt`
  cannot be aimed, so the break is issued unconditionally — that is what lets a host abort a long
  unbounded `execute_command` that no bounded operation covers — and `NothingRunning` is the
  honest answer when nothing will report it. And **the watchdog files nothing**, reaching the engine
  through a private `break_in_only`, which deletes the `by_watchdog | flag` reconciliation from five
  sites: a deadline and a host request are now independent signals rather than two readings of one
  bit.

  **The residue is named rather than closed**, and it is two shapes of one fact — `SetInterrupt`
  is engine-wide, so which operation a break *lands* on is not this crate's to decide. A break
  aimed at operation N can land on N+1, because N ended between the host reading what was running
  and the break arriving; and a request can be filed against N *after* N's last read of one, since
  an operation accepts requests for slightly longer than it reads them. Neither is reportable. What
  the second one gets is a **drain**: an operation closing on a request nobody read consumes the
  engine's own pending break, so it cannot go on to stop the next operation with nothing to explain
  it — the policy `execute_and_wait`, `settle` and the bounded command path already applied
  wherever a break belonged to no operation, generalised to the one window with no site to put it
  at. `BreakRequest::Raised` says which operation a request was filed against and deliberately does
  not promise that operation will report it: whether the engine thread has a read left is not
  knowable to the calling thread. `examples/interrupt_provenance.rs`
  is the measurement #136 asked for before anything relies on one: a request that *ended* a wait is
  consumed before the wait returns (`[false; 5]`), one that did not is still readable
  (`[true, false, …]`), two back to back are one flag rather than two, and one lodged after the
  wait it was too late for belongs to the next operation. So a post-wait `GetInterrupt` is a
  **forward** signal, which is stage 3's to use.

- **A wait returns what it did.** `DebugEngine::wait_for_event` answers a `WaitOutcome` —
  `Stopped { process }`, `Expired`, `Deadline` or `OnRequest` — instead of `Result<(), _>`, and
  every wait in the crate now goes through one private `pump(bound)` that produces that value
  before anything downstream can look. `Bound` says how a pump is bounded: `Finite(ms)` is a plain
  `WaitForEvent(ms)` whose expiry leaves the target running, and `Watchdog(ms)` is
  `WaitForEvent(INFINITE)` with the Ctrl+Break watchdog the old private
  `wait_for_event_bounded` provided. Stage 1 of
  [#136](https://github.com/glslang/dbgscope/issues/136).

  The engine offers four endings and three of them were invisible from outside the wait: `S_OK` and
  `S_FALSE` are flattened into one `Ok(())` by the generated wrapper, and a break has been serviced
  by the time anything else could look. So the outcome used to be reconstructed *afterwards*, by
  three parties, out of shared mutable state — the last-event slot and the session's process list
  each read twice, the interrupt flag read twice, and the `HRESULT` only the waiting call ever saw
  discarded. #136's evidence that this is one root rather than twenty defects: **15 of the 22
  findings** on the [#133](https://github.com/glslang/dbgscope/pull/133) review were one of
  those reads moving, and **9** of them were a single question — may this writer record a stop?
  — asked once per writer. Those nine are now unreachable rather than guarded: an expiry and a
  break are *arms* of the value, and only `Stopped` reaches the recorder.

  Behaviour is otherwise unchanged, with two deliberate exceptions, both of them one rule replacing
  three. **A break outranks the wait's own error**, either origin's — which `execute_and_wait` and
  `settle` already did ("a break makes both of these fail"), `run_to_address` did for the watchdog's
  break alone, and `wait_for_event` did not do at all. Narrow in practice, since `SetInterrupt` ends
  a wait with `S_OK`: it takes the target failing in the same window. And **the request is taken
  rather than read**, by the pump, so no path can leave one standing for the next operation to be
  charged with; `run_to_address` had a line for that and `wait_for_kernel_break_in` had neither that
  nor the clear on the way in.

  `examples/deferred_arrival.rs` is the measurement #133 is held to and it is unmoved: arm A 0 short
  in 40 rounds under load, arm F 4.2 µs, arm H 5.6 µs (x64 bench, Windows 11 26200, 24 spinners).
  `examples/session_fuzz.rs` is clean over seeds 1, 2, 7 and 13. One thing #136 makes visible
  without changing: a **host's** break during a kernel attach is still reported as a clean break-in
  rather than as a timeout, because naming it wants an error of its own — stage 2's.

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
- **`run_to_address` no longer leaves its watchdog's interrupt raised.** It was the one bounded
  path that neither cleared the shared flag when it began nor consumed it when it ended, which
  cost it nothing of its own -- it classifies by the watchdog's private flag -- and cost everything
  else once the arrival record began reading the shared one: a single timed-out run left every
  later wait declining to record a real initial break, and any live open still held pumping to its
  bound for a target that had already stopped. All five paths that pump now clear on the way in,
  and this one consumes on the way out.
- **A live open a host interrupts now ends, instead of pumping through the break.** New:
  `DbgEngError::LiveTargetInterrupted`. The pumping this release introduces made an interrupt
  something the open ignored -- before it, a live open was a single `WaitForEvent`, so the break
  ended the wait and `wait()` returned. What that costs is not only the caller's time: measured
  with the check backed out, an interrupted open spends the whole 30s bound and answers
  `CommandFailed(0x8000FFFF)`, because the pumping let the debuggee run to completion and left no
  session to ask. The ending is the same rule the bound uses -- a process visibly in the session
  ends the wait `Ok` -- except that a process which is not there is reported as interrupted rather
  than as a timeout the open never reached, since a timeout says the target is not coming and this
  says nothing about the target at all.
- **A break nobody's target asked for is not an arrival, whichever origin raised it and whichever
  wait took it.** The watchdog's deadline and a host's `InterruptHandle` reach the engine through
  the same `SetInterrupt` and produce the same stop; only the advice differs, which is what
  `Interruption`'s two variants are for. Recording it lets a guard report an initial-break wait
  that never happened, because a Ctrl+Break stops whatever was running -- in a mixed session, a
  deferred target that has not reached its loader breakpoint. This arrived as three review rounds,
  one door at a time: the watchdog on the bounded wait, then a host on the bounded wait, then a
  host on the finite wait -- which is the one a live open pumps with, so the false arrival reaches
  the guard directly. The rule is therefore inside `note_where_it_stopped` and not at its call
  sites: both origins raise the same flag, so one question covers every wait in the crate and a
  new one cannot forget it. It reads the flag rather than consuming it, since the callers still
  need it to say which origin asked, and `wait_for_live_target` now clears it when an open begins
  -- the line `execute_and_wait` and `settle` already carry, without which a stale flag would
  leave an open pumping to its bound for an answer it had.
- **A process that leaves a session takes its recorded stop with it.** `stopped_on` is keyed by
  `(engine id, pid)`, and engine ids are reused immediately -- measured: detaching engine id 0 and
  attaching another process hands the freed 0 straight back. So a session that `.detach`es one of
  its processes through the raw hatch and attaches to the same pid again gets the whole pair back,
  and `presence_of` would answer `Arrived` for a target whose initial breakpoint had not happened.
  Pruned alongside the attach record it sits beside, at the two openers, which is the only cadence
  it needs: nothing reads either record outside an open. `prune_dead_attachments` is
  `prune_processes_that_left`, since it no longer prunes only attachments.
- **A wait that stopped on nothing no longer records a stop.** `stopped_on` is written as each
  wait observes a stop, and two kinds of wait come back having observed none. A **watchdog-forced**
  Ctrl+Break was being recorded, which `wait_for_event_bounded` documents as something callers must
  not treat as a normal completion: it stops whatever was running, so an `execute_and_wait` or
  `run_to_address` pumping a mixed session could stop a deferred target before its initial
  breakpoint and leave that target's still-held guard reporting an initial-break wait that never
  happened. The other is an **expiry**, which `WaitForEvent` reports as `S_FALSE` and the generated
  wrapper flattens into the same `Ok` a stop gets; that one was never reaching the record, because
  an expired wait leaves `GetLastEventInformation` reporting `DEBUG_ANY_ID` rather than the event
  before it -- measured, and so the safety rested on an undocumented sentinel in the one function a
  guard trusts to end its wait early. Both are now gated, the expiry by reading the raw `HRESULT`
  through the vtable as `interrupted` already does, and the sentinel is pinned so that an engine
  which stops supplying it fails a test rather than an open.
- **What a teardown lets go of now turns on `EndSession`'s own outcome**, not on the value
  `end_session` returns. The two differ exactly when a detach fails: `end_session` reports that
  failure to its caller, and rightly, but a process this engine could not detach from is one left
  attached and running — it does not keep the session alive. Gating on the combined result held
  back both things the session owns on a session that had definitely gone: the deferred input
  buffers, where the cost is a leak, and the record of which processes this engine stopped on,
  where the cost is the stale entry the previous entry is about, reached by a second road. Found by
  review rather than by a test, and it stays that way: the split cannot be staged, because the
  detach loop *skips* a process the engine no longer lists rather than failing on it.
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
