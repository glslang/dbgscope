# Unknown, not absent

> `the walk ran out of its {allowed} while enumerating heap roots: {coverage}; what is
> missing is unknown, not absent`
>
> — `src/heap.rs`, the diagnostic a truncated root enumeration writes

A debugger reads a machine that is bigger than any one read of it. Paged pool is partly out
on disk. A live kernel keeps allocating between the reads that make up a single walk. A
minidump was written by someone who chose what to keep. A four-byte pool tag holds bytes that
no font renders. In every one of those cases there is a true answer and the API cannot see all
of it.

The usual Rust advice is to make illegal states unrepresentable. That advice assumes you know
which states are legal. Here the harder problem is the inverse: the ground truth is genuinely
unknowable at the boundary, and a type that reports a partial reading as a total one is not
merely imprecise — it is wrong in the direction that gets acted on. "No chunk carries that tag"
and "the walk reached almost none of the pool" are the same empty `Vec` and opposite
conclusions.

So the rule this crate is built to: **an answer carries what the answering cost.** Never a bare
count, never a bare `String`, never a rendering that cannot be handed back. And — the part that
takes the actual work — never at the price of making the ordinary call unpleasant.

This document is the long form. Each section names the type, why the obvious simpler shape was
wrong, and what it costs a caller who does not care.

---

## 1. A pool walk against a live kernel is normally incomplete

Not "sometimes", not "when something breaks". Normally.

Paged pool is a paged resource: parts of it are on disk, and a page the memory manager has
paged out cannot be read through the debugger either — the debugger reads the same physical
memory the machine does. So `SnapshotWalker` meets committed virtual ranges whose contents
are simply not there, files them as `sparse virtual range at {address:#x}+{size:#x} (valid
{valid_base:#x}+{valid_size:#x})`, and the chunks inside them never enter the snapshot.

The naive shape for that is a `bool complete` on the report. It was, once. It is wrong, because
**there are two ways to fall short and they need opposite responses from the caller**:

```rust
pub enum WalkCoverage {
    /// The walk covered everything it set out to.
    Complete,
    /// It stopped early because its deadline passed. What it reached was really there;
    /// what is missing is unknown rather than absent, and a longer budget reaches more of it.
    BudgetExpired,
    /// It ran to the end without covering all of it — unreadable regions, a region that
    /// stopped mid-chunk, a traversal cap. Unlike BudgetExpired, more time changes nothing.
    Partial,
}
```

`src/pool/query.rs`. A caller holding `BudgetExpired` should retry with `PoolWalk::within(a
longer deadline)`. A caller holding `Partial` should not: the same gaps come back however long
it runs, and retrying is pure latency. A `bool` collapses those into one word and pushes the
distinction onto a human reading diagnostics.

Two further properties of it are load-bearing:

**It is computed in one place, from the walk's own two bits.** `report_of` in
`src/pool/query.rs` is the only site that turns `(index.complete, index.budget_expired)` into a
`WalkCoverage`. No caller has to know that "incomplete" has more than one cause, and none can
invent the distinction differently.

**It is not implied by the diagnostics.** A walk can end incomplete having said nothing at all —
`walk_vs` clears completeness when a readable region stops mid-chunk, without a message. A
caller that wants to reject partial results consults `coverage` and never the message list.
The inverse also holds: a walk with thousands of diagnostics can be `Complete`.

### Running out of time is not an error

```rust
pub const DEFAULT_WALK_BUDGET: Duration = Duration::from_secs(120);
```

A walk is thousands of debugger reads plus every committed pool page, and over a live KDNET
link each of those crosses the wire. On a busy kernel that is minutes. Nothing used to stop it.

The walk polls the engine's interrupt flag, and two things set it: Ctrl+C from a human at a
WinDbg prompt, and `InterruptHandle::interrupt` from a host thread. **Both need somebody
watching the clock.** A caller that is simply blocked on the call is not watching anything, and
because one engine serves one target one call at a time, every later call queued behind the
walk. The session was wedged until it was killed, which on a live kernel leaves the guest
halted. A deadline is the one stopper that needs nobody present — which is why it exists
alongside the handle rather than instead of it.

The budget frees the caller. What matters for this document is what it returns: not
`Err(Timeout)`, but the chunks it reached, `coverage: BudgetExpired`, and a diagnostic saying
how far it got. An `Err` would discard the work, and the work is real — those chunks were
genuinely there. `120s` is sized to fit inside a typical host's per-call budget with room for
the answer to travel back; a host that knows its own deadline passes that instead.

Interruption gets the same treatment one level up. `PoolQueryError::Interrupted` is its own
variant rather than a `Walk(String)`, because it is not a failure of the walk at all: somebody
asked for it to stop. A host that reports "walking the pool failed" for an interrupt it raised
itself is telling its user the target is broken. This is also what makes `PoolWalk::unbounded()`
usable away from an interactive prompt: a host that holds an `InterruptHandle` and knows its own
cancellation conditions can run without a deadline and stop the walk on its own terms.

---

## 2. Making that bearable

This is the part that is actually hard, and the reason the theme is worth a talk rather than a
footnote. Nobody wants to unwrap a coverage flag on every call. Four things carry it.

### `PoolAnswer<T>` — the answer and its walk are one value

```rust
pub struct PoolAnswer<T> {
    /// What was asked for.
    pub found: T,
    /// The state of the walk it was drawn from.
    pub walk: PoolSnapshotReport,
}
```

The obvious alternative is a `find_tag` that returns the spans and a separate
`snapshot_report()` for the coverage. That is broken, and subtly: **an incomplete walk is
deliberately not cached**, so the second call finds nothing cached and walks *again*. The
caller then holds a count from one walk and a coverage figure from another, and reports them as
if they described each other — which is exactly the mistake coverage exists to prevent,
arriving through the reporting instead of through the walk.

So the pairing is made where both come from one `PoolIndex`, and it cannot be made anywhere
else. The cost to a caller who does not care is one field access: `answer.found`.

### `impl From<bool> for PoolWalk` — the ordinary call did not change

```rust
pub fn find_tag(
    engine: &DebugEngine,
    tag: &str,
    ...,
    stop_after_matches: Option<NonZeroUsize>,
    walk: impl Into<PoolWalk>,
)
```

`PoolWalk` carries a refresh flag and a budget. Callers that had been passing `false` for
"reuse the cache" still pass `false`, and pick up `DEFAULT_WALK_BUDGET` without asking. The
richer form is there when wanted:

```rust
PoolWalk::cached()                          // reuse a snapshot; default budget
PoolWalk::refreshed().within(secs(30))      // rebuild, my deadline
PoolWalk::cached().unbounded()              // only if you can interrupt it
```

Adding a dimension to an API does not have to add a parameter to its call sites.

### `WalkCoverage::complete()` — the escape hatch is one word

```rust
if !answer.walk.coverage.complete() { /* qualify the result */ }
```

A caller who genuinely only needs the boolean gets the boolean. The three-way enum is there for
the caller who needs to *decide what to do*, and the `bool` projection means the richer type
costs nothing to ignore. Neither reading has to be justified.

### The default is the honest one

`PoolWalk::cached()` bounds the walk. `unbounded()` is opt-in and its doc comment says exactly
who it is for: "Only for a caller that can interrupt it." The shape that overstates — a walk
with no bound, a report with no coverage — is the one you have to type extra characters to get.

---

## 3. Counting things honestly

Coverage is the headline; the same rule applies to every number the walk reports.

### Diagnostics are grouped by shape, and the totals travel as numbers

A live target keeps allocating between the reads that make up one walk, so a single stale list
pointer yields one `unreadable VS free tree node 0x…` line per node — 14,000 of them measured
on a busy kernel. Keeping them all buries the handful of *distinct* problems a reader needs,
and every consumer truncates the list anyway, so which ones survive gets decided by position
rather than by significance.

`PoolDiagnostics` keeps `DIAGNOSTIC_EXAMPLES` (8) verbatim messages **per shape**, where a
shape is the message with every number standing in for itself. And it keeps the per-shape
totals as `usize`:

```rust
pub fn emitted(&self) -> usize    // the number that describes the walk
pub fn examples(&self) -> &[String]  // the number that describes this struct
```

The doc comment names the failure directly: *"A walk that emitted 7,700 complaints reporting
'71 diagnostics' is the specific failure the module exists to avoid, so the numbers travel as
numbers."* Flattened to text the totals survive only as prose inside a summary line, and a
consumer that counts the lines it received is measuring the cap — then printing the answer as a
property of the target.

### `refused_chunks` — a count, because the diagnostic cannot be one

Diagnostics collapse by shape, and a chunk refusal is reported once per *extent*. So the figure
beside that line counts extents that contained a refusal, which reads like a chunk count and is
not one. On the walk that raised this, the difference was between "884" and a number nothing
recorded. It is a separate `u64` on the report.

### `unplaced_bytes` — sizing the cost of refusing to guess

When `walk_vs` cannot say where a chunk begins in a committed VS subsegment, it declines to
decode it rather than decoding from a guess. What that buys is that nothing fabricated enters
`spans`. What it costs is coverage — **and coverage is invisible unless it is sized**. A walk
reporting no refusals and no unplaced bytes decoded every committed byte it reached; one
reporting a large figure has lost the chunk chain somewhere.

This is the pattern in miniature: the conservative decision is only defensible if the API also
reports what the conservatism cost.

### `WalkStalls` — including when the answer is zero

```rust
pub struct WalkStalls {
    pub pages: u64,            // times a query could not advance and the walk stepped a page
    pub skipped_bytes: u64,    // bytes filed unreadable by those steps
    pub recovered_bytes: u64,  // committed bytes read *after* a stall, in regions that stalled
}
```

`recovered_bytes` is what the page-stepping strategy is judged by, and **on live 26100 it has
measured zero**: 1,619 stalls, 6,627,520 bytes stepped over, nothing read behind any of them.
The doc comment says so, and says why that is the number saying what it says rather than a
counter nobody wired up. A crate that only reports metrics when they flatter the design is
back to overstating.

---

## 4. Execution control: a bounded wait, and a forced break says so

DbgEng does not "run a command". It sets a run state and returns; nothing moves until a
`WaitForEvent` pumps it. So execution control here is a bounded wait with a watchdog behind it,
and the interesting question is what the bound reports when it fires.

### The watchdog

`SetInterrupt` is the one DbgEng call documented as safe from any thread — the rest of the
engine is single-thread-affine — which is the entire reason a watchdog can exist without a
second threading model. `Watchdog` arms a thread that raises the interrupt once a deadline
passes, and re-raises every `WATCHDOG_REPEAT` (200ms) after that, because one `SetInterrupt` is
a request, not a guarantee: the engine acts on it at its next poll and a busy operation can be
between polls when it arrives.

It stops **the moment** it is disarmed, via a condition variable, and that is why it is a type
rather than two `thread::spawn`s. Both bounded paths used to poll a flag on a fixed sleep, so
`join` waited out whatever was left of the interval: every bounded operation paid up to one
interval whether or not it came near its deadline. A downstream host measured that tax at
~200ms on a command whose unbounded median was 0.22ms, and routed its cheap queries around the
bounded path to avoid it — a design decision taken to work around a `sleep`. The bound now
costs nothing until it is actually reached.

### A forced break is reported as a forced break

```rust
pub struct CommandRun {
    pub output: String,
    /// `None` when the command ran to completion.
    pub cut_short: Option<Interruption>,
    pub target_gone: bool,
}

pub enum Interruption {
    Deadline { after_ms: u32 },
    OnRequest,
}
```

A `String` alone cannot answer "did this run?", and an interrupted command is exactly the case
where the text *looks* like an answer and is not: a search cut short prints the hits it had
reached and nothing to say there were more. Encoding it as an `Err` is no better — that
discards the output, which is the whole reason to interrupt rather than end the session.

The two `Interruption` variants are distinguished because the advice differs. `Deadline` needs
saying: nobody outside the crate can see the watchdog fire, so a caller rendering for a human
should report it and say what to do — scope the command and retry. `OnRequest` mostly does not:
that caller knows, having asked.

And the origin is decided by **the watchdog's own flag**, not by the shared `interrupt_raised`
bit — which the watchdog sets too, since that is what `InterruptHandle::interrupt` does.
Reading the shared bit would report every deadline as a host request.

### A bound that bounds less than it appears to, and says so

```rust
/// Upper bound (ms) on a live-kernel break-in wait. …
///
/// **Bounds less than it appears to.** The watchdog works by `SetInterrupt`, which only
/// reaches a target that has *connected*, so this caps a connected-but-unresponsive target
/// and nothing else. One that never dials in — powered off, wrong key, not booted with
/// `bcdedit /debug on` — blocks past this bound indefinitely (measured: >300s, killed).
const KERNEL_ATTACH_WAIT_MS: u32 = 60_000;
```

A live kernel requires `WaitForEvent(INFINITE)`; a finite timeout returns `E_NOTIMPL`. So the
watchdog is the only bound, and it is a partial one. The honest thing is not to hide that
behind a constant named like a guarantee. The same limitation is restated on
`InterruptHandle::interrupt` and on `wait_for_event_bounded`, because those are where a caller
meets it.

### `run_to_address` names four endings, not two

```rust
pub enum RunToOutcome {
    Hit,
    StoppedElsewhere { stopped_at: u64 },
    Timeout,
    TargetGone,
}
```

`Timeout` — "the address was not reached with the current input/state" — is not `Hit == false`,
and neither is `StoppedElsewhere`, which carries where it actually stopped.

### A target that ends is an ending, not a failure

`target_gone` deserves its own note because it is where "not an error" is least obvious. A
program running to completion is the ordinary end of a `go`. DbgEng reports it terribly:
`WaitForEvent` answers `E_UNEXPECTED` ("Catastrophic failure", which names nothing),
`GetNumberProcesses` and `GetExitCode` fail beside it, and `.lastevent` says `<no event>`. Only
`GetExecutionStatus` reading `DEBUG_STATUS_NO_DEBUGGEE` says anything.

It is a `bool` on the result rather than an `Err` for the usual reason: **the output above it is
real and this is the only copy of it.** The module loads, the breakpoint banner, whatever an
embedded script printed before the target ran out — on the run that ends the target there is no
successor to print them again.

It is also terminal, and the crate says so rather than letting a caller find out: nothing will
run against that engine again, and driving execution control with no debuggee faults *inside*
DbgEng with a `STATUS_ACCESS_VIOLATION` that `catch_unwind` cannot trap. Hence
`refuse_without_a_debuggee` on every road in.

---

## 5. The tag: a rendering is not an identifier

A pool tag is four bytes. WinDbg prints it as four characters. Those are not the same thing,
and the crate keeps them apart at every boundary.

Internally a tag is always the raw `u32`. `display_tag` maps each byte to itself if printable
and to `.` otherwise — and the loss is worse than "unprintable bytes vanish", because **`.` is
itself printable**. A tag whose bytes really are `....` renders identically to one nothing can
print. A caller holding `....` cannot tell which of 2^32 tags it came from.

That would be a curiosity if the rendering were never handed back. It is: a consumer displays a
tag, a human retypes it, and it goes to `find_tag`. Without care that round trip **silently
finds a different tag** rather than failing — the test pins it:

```rust
let binary = u32::from_le_bytes([0x00, 0x01, 0x80, 0xff]);
let dots   = u32::from_le_bytes(*b"....");
assert_eq!(display_tag(binary), display_tag(dots));
assert_ne!(binary, dots);
assert_eq!(parse_tag(&display_tag(binary)), Some(dots));   // ← the lie
assert_eq!(parse_tag(&raw_tag_hex(binary)), Some(binary)); // ← the fix
```

So there is a second form. `raw_tag_hex` gives `0x` plus the four bytes in **memory order**, so
it reads in the same direction as the printed tag and as the debugger's own output — `Tgsm` is
`0x5467736d`, not `0x6d736754`. `parse_tag` takes either, and the two cannot collide, which is
what makes accepting both safe rather than a guess: the raw form is exactly ten characters and
a printed tag is at most four, so `"0x2e"` stays the ordinary four-byte tag it has always been.

### Two predicates, because there are two separate failures

```rust
pub fn display_is_ambiguous(tag: u32) -> bool   // the rendering does not identify the tag
pub fn display_round_trips(tag: u32) -> bool    // it identifies it and survives the trip
```

Collapsing them would get the reason wrong. A tag can be perfectly unambiguous and still not
come back: `!dbgscope.poolmap` splits arguments on whitespace, so raw bytes `A BC` return as
the tag `A` with `BC` left over as a stray argument, and an all-space tag returns as no
argument at all. Only a nonempty run of non-space bytes followed by nothing but spaces survives
— exactly the shape `parse_tag` rebuilds when it pads a short tag to four bytes. `Ntf `
round-trips; `A BC` does not, and for a different reason than `....` does.

### One rule for every output site

```rust
pub fn tag_label(tag: u32) -> String {
    if display_round_trips(tag) { display_tag(tag) } else { raw_tag_hex(tag) }
}
```

Every place that prints a tag for someone who might hand it back goes through this. Not because
it is tidier, but because printing a rendering that cannot be queried is what made `....` an
unusable answer, and one rule is what stops the extension's output and a programmatic host's
from disagreeing about the same chunk. `PoolSpan` keeps `raw_tag: u32` beside `display_tag:
String` so a consumer never has to reconstruct one from the other.

---

## 6. The same rule, everywhere else

Once you adopt it, it stops being a pool-walker concern.

| Type | What it refuses to overstate |
|---|---|
| `RegisterValue::Unavailable` | A minidump without floating-point state holds no value for `xmm0`. That is not `0`. |
| `RegisterValue::Bytes` | x87 and vector registers stay in the engine's byte order rather than being squeezed into an `f64` that cannot represent them. |
| `SymbolKind::Deferred` | *Not* a statement that symbols are missing — the engine will fetch them on first use, and a deferred module usually resolves fine. The most consequential value in the enum. |
| `SymbolKind::Other(u32)` | An unrecognised symbol type keeps the engine's own code rather than flattening to `None`, which would read as "no symbols" for something that has them. |
| `SymbolKind::has_type_info()` | Says the narrow thing the pool walker actually needs (private types), not "has symbols". |
| `Module::name` empty | For an unloaded module there is no name to qualify symbols by. Empty is the fact, not a truncation. |
| `PoolSpan::requested_size: Option<u64>` | Set only where allocator metadata validates it. Kernel pool and LFH/VS spans leave it `None` rather than guessing from capacity. |
| `PoolState::Unreadable` | A distinct state from `Allocated` and the two free states — the walker reached the chunk and could not read it. |
| `query::chunk_at` → `Ok(None)` | "Not covered by the snapshot at all", which is a different answer from "it is a free hole" — that comes back as a chunk whose `PoolState` is not `Allocated`. |
| `find_tag` indexes allocated chunks only | A freed chunk's tag is not reliably preserved by the allocator, so "freed chunks with this tag" would be inventing information. |
| `PoolKind`'s eight variants | Not collapsed to paged/nonpaged, because crossing one of those boundaries creates false holes. |
| `HeapScope` | Names the heaps that were skipped and *why* — `nt_heaps_skipped`, `unknown_heaps_skipped`, `unreadable_heaps_skipped` — rather than reporting a count of the ones that worked. |
| `Scope::has_context()` | `false` is a legitimate scope, not a failed read: a target with no thread context still has a position. |
| `Scope`'s target identity | A scope carries the target it was read from and is refused rather than applied to a later one. |
| `LayoutProvenance::fingerprint` | A digest of the resolved offsets actually used. Deliberately contains no build-number policy — it records what was decoded from, not what Microsoft shipped. |
| `PoolQueryError`'s variants | "You are pointed at the wrong kind of target" (never going to work) is a different variant from "the target is running" (break in and retry). |

---

## 7. What it costs

It is not free, and the honest version of this document says so.

**More types.** `WalkCoverage`, `PoolAnswer`, `PoolWalk`, `Interruption`, `CommandRun`,
`PoolDiagnostics`, `WalkStalls`, `DiagnosticShape` all exist because a simpler shape lied. That
is eight public types a reader has to meet.

**Callers must decide.** A host that just wants a number now has to choose what to do about
`BudgetExpired`. That is the point — it was always making that choice, silently and wrongly —
but it is still work that a `Vec<PoolSpan>` did not ask for.

**It only pays where the source is genuinely lossy.** Applied to an API whose ground truth is
knowable, this is ceremony. The test is whether you can name the wrong answer the simpler shape
would produce. Every type above has one, and most have a linked issue where it actually
happened.

The transferable claim is narrow and, I think, correct: **anyone reading from a partial or
lossy source has this problem** — a scraper, a log parser, a sampling profiler, a flaky network
client, an OCR pipeline, an LLM extraction step. The debugger is just a setting where the
partiality is impossible to talk yourself out of.

---

## Reading the source

| Theme | Where |
|---|---|
| Coverage, budgets, the answer/walk pairing | `src/pool/query.rs` |
| Diagnostics by shape, stalls, refusals, unplaced bytes | `src/pool/snapshot.rs` |
| The tag's two forms and four predicates | `src/pool/decode.rs` |
| Watchdog, `CommandRun`, `RunToOutcome`, the no-debuggee guard | `src/dbgeng.rs` |
| Heap-side coverage and scope | `src/heap.rs` |
| Randomised check that the session invariant holds | `examples/session_fuzz.rs` |
