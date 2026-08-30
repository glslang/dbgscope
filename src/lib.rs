//! Typed access to a WinDbg/DbgEng debug session, and allocator walkers built on it.
//!
//! Two layers, and the split is worth knowing before reading further.
//!
//! [`dbgeng`] is the session driver: it opens a target — a live kernel over KD, a local
//! kernel, a launched or attached user-mode process, a crash dump, or a TTD trace — and
//! answers in values rather than in the text `r`, `lm` and `bl` print. It also *drives*
//! the target, which is the part that takes care: DbgEng sets a run state and returns,
//! and nothing moves until a `WaitForEvent` pumps it, so execution control here is a
//! bounded wait with a watchdog behind it rather than a command send.
//!
//! [`pool`] and [`heap`] are allocator archaeology on top of that session — the kernel
//! pool and user-mode Segment Heap respectively. They share their page-segment, LFH, VS,
//! backend and large-allocation decoding, because the two allocators are the same
//! machinery either side of the ring boundary.
//!
//! Everything is Windows-only in practice: the public surface calls Windows APIs directly.
//!
//! # The design rule
//!
//! The organising idea is smaller than the API and worth stating first: **every answer
//! carries what the answering cost.**
//!
//! A debugger reads a machine bigger than any one read of it. Paged pool is partly out on
//! disk, and a page the memory manager has paged out cannot be read through the debugger
//! either. A live kernel keeps allocating between the reads that make up a single walk. A
//! minidump was written by someone who chose what to keep. In each case there is a true
//! answer and this crate cannot see all of it — and a type that reports a partial reading as
//! a total one is wrong in the direction that gets acted on. "No chunk carries that tag" and
//! "the walk reached almost none of the pool" are the same empty [`Vec`] and opposite
//! conclusions.
//!
//! The familiar advice is to make illegal states unrepresentable, which presumes you know
//! which states are legal. Here the problem is the inverse: when the ground truth is
//! genuinely unknowable, the type has to carry its own incompleteness. Three places where
//! that surfaces in the public API:
//!
//! * **Coverage.** [`pool::query::WalkCoverage`] is a three-way enum, not a `bool`, because
//!   the two ways of falling short need opposite responses:
//!   [`BudgetExpired`](pool::query::WalkCoverage::BudgetExpired) reaches more of the pool if
//!   given more time, and [`Partial`](pool::query::WalkCoverage::Partial) reports the same
//!   gaps however long it runs. Running out of
//!   [`DEFAULT_WALK_BUDGET`](pool::query::DEFAULT_WALK_BUDGET) is not an error: the walk
//!   returns what it reached, with the coverage saying so.
//!
//! * **Forced breaks.** A bounded command Ctrl+Broken at its deadline comes back as a
//!   [`CommandRun`](dbgeng::CommandRun) whose `cut_short` is
//!   [`Interruption::Deadline`](dbgeng::Interruption::Deadline), *keeping the output captured
//!   up to the break*. Not an `Err`, which would discard that output — the whole reason to
//!   interrupt rather than end the session — and not a bare [`String`], because a search cut
//!   short prints the hits it reached and nothing to say there were more.
//!
//! * **Tags.** A pool tag is four bytes and its printed form is a lossy rendering: every
//!   unprintable byte becomes `.`, and so does a literal `.`. The tag stays raw internally,
//!   and every output site prints through [`pool::tag_label`], which shows the raw form
//!   wherever the rendering would not survive being handed back.
//!
//! Carrying that without making the ordinary call unpleasant is the part that took the work.
//! [`PoolAnswer<T>`](pool::query::PoolAnswer) pairs an answer with the walk it came from, so
//! the two cannot be drawn from different walks; `impl From<bool>` for
//! [`PoolWalk`](pool::query::PoolWalk) leaves existing call sites unchanged while adding a
//! budget dimension; and [`WalkCoverage::complete`](pool::query::WalkCoverage::complete) is a
//! one-word escape hatch for a caller who only needs the boolean.
//!
//! The repository's `docs/unknown-not-absent.md` is the long form, including what the rule
//! costs and where it does not apply.
//!
//! # Examples
//!
//! Open a dump and read its modules as values:
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use dbgscope::dbgeng::DebugEngine;
//!
//! let engine = DebugEngine::new();
//! engine.open_dump(r"C:\dumps\MEMORY.DMP")?;
//! // `open_dump` only commits the session. The engine has no current process or thread
//! // until it has been pumped, so every read below fails without this.
//! engine.wait_for_event(60_000)?;
//!
//! for module in engine.modules()? {
//!     println!("{:#018x}  {:<24} {:?}", module.base, module.name, module.symbols);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Walk the pool for a tag, and qualify the answer by the walk that produced it:
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let engine = dbgscope::dbgeng::DebugEngine::new();
//! use dbgscope::pool::{query, tag_label};
//!
//! // `false` converts into a PoolWalk meaning "reuse any snapshot cached for this
//! // target"; `true` rebuilds. Either picks up DEFAULT_WALK_BUDGET.
//! let answer = query::find_tag(&engine, "Pipe", None, None, false)?;
//!
//! for span in &answer.found {
//!     println!("{:#018x} {:>8} {}", span.usable_address, span.size, tag_label(span.raw_tag));
//! }
//!
//! if !answer.walk.coverage.complete() {
//!     eprintln!(
//!         "{} spans is a floor, not a total ({:?})",
//!         answer.found.len(),
//!         answer.walk.coverage,
//!     );
//! }
//! # Ok(())
//! # }
//! ```

pub mod allocator;
pub mod dbgeng;
pub mod heap;
pub mod pool;
mod pool_extension;
