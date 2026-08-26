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

pub mod allocator;
pub mod dbgeng;
pub mod heap;
pub mod pool;
mod pool_extension;
