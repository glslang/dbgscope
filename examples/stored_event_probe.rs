//! Scratch experiment (not part of the public API), and the record behind
//! [`DebugEngine::last_event`], [`DebugEngine::stored_event`] and
//! [`DebugEngine::stack_frames_from`].
//!
//! Six questions no unit test can answer, because each is a question about what a real
//! `dbgeng.dll` does. Measured on dbgeng 10.0.29547.1002, x64, Windows 11 26200, 2026-09-05.
//!
//! 0. **What does an engine with nothing to report say?** Not an error — `S_OK`, kind `0`, and
//!    `DEBUG_ANY_ID` (`0xffffffff`) for both ids. True of an engine holding no target at all
//!    (`empty`) *and* of a dump `open_dump` has named but nothing has pumped (`unwaited`), since
//!    the engine reads the dump's event on the first wait rather than at the open. Kind `0` is not
//!    a `DEBUG_EVENT_*` value, so `last_event` reports `None` for it rather than dressing it up as
//!    an event; without that, "the target is not loaded yet" reads as an unrecognised event kind.
//!
//! 1. **How does the engine say "this target has no stored event"?** It refuses, and the refusal
//!    has to be told apart from a failure. Measured: `E_UNEXPECTED` (`0x8000ffff`), on a live
//!    process and on a kernel crash dump alike — which is what `no_stored_event` is pinned to.
//! 2. **Does a kernel crash dump have one?** No. A bug check is not an exception event, and
//!    `ReadBugCheckData` is what reads it — so the two calls do not overlap, and neither is a
//!    fallback for the other. Its *last* event is a second-chance, noncontinuable
//!    `STATUS_BREAKPOINT` with **zero** parameters, in `nt!KeBugCheck2`.
//! 3. **What is the last event on a freshly launched process?** `DEBUG_EVENT_EXCEPTION` (`0x2`)
//!    carrying `STATUS_BREAKPOINT` (`0x80000003`), first-chance, one parameter. Not
//!    `DEBUG_EVENT_BREAKPOINT` — the initial break arrives as an exception, which is the same
//!    finding `last_event_process`'s doc comment records from the other direction.
//! 4. **Does `GetStoredEventInformation` refuse a context buffer that is too small?** **No, and
//!    that is the trap this file caught.** It truncates: offered 716 bytes for an x64 dump it
//!    writes 716, reports 716 and returns success, and the damage surfaces three calls later when
//!    `GetContextStackTrace` rejects the truncated context with `E_INVALIDARG`. `GetScope`
//!    *does* refuse, which is why `SCOPE_CONTEXT_SIZES` climbs from the smallest size — and why
//!    borrowing that ladder here was wrong. `STORED_CONTEXT_SIZES` starts above every real
//!    `CONTEXT` instead; offered 4,096 the same dump reports 1,232, which is x64's.
//! 5. **What actually makes the two stack walks differ?** The **selected thread**, and only that.
//!    On the two-thread dump, after `~1s`, `stack_frames` returns the parked thread's six frames
//!    (`ntdll!NtDelayExecution` … `throwcrash2!parked`) while `stack_frames_from` still returns
//!    the crash's twelve. `.frame 5`, `.cxr` and `.ecxr` move **neither** — they change the symbol
//!    scope, and `GetStackTrace` walks from the thread's registers. A single-threaded dump cannot
//!    show any of this: both walks agree in every state it can be put in, which is how the first
//!    run of this file nearly recorded "no difference" as the answer.
//!
//! ```text
//! cargo run --example stored_event_probe -- live
//! cargo run --example stored_event_probe -- empty
//! cargo run --example stored_event_probe -- dump <path-to-dump>
//! cargo run --example stored_event_probe -- unwaited <path-to-dump>
//! ```
//!
//! **The dump arm wants a user-mode fault dump, and a two-thread one to answer question 5.** The
//! ones measured above were made by compiling a program that throws an object nothing catches —
//! so the CRT calls `terminate` → `abort` → `__fastfail`, which is the explorer walkthrough's
//! first fault exactly — and letting WER's `LocalDumps` catch it at `DumpType=1`. That is a
//! 190 KB minidump, and the second thread is a `Sleep(INFINITE)` started before the throw.
//!
//! **The engine has to be in `target/debug/examples`, not `target/debug`** — see
//! `breakpoint_probe.rs`, which explains what a wrong-engine run looks like. Here it would cost
//! the symbols on the frames and nothing else, since every question above is about event records
//! rather than about names.
//!
//! **How question 1 was measured, and how to measure it again.** A predicate that turns a refusal
//! into `Ok(None)` cannot be measured through itself: with `no_stored_event` in place, a live
//! target prints "no stored event" whatever the engine said. So it was flipped to `|_| false` for
//! one run, which surfaces every refusal with its `HRESULT` in the error text, and flipped back
//! for the next — and the second run is what shows the predicate catching the code the first one
//! printed. Do that again rather than trusting this comment if the engine version moves.

use dbgscope::dbgeng::{DebugEngine, DebugEvent};

/// A target that lives long enough to be asked about, and exits on its own if this program dies
/// holding it.
const TARGET: &str = "cmd.exe /c ping -n 60 127.0.0.1";

/// How many frames to walk, from each of the two walks that are being compared.
const FRAMES: usize = 12;

/// Long enough for the engine to read a dump off a cold disk and resolve what it needs to report
/// an event. Nothing here is timing-sensitive; this is a bound, not a measurement.
const WAIT_MS: u32 = 60_000;

fn main() {
    let mut args = std::env::args().skip(1);
    let arm = args.next().unwrap_or_else(|| "live".into());
    match arm.as_str() {
        "live" => live(),
        "empty" => empty(),
        "dump" => match args.next() {
            Some(path) => dump(&path),
            None => {
                println!("dump needs a path: cargo run --example stored_event_probe -- dump <path>")
            }
        },
        "unwaited" => match args.next() {
            Some(path) => unwaited(&path),
            None => println!(
                "unwaited needs a path: cargo run --example stored_event_probe -- unwaited <path>"
            ),
        },
        other => {
            println!("unknown arm {other}");
            println!("arms: live, empty, dump <path>, unwaited <path>");
        }
    }
}

/// An engine holding nothing at all — the state every engine is in before its first open.
fn empty() {
    println!("======== empty: an engine with no target ========");
    let engine = DebugEngine::new();
    print_reads(&engine);
}

/// A dump named but never pumped, which is the state `open_dump` alone leaves the engine in.
fn unwaited(path: &str) {
    println!("======== unwaited: {path} ========");
    let engine = DebugEngine::new();
    if let Err(e) = engine.open_dump(path) {
        println!("could not open {path}: {e}");
        return;
    }
    print_reads(&engine);
}

/// Just the two event reads, for the arms that are asking what an engine says before it has
/// anything to say.
fn print_reads(engine: &DebugEngine) {
    match engine.last_event() {
        Ok(Some(event)) => print_event("last_event", &event),
        Ok(None) => println!("  last_event: none — this engine has seen no event"),
        Err(e) => println!("  last_event: {e}"),
    }
    match engine.stored_event() {
        Ok(Some(event)) => print_event("stored_event", &event),
        Ok(None) => println!("  stored_event: none"),
        Err(e) => println!("  stored_event: {e}"),
    }
}

/// A launched process, stopped at its loader break.
fn live() {
    println!("======== live: {TARGET} ========");
    let engine = DebugEngine::new();
    if let Err(e) = engine.launch_process(TARGET) {
        println!("could not launch {TARGET}: {e}");
        return;
    }
    report(&engine);
}

/// A dump, opened by path.
fn dump(path: &str) {
    println!("======== dump: {path} ========");
    let engine = DebugEngine::new();
    if let Err(e) = engine.open_dump(path) {
        println!("could not open {path}: {e}");
        return;
    }
    // **The wait is not optional, and leaving it out is its own finding.** `open_dump` names the
    // file; the engine reads it on the first wait. Before that `last_event` answers kind `0x0`
    // with `DEBUG_ANY_ID` for both ids and no exception — "no event yet" rather than an error —
    // and `stack_frames` fails outright with `E_UNEXPECTED`. Anything asking either question of a
    // dump has to have waited first.
    if let Err(e) = engine.wait_for_event(WAIT_MS) {
        println!("could not wait for the dump's event: {e}");
        return;
    }
    // A bug check is the kernel's answer to the same question this is asking, and printing it
    // beside the event is what shows the two do not overlap.
    match engine.bug_check() {
        Ok(Some(bug)) => println!(
            "  bug check: {:#x} ({:#x}, {:#x}, {:#x}, {:#x})",
            bug.code, bug.parameters[0], bug.parameters[1], bug.parameters[2], bug.parameters[3]
        ),
        Ok(None) => println!("  bug check: none (code 0)"),
        Err(e) => println!("  bug check: unreadable ({e})"),
    }
    report(&engine);
}

/// Both event reads, and the two stack walks, on whatever target the caller opened.
fn report(engine: &DebugEngine) {
    match engine.last_event() {
        Ok(Some(event)) => print_event("last_event", &event),
        Ok(None) => println!("  last_event: none — this engine has seen no event"),
        Err(e) => println!("  last_event: {e}"),
    }
    let stored = match engine.stored_event() {
        Ok(Some(event)) => {
            print_event("stored_event", &event);
            Some(event)
        }
        Ok(None) => {
            println!("  stored_event: none — this target was not stored on an event");
            None
        }
        Err(e) => {
            println!("  stored_event: {e}");
            None
        }
    };

    // The comparison the new walk exists for: the same session, walked two ways.
    match engine.stack_frames(FRAMES) {
        Ok(frames) => print_frames("stack_frames (current context)", &frames),
        Err(e) => println!("  stack_frames: {e}"),
    }
    let Some(context) = stored.as_ref().and_then(|event| event.context.as_ref()) else {
        println!("  stack_frames_from: skipped — no stored context to walk from");
        return;
    };
    println!("  stored context: {} bytes", context.len());
    match engine.stack_frames_from(context, FRAMES) {
        Ok(frames) => print_frames("stack_frames_from (stored context)", &frames),
        Err(e) => println!("  stack_frames_from: {e}"),
    }

    // **The claim the second walk exists for**, which the two agreeing above does not establish:
    // on a freshly opened dump the session is already looking at the crash, so both walks answer
    // the same question. Navigate away and ask again.
    //
    // Three navigations rather than one because two of them are the *negative* result: `.frame`
    // moves the symbol scope and moves neither walk, and `~1s` moves the selected thread and moves
    // only the first. Running just the one that works would have left "a walk follows the session"
    // looking like a broader claim than it is.
    if let Ok(threads) = engine.execute_command("~") {
        println!("\n  threads in this target:\n{}", threads.trim_end());
    }
    for navigation in [".frame 5", "~1s", "~0s"] {
        match engine.execute_command(navigation) {
            Ok(_) => println!("\n  -------- after `{navigation}` --------"),
            Err(e) => {
                println!("\n  `{navigation}` did not run: {e}");
                continue;
            }
        }
        match engine.stack_frames(FRAMES) {
            Ok(frames) => print_frames("stack_frames (current context)", &frames),
            Err(e) => println!("  stack_frames: {e}"),
        }
        match engine.stack_frames_from(context, FRAMES) {
            Ok(frames) => print_frames("stack_frames_from (stored context)", &frames),
            Err(e) => println!("  stack_frames_from: {e}"),
        }
    }
}

fn print_event(tag: &str, event: &DebugEvent) {
    println!(
        "  {tag}: kind={:#x} process={} thread={} context={}",
        event.kind,
        event.process,
        event.thread,
        event
            .context
            .as_ref()
            .map_or_else(|| "none".into(), |c| format!("{} bytes", c.len())),
    );
    match &event.exception {
        None => println!("    exception: none"),
        Some(record) => {
            println!(
                "    exception: code={:#010x} flags={:#x} address={:#x} first_chance={} \
                 noncontinuable={} nested={:?}",
                record.code,
                record.flags,
                record.address,
                event.first_chance,
                record.noncontinuable(),
                record.nested.map(|at| format!("{at:#x}")),
            );
            // The parameter *count* is the field the two shapes of a fail-fast are told apart by,
            // so it is printed rather than left to be counted off the list.
            println!(
                "    parameters ({}): {}",
                record.parameters.len(),
                record
                    .parameters
                    .iter()
                    .map(|p| format!("{p:#x}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
}

fn print_frames(tag: &str, frames: &[dbgscope::dbgeng::StackFrame]) {
    println!("  {tag}: {} frames", frames.len());
    for frame in frames {
        println!(
            "    {:>2}  {:#018x}  {}",
            frame.index,
            frame.instruction_offset,
            frame.symbol.as_deref().unwrap_or("(no symbol)")
        );
    }
}
