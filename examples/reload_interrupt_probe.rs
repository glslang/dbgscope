//! Does `SetInterrupt` reach an `IDebugSymbols::Reload("")` that is in progress — and what does a
//! reload cut short leave behind?
//!
//! windbg-mcp's `FOLLOWUPS.md` item 54 wanted a wall-clock bound on `modules { "refresh": true }`,
//! which is this reload, and said to measure first: a watchdog that cannot break the call in is
//! worse than no bound, because it claims one. `read_memory_bounded`'s doc records the same
//! question left open for `ReadVirtual`, for want of a link slow enough for a call to sit in. A
//! live kernel over 115200-baud serial is that link. This is the record behind
//! `DebugEngine::reload_symbols_bounded`'s doc, and it drives that method rather than a copy of it.
//!
//! Each argument is one trial: `d<ms>` bounds a reload with the method's own watchdog at `<ms>`,
//! and `r<ms>` runs one with no deadline while another thread raises a host interrupt at `<ms>`
//! (and every 200ms after, as the watchdog does) — the two origins `cut_short` distinguishes. `s`
//! raises a host interrupt with nothing running and then reloads, which asks whether a request
//! left pending stops the next reload the way it does not stop the next command. Each
//! reports how long the reload took, what `cut_short` said, and how many modules the engine held
//! afterwards. **Only a cold reload is worth interrupting**: the first one after an attach reads
//! the target's module list across the link, and later ones are answered from the engine's cache
//! in tens of milliseconds. So the first trial is spent on the first reload, the cache is flushed
//! before each later one, and an unbounded reload follows each so that every trial starts from the
//! same inventory. `end_session` resumes and detaches the target at the end.
//!
//! Usage: set `DBGSCOPE_KERNEL_CONNECTION` (e.g. `com:port=COM1,baud=115200`), then
//! `reload_interrupt_probe [d<ms>|r<ms> ...]` (default `d1000 r1000`). Install matching DbgEng
//! DLLs beside this executable. Never put a KDNET key on the command line.
use dbgscope::dbgeng::{DbgEngError, DebugEngine};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

/// The crate's own watchdog repeat, so a host's request is raised the way a deadline is.
const REPEAT: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Copy)]
enum Trial {
    /// The reload's own watchdog, at this many milliseconds.
    Deadline(u32),
    /// No deadline; a host interrupt raised from another thread after this many milliseconds.
    Request(u64),
    /// No deadline; a host interrupt raised *before* the reload, while nothing is running, so it
    /// is filed against nothing and left pending -- does it stop the reload that follows?
    Stale,
}

impl Trial {
    fn parse(arg: &str) -> Self {
        let (kind, ms) = arg.split_at(1);
        match kind {
            "d" => Self::Deadline(ms.parse().expect("d<ms>")),
            "r" => Self::Request(ms.parse().expect("r<ms>")),
            "s" if ms.is_empty() => Self::Stale,
            _ => panic!("each trial is d<ms>, r<ms> or s, not {arg:?}"),
        }
    }
}

fn held(e: &DebugEngine) -> String {
    match e.modules() {
        Ok(modules) => modules.len().to_string(),
        Err(why) => format!("unreadable ({why})"),
    }
}

fn reload(e: &DebugEngine) -> (Duration, Result<(), DbgEngError>) {
    let start = Instant::now();
    let result = e.reload_symbols("");
    (start.elapsed(), result)
}

/// Empties the engine's cache of target memory, so the next reload reads the link again.
fn flush(e: &DebugEngine) {
    if let Err(why) = e.execute_command(".cache flushall") {
        println!("PROBE `.cache flushall` failed: {why}");
    }
}

fn run(e: &DebugEngine, trial: Trial) {
    let before = held(e);
    let start = Instant::now();
    // The elapsed time is taken as the reload returns, not after the raiser is joined: that join
    // can wait out the rest of a `REPEAT` and would be charged to the reload.
    let (result, elapsed, raises) = match trial {
        Trial::Deadline(ms) => {
            let result = e.reload_symbols_bounded("", ms);
            (result, start.elapsed(), 0)
        }
        Trial::Stale => {
            let raised = e.interrupt_handle().interrupt();
            println!("PROBE   raised with nothing running: {raised:?}");
            let start = Instant::now();
            let result = e.reload_symbols_bounded("", 0);
            (result, start.elapsed(), 1)
        }
        Trial::Request(ms) => {
            let handle = e.interrupt_handle();
            let done = Arc::new(AtomicBool::new(false));
            let stop = Arc::clone(&done);
            let raiser = thread::spawn(move || {
                thread::sleep(Duration::from_millis(ms));
                let mut raises = 0u32;
                while !stop.load(Ordering::SeqCst) {
                    if let Err(why) = handle.interrupt() {
                        println!("PROBE   SetInterrupt failed: {why}");
                    }
                    raises += 1;
                    thread::sleep(REPEAT);
                }
                raises
            });
            let result = e.reload_symbols_bounded("", 0);
            let elapsed = start.elapsed();
            done.store(true, Ordering::SeqCst);
            let raises = raiser.join().expect("the raiser does not panic");
            (result, elapsed, raises)
        }
    };
    println!(
        "PROBE {trial:?}: returned after {elapsed:?} with {result:?} ({raises} host raise(s)); \
         modules held {before} before, {} after; interrupt pending afterwards: {:?}",
        held(e),
        e.interrupted(),
    );
    let (took, result) = reload(e);
    println!(
        "PROBE   unbounded reload after it: {took:?} {result:?}, modules held {}",
        held(e)
    );
}

fn main() {
    let connection = std::env::var("DBGSCOPE_KERNEL_CONNECTION")
        .expect("set DBGSCOPE_KERNEL_CONNECTION to the kernel connection string");
    let mut trials: Vec<Trial> = std::env::args().skip(1).map(|a| Trial::parse(&a)).collect();
    if trials.is_empty() {
        trials = vec![Trial::Deadline(1000), Trial::Request(1000)];
    }

    let e = DebugEngine::new();
    let start = Instant::now();
    if let Err(why) = e.attach_kernel(&connection) {
        println!("PROBE attach failed after {:?}: {why}", start.elapsed());
        let _ = e.end_session();
        return;
    }
    println!(
        "PROBE attached in {:?}; modules held {}",
        start.elapsed(),
        held(&e)
    );

    let mut trials = trials.into_iter();
    if let Some(trial) = trials.next() {
        println!("PROBE -- the first reload after the attach --");
        run(&e, trial);
    }
    let (took, result) = reload(&e);
    println!(
        "PROBE unbounded reload, warm: {took:?} {result:?}, modules held {}",
        held(&e)
    );
    flush(&e);
    let (took, result) = reload(&e);
    println!(
        "PROBE unbounded reload after a flush: {took:?} {result:?}, modules held {}",
        held(&e)
    );
    for trial in trials {
        flush(&e);
        run(&e, trial);
    }
    // A bound that is never reached must cost nothing and report nothing.
    flush(&e);
    let start = Instant::now();
    let generous = e.reload_symbols_bounded("", 60_000);
    println!(
        "PROBE a 60s bound on a cold reload: {:?} {generous:?}, modules held {}",
        start.elapsed(),
        held(&e)
    );

    match e.execute_command("r") {
        Ok(text) => println!("PROBE session still answers `r` ({} bytes)", text.len()),
        Err(why) => println!("PROBE session no longer answers `r`: {why}"),
    }
    println!("PROBE end_session: {:?}", e.end_session());
}
