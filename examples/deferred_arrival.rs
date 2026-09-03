//! Scratch measurement for dbgscope#128 (not part of the public API): when a `WaitForEvent`
//! returns on an event belonging to a target the caller was **not** waiting for, is the
//! waited-for target lost, or does it arrive on a later wait? The issue deferred between fixing
//! the library and fixing the test on exactly that question, and had not taken the measurement.
//!
//! The failure is `launch_process` returning `Ok` with the launched process absent from a session
//! that already held an attached one. `CreateProcessWide` is deferred to the next `WaitForEvent`,
//! and a live `PendingTarget::wait` used to make exactly one of those — which can return on the
//! *other* target's event instead.
//!
//! What this measured, on an x64 bench (Windows 11 26200, 4 cores), `<rounds>` = 40 and
//! `<spinners>` = 24:
//!
//! - **It is not lost.** Every shortfall observed, across every arm, had the missing process
//!   present on the very next wait — never later than that. So pumping reaches it, and the
//!   library fix (`Arrival`) is the one the contract asks for.
//! - **The race is real and load-sensitive.** Arm A, attach-then-launch: 3 short in 40 rounds
//!   under load, 0 in 40 quiet — and 0 in 40 with the fix, under the same load. The other
//!   ordering never came up short here, so the attach half is a latent hazard rather than an
//!   observed one.
//! - **The event that wins is the attached process's break-in.** `.lastevent` on a short round
//!   names it: `510.29b4: Break instruction exception - code 80000003 (first chance)`, on the
//!   *attached* pid. `AttachProcess` injects a thread to raise it, and under load that thread is
//!   scheduled late enough to land a whole wait after its own.
//! - **A pump must not swallow a real failure** (arm C). A launch whose image does not exist fails
//!   *inside* the wait — `Err(0x80070002)` in 13ms, no debuggee behind it, a further wait
//!   answering `E_UNEXPECTED` in 37µs — so the loop propagates rather than pumping on.
//! - **A guard may ask before it waits** (arms E, F and H). Neither opener lists its process
//!   before the wait that completes it, so the ask cannot fire on an ordinary open; a guard whose
//!   target arrived meanwhile took 29.36s and `E_UNEXPECTED` before the fix against single-digit
//!   µs after. Arm H is the same guard with a *second* target arrived since, which overwrites the
//!   engine's one slot recording where it stopped — 29.4s and `E_UNEXPECTED` when the ask reads
//!   that slot, µs when it reads a record written as each wait observed a stop. That is the
//!   argument for an arrival being delivered by the wait that observed it rather than read back
//!   from that slot afterwards.
//! - **The two endings of an open cannot meet** (arm I). An expired finite wait really is `Ok` —
//!   `S_FALSE`, which the wrapper flattens (300ms bound, returned at 311ms) — so a wait that
//!   expires while the engine holds nothing would end an open successfully with no debuggee. It
//!   cannot: a wait with no debuggee *fails* rather than expiring, `E_UNEXPECTED` in 200µs on a
//!   fresh engine and 14µs on one whose session has ended, and the loop propagates that. Both
//!   openers are `has_target` false until the wait that realises them, and an attach to a pid
//!   nothing owns is refused at `begin` (`0x80070057`) rather than at the wait. So no open passes
//!   through "returned `Ok`, holds nothing".
//! - **Membership is not the same claim as the initial break** (arm G). A process is registered
//!   when its create event is processed — `cpr` is ignored — and its loader breakpoint arrives
//!   later, so a competing break in between would end a wait with the process listed and not
//!   stopped. Arm G asks whose event the launch actually ended on and answers 0 in 40, which is
//!   **not** evidence the window is unreachable: this fixture holds exactly one competing break,
//!   the attach's injected break-in, and it is spent on the wider window before the narrower one
//!   opens. The terminal condition is tightened on the mechanism rather than on that count.
//! - **Two forcings that do not work**, recorded so they are not tried again: two pending targets
//!   and one wait (arm B) and a `SetInterrupt` before the wait (arm D) both come back with the
//!   session whole on a quiet machine. There is no deterministic reproduction of the race itself;
//!   arm F is the deterministic half, and it is a different question.
//!
//! Run: cargo run --example deferred_arrival [rounds] [spinners]

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use dbgscope::dbgeng::DebugEngine;

const LAUNCH: &str = "cmd.exe /c ping -n 30 127.0.0.1";
const WAIT_MS: u32 = 30_000;
/// How many extra pumps to give a session that came back short.
const EXTRA_PUMPS: usize = 8;

fn a_process_to_attach_to() -> Child {
    Command::new("ping")
        .args(["-n", "30", "127.0.0.1"])
        .stdout(Stdio::null())
        .spawn()
        .expect("could not start a process to attach to")
}

/// How many processes `|` lists, and the listing itself.
fn listed(e: &DebugEngine) -> (usize, String) {
    let text = e.execute_command("|").unwrap_or_default();
    (text.lines().filter(|l| l.contains("id:")).count(), text)
}

/// The system pid `|` gives for the process it says the engine `create`d.
fn created_pid(listing: &str) -> Option<u64> {
    let row = listing.lines().find(|l| l.contains("\tcreate\t"))?;
    let after = row.split("id: ").nth(1)?;
    u64::from_str_radix(after.split_whitespace().next()?, 16).ok()
}

/// The system pid `.lastevent` attributes the last event to.
fn last_event_pid(e: &DebugEngine) -> Option<u64> {
    let text = e.execute_command(".lastevent").ok()?;
    let line = text.lines().find(|l| l.contains("Last event:"))?;
    let after = line.split("Last event: ").nth(1)?;
    u64::from_str_radix(after.split('.').next()?, 16).ok()
}

/// Pumps until the session holds `want` processes, reporting how many pumps it took.
fn pump_until(e: &DebugEngine, want: usize) -> (Option<usize>, usize) {
    for pump in 1..=EXTRA_PUMPS {
        let started = Instant::now();
        let waited = e.wait_for_event(WAIT_MS);
        let (count, _) = listed(e);
        println!(
            "      pump {pump}: wait -> {:?} in {:?}, now {count} process(es)",
            waited.as_ref().map(|_| "Ok").map_err(|err| err.to_string()),
            started.elapsed()
        );
        if count >= want {
            return (Some(pump), count);
        }
    }
    let (count, _) = listed(e);
    (None, count)
}

/// CPU spinners, to reproduce the loaded runner the issue is about.
fn load(n: usize) -> Vec<Child> {
    (0..n)
        .map(|_| {
            Command::new("cmd.exe")
                .args(["/c", "for /l %i in (1,0,2) do @rem"])
                .stdout(Stdio::null())
                .spawn()
                .expect("could not start a load generator")
        })
        .collect()
}

/// Arm A: the natural race — the two openers one after the other, in both orderings, exactly as
/// `test_a_mixed_session_comes_apart_by_where_each_process_came_from` does them. Repeated, because
/// it is load-sensitive.
fn natural(rounds: usize, attach_first: bool) {
    let order = if attach_first {
        "attach_process then launch_process"
    } else {
        "launch_process then attach_process"
    };
    println!("=== A. {order} x{rounds} ===");
    let mut short = 0usize;
    let mut recovered = 0usize;
    for round in 1..=rounds {
        let mut theirs = a_process_to_attach_to();
        {
            let e = DebugEngine::new();
            let launched = if attach_first {
                e.attach_process(theirs.id()).expect("attach failed");
                e.launch_process(LAUNCH)
            } else {
                let launched = e.launch_process(LAUNCH);
                e.attach_process(theirs.id()).expect("attach failed");
                launched
            };
            let (count, text) = listed(&e);
            if count < 2 {
                short += 1;
                println!("  round {round}: openers -> {launched:?}, {count} process(es):\n{text}");
                println!(
                    "      .lastevent => {}",
                    e.execute_command(".lastevent")
                        .unwrap_or_else(|err| err.to_string())
                        .trim()
                );
                let (pumps, after) = pump_until(&e, 2);
                match pumps {
                    Some(n) => {
                        recovered += 1;
                        println!("      => the launched process arrived on pump {n}");
                    }
                    None => println!("      => still {after} after {EXTRA_PUMPS} pumps"),
                }
            }
            let _ = e.end_session();
        }
        let _ = theirs.kill();
        let _ = theirs.wait();
    }
    println!("  {order}: short {short}/{rounds}, recovered by pumping {recovered}/{short}");
}

/// Arm B: an attempt at forcing the race — two pending targets and one wait, on the theory that
/// `AttachProcess` raises its break-in at once while the launch has yet to spawn anything. It does
/// not force it: quiet, the single wait comes back with both processes. Kept because it is the one
/// shape where a launch and an attach are outstanding together, which is what the elimination in
/// `Arrival::Launched` has to survive.
fn forced() {
    println!("\n=== B. attach_process_begin + launch_process_begin, then one wait ===");
    let mut theirs = a_process_to_attach_to();
    {
        let e = DebugEngine::new();
        let attach = e.attach_process_begin(theirs.id()).expect("attach failed");
        let launch = e.launch_process_begin(LAUNCH).expect("launch failed");
        drop(attach);
        drop(launch);
        let started = Instant::now();
        let waited = e.wait_for_event(WAIT_MS);
        let (count, text) = listed(&e);
        println!(
            "  one wait -> {:?} in {:?}, {count} process(es):\n{text}",
            waited.as_ref().map(|_| "Ok").map_err(|err| err.to_string()),
            started.elapsed()
        );
        if count < 2 {
            let (pumps, after) = pump_until(&e, 2);
            match pumps {
                Some(n) => println!("  => the second target arrived on pump {n}"),
                None => println!("  => still {after} after {EXTRA_PUMPS} pumps"),
            }
        }
        let _ = e.end_session();
    }
    let _ = theirs.kill();
    let _ = theirs.wait();
    std::thread::sleep(Duration::from_millis(200));
}

/// Arm G: is membership the same claim as the initial break? Review on #133 argued it is not —
/// that a competing target's event can win *after* the launch's create-process event has put it in
/// the session's list but *before* its loader breakpoint is delivered, so a wait that stops at
/// membership can return with its own target not yet stopped. This asks the session which process
/// the event it stopped on belongs to, on every round the openers came back whole.
fn membership_against_the_break(rounds: usize) {
    println!("=== G. does the launch's own event end the wait? x{rounds} ===");
    let mut asked = 0usize;
    let mut elsewhere = 0usize;
    for round in 1..=rounds {
        let mut theirs = a_process_to_attach_to();
        {
            let e = DebugEngine::new();
            e.attach_process(theirs.id()).expect("attach failed");
            e.launch_process(LAUNCH).expect("launch failed");
            let (count, text) = listed(&e);
            match (count, created_pid(&text), last_event_pid(&e)) {
                (2, Some(ours), Some(event)) => {
                    asked += 1;
                    if event != ours {
                        elsewhere += 1;
                        println!(
                            "  round {round}: the launch returned on {event:#x}'s event, not its \
                             own ({ours:#x}):\n{text}"
                        );
                    }
                }
                other => println!("  round {round}: could not ask ({other:?}):\n{text}"),
            }
            let _ = e.end_session();
        }
        let _ = theirs.kill();
        let _ = theirs.wait();
    }
    println!("  ended on another target's event: {elsewhere}/{asked} asked, of {rounds} rounds");
}

/// Arm E: may a wait ask *before* it waits? Only if neither opener puts its process in the
/// session's list before that wait runs — an attach that reads as already there would skip its
/// break-in, leaving the target running where the caller asked for it stopped.
fn listed_before_the_wait() {
    println!("\n=== E. is a pending target listed before the wait that completes it? ===");
    let mut theirs = a_process_to_attach_to();
    {
        let e = DebugEngine::new();
        // On a session that already holds a target, so the listing is answerable at all.
        e.launch_process(LAUNCH).expect("launch failed");
        let (before, _) = listed(&e);
        let pending = e.attach_process_begin(theirs.id()).expect("attach failed");
        let (after_begin, text) = listed(&e);
        println!("  attach_process_begin: {before} process(es) -> {after_begin}:\n{text}");
        println!(
            "  is the attached pid {} listed before the wait? {}",
            theirs.id(),
            text.contains(&format!("id: {:x}\t", theirs.id()))
        );
        pending.wait().expect("attach wait failed");
        let (after_wait, text) = listed(&e);
        println!("  after the wait: {after_wait} process(es):\n{text}");
        let _ = e.end_session();
    }
    let _ = theirs.kill();
    let _ = theirs.wait();
}

/// Arm F: a guard waited *after* something else pumped its target in. `PendingTarget`'s own docs
/// describe dropping a guard and letting the target materialize at the next wait from any source,
/// so a guard still held when that happens must not go on to wait for an event that has been and
/// gone.
fn a_target_that_arrived_before_its_wait() {
    println!("\n=== F. wait() on a guard whose target is already in the session ===");
    let e = DebugEngine::new();
    let pending = e.launch_process_begin(LAUNCH).expect("launch failed");
    e.wait_for_event(WAIT_MS).expect("the outside pump failed");
    let (count, _) = listed(&e);
    let started = Instant::now();
    let waited = pending.wait();
    println!(
        "  {count} process(es) before wait(); wait() -> {:?} in {:?}",
        waited.as_ref().map(|_| "Ok").map_err(|err| err.to_string()),
        started.elapsed()
    );
    let _ = e.end_session();
}

/// Arm H: the case review raised against making the last event the terminal condition — a guard
/// whose target stopped, and then a *second* target's event overwrote the one session-wide slot
/// recording where the engine stopped. The launch guard cannot then tell its own arrival from one
/// still coming, so it pumps; what it must not do is call that a missing process.
fn a_guard_whose_event_was_overwritten() {
    println!("\n=== H. wait() on a guard whose stop was overwritten by another target ===");
    let mut theirs = a_process_to_attach_to();
    {
        let e = DebugEngine::new();
        let launch = e.launch_process_begin(LAUNCH).expect("launch failed");
        e.wait_for_event(WAIT_MS).expect("the launch pump failed");
        let attach = e
            .attach_process_begin(theirs.id())
            .expect("attach begin failed");
        e.wait_for_event(WAIT_MS).expect("the attach pump failed");
        drop(attach);
        let (count, text) = listed(&e);
        println!(
            "  {count} process(es); last stopped on pid {:?}, the launch is pid {:?}",
            last_event_pid(&e),
            created_pid(&text)
        );
        let started = Instant::now();
        let waited = launch.wait();
        println!(
            "  launch.wait() -> {:?} in {:?}",
            waited.as_ref().map(|_| "Ok").map_err(|err| err.to_string()),
            started.elapsed()
        );
        let _ = e.end_session();
    }
    let _ = theirs.kill();
    let _ = theirs.wait();
}

/// Arm I: the two endings of a live open, and whether they can meet. Review round 6 on #133 read
/// them as meeting â a finite `WaitForEvent` that expires returns `S_FALSE`, which the wrapper
/// maps to `Ok`, so an open whose target never joined would end successfully with no debuggee. The
/// question is whether a wait can *expire* while the engine holds nothing, or only fail.
///
/// The wrapper no longer flattens the two (dbgscope#136): the wait answers a `WaitOutcome`, so
/// this arm prints the distinction rather than inferring it from a duration. The measurement is
/// unchanged -- what changed is that `Expired` and `Stopped` are separate answers from the call
/// that knew.
fn what_a_wait_can_conclude() {
    println!("=== I. what a wait can conclude ===");

    fn wait_once(what: &str, e: &DebugEngine) {
        let started = Instant::now();
        let waited = e.wait_for_event(300);
        println!(
            "   {what}: wait(300) -> {:?} in {:?}; has_target {:?}",
            waited
                .as_ref()
                .map(|outcome| format!("{outcome:?}"))
                .map_err(|err| err.to_string()),
            started.elapsed(),
            e.has_target()
        );
    }

    let e = DebugEngine::new();
    wait_once("fresh engine, never had a target", &e);
    drop(e);

    let e = DebugEngine::new();
    e.launch_process(LAUNCH).expect("launch failed");
    e.end_session().expect("end_session failed");
    wait_once("after end_session", &e);
    drop(e);

    for (what, opened) in [("launch", true), ("attach", false)] {
        let mut theirs = a_process_to_attach_to();
        {
            let e = DebugEngine::new();
            let begun = if opened {
                e.launch_process_begin(LAUNCH).map(drop)
            } else {
                e.attach_process_begin(theirs.id()).map(drop)
            };
            println!(
                "   pending {what}: begin {:?}, has_target before the wait {:?}",
                begun.as_ref().map(|()| "Ok").map_err(|err| err.to_string()),
                e.has_target()
            );
            wait_once(&format!("pending {what}"), &e);
        }
        let _ = theirs.kill();
        let _ = theirs.wait();
    }

    let e = DebugEngine::new();
    println!(
        "   attach to a pid nothing owns: begin {:?}",
        e.attach_process_begin(0x000f_4240)
            .map(drop)
            .map_err(|err| err.to_string())
    );
    drop(e);

    let e = DebugEngine::new();
    e.launch_process(LAUNCH).expect("launch failed");
    wait_once("a stopped target, nothing left to report", &e);
}

/// Arm C: the failure a pump must not turn into a hang — a launch whose image does not exist.
/// The spawn is deferred, so this fails *inside* the wait, and a fix that pumps until a process
/// appears has to see that failure rather than wait out its whole deadline.
fn a_launch_that_cannot_start() {
    println!("\n=== C. launch_process on an image that does not exist ===");
    let e = DebugEngine::new();
    let started = Instant::now();
    let launched = e.launch_process("no_such_program_xyzzy.exe");
    println!(
        "  launch_process -> {launched:?} in {:?}",
        started.elapsed()
    );
    println!("  has_target -> {:?}", e.has_target());
    let (count, text) = listed(&e);
    println!("  {count} process(es): {}", text.trim());
    let started = Instant::now();
    let again = e.wait_for_event(WAIT_MS);
    println!(
        "  a further wait -> {:?} in {:?}",
        again.as_ref().map(|_| "Ok").map_err(|err| err.to_string()),
        started.elapsed()
    );
    let _ = e.end_session();
}

/// Arm D: the other attempt at forcing it — a break-in requested before the wait, on the theory
/// that it returns at once, long before a spawn that takes tens of milliseconds at best. It does
/// not: quiet, the wait still comes back with both processes in ~13ms, so DbgEng realises the
/// deferred create before it acts on the interrupt. Under load it goes short at about arm A's
/// rate, which is arm A's race and not a forcing.
fn forced_by_interrupt(rounds: usize) {
    println!("\n=== D. attach, launch_process_begin, SetInterrupt, then one wait x{rounds} ===");
    for round in 1..=rounds {
        let mut theirs = a_process_to_attach_to();
        {
            let e = DebugEngine::new();
            e.attach_process(theirs.id()).expect("attach failed");
            let pending = e.launch_process_begin(LAUNCH).expect("launch failed");
            let _ = e.interrupt_handle().interrupt();
            let started = Instant::now();
            let waited = pending.wait();
            let (count, text) = listed(&e);
            println!(
                "  round {round}: wait -> {:?} in {:?}, {count} process(es)",
                waited.as_ref().map(|_| "Ok").map_err(|err| err.to_string()),
                started.elapsed()
            );
            if count < 2 {
                println!("{text}");
                println!(
                    "      .lastevent => {}",
                    e.execute_command(".lastevent")
                        .unwrap_or_else(|err| err.to_string())
                        .trim()
                );
                let (pumps, after) = pump_until(&e, 2);
                match pumps {
                    Some(n) => println!("      => the launched process arrived on pump {n}"),
                    None => println!("      => still {after} after {EXTRA_PUMPS} pumps"),
                }
            }
            let _ = e.end_session();
        }
        let _ = theirs.kill();
        let _ = theirs.wait();
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let rounds: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(10);
    let spinners: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(0);
    let mut load = load(spinners);
    if spinners > 0 {
        println!("(running under {spinners} CPU spinners)");
    }
    membership_against_the_break(rounds.max(1));
    a_guard_whose_event_was_overwritten();
    a_target_that_arrived_before_its_wait();
    listed_before_the_wait();
    what_a_wait_can_conclude();
    a_launch_that_cannot_start();
    forced_by_interrupt(rounds.max(1));
    forced();
    natural(rounds, true);
    natural(rounds, false);
    for mut child in load.drain(..) {
        let _ = child.kill();
        let _ = child.wait();
    }
}
