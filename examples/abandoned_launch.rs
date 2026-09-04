//! Scratch measurement for dbgscope#141 (not part of the public API): a launch guard dropped
//! **before** anything pumps leaves its `Waiting` entry removed and no exclusion behind it, while
//! `CreateProcessWide` is still queued. Whose process does the *next* launch get?
//!
//! The issue was written from reasoning. Both of its load-bearing claims needed measuring, and the
//! first draft of this file measured the wrong thing:
//!
//! - **A.** How many queued creates does **one** `WaitForEvent` realise? If a single pump realises
//!   both, then counting the session when `wait()` returns cannot tell a guard satisfied by its own
//!   process from one satisfied by its predecessor's — which is what the first version of this
//!   example did, and why it reported "waited for its own process" for a case it had not tested.
//!
//! - **B.** Does a launch whose image does not exist fail at `launch_process_begin`, or later
//!   inside the wait? This decides whether the fix is hard. `deferred_arrival`'s arm C says "fails
//!   *inside* the wait", but that arm calls the combined `launch_process`, which cannot tell the
//!   two apart — the error comes back from one call either way. windbg-mcp's `worker.rs` says the
//!   opposite and claims a live check.
//!
//! - **C.** The contract itself, observed rather than inferred: when the second guard's `wait()`
//!   returns, is that guard's **own program** in the session? Distinguishable images (`cmd.exe`
//!   then `ping.exe`) rather than a count, because a count cannot answer it. **This arm reports
//!   0 short and that is not the all-clear it looks like**: it reads *membership*, and membership
//!   is exactly the weaker claim this crate is built on not confusing with having stopped. The
//!   defect is real and is caught by reading the register instead --
//!   `test_an_abandoned_launch_does_not_hand_its_process_to_the_next_one`, which needs internals
//!   this example does not have. Kept as the record of what the public surface can and cannot
//!   see.

use dbgscope::dbgeng::DebugEngine;
use std::time::Instant;

/// The session's process listing, through the public surface only — the same `|` reading
/// `deferred_arrival` uses, since `session_processes` is private to the crate.
fn listing(e: &DebugEngine) -> String {
    e.execute_command("|").unwrap_or_default()
}

fn count(listing: &str) -> usize {
    listing.lines().filter(|l| l.contains("id:")).count()
}

/// Arm A: does one pump realise one queued create, or all of them?
fn how_many_creates_one_pump_realises() {
    println!("\n=== A. two queued creates, one explicit wait ===");
    let e = DebugEngine::new();
    let first = e.launch_process_begin("cmd.exe /c ping -n 30 127.0.0.1");
    let second = e.launch_process_begin("ping.exe -n 30 127.0.0.2");
    println!(
        "  both begun: {:?} / {:?}, session {} process(es)",
        first.is_ok(),
        second.is_ok(),
        count(&listing(&e))
    );
    // Neither guard is waited on: this arm is about the pump, not about delivery.
    drop(first);
    drop(second);
    for pump in 1..=3 {
        let started = Instant::now();
        let waited = e.wait_for_event(20_000);
        println!(
            "  pump {pump}: {:?} in {:?}, session now {} process(es)",
            waited.as_ref().map(|_| "Ok").map_err(|err| err.to_string()),
            started.elapsed(),
            count(&listing(&e))
        );
    }
    let _ = e.end_session();
}

/// Arm B: the question the fix turns on — where does a bad image fail?
fn where_a_bad_image_fails() {
    println!("\n=== B. launch_process_begin on an image that does not exist ===");
    let e = DebugEngine::new();
    let started = Instant::now();
    let begun = e.launch_process_begin("no_such_program_xyzzy.exe");
    println!(
        "  launch_process_begin -> {:?} in {:?}",
        begun
            .as_ref()
            .map(|_| "Ok(guard)")
            .map_err(|e| e.to_string()),
        started.elapsed()
    );
    match begun {
        Err(_) => println!(
            "  => fails AT BEGIN, so a guard for a launch that never starts is not constructible \
             and nothing has to retire one."
        ),
        Ok(guard) => {
            let waited = guard.wait();
            println!(
                "  guard.wait() -> {:?}",
                waited.as_ref().map(|()| "Ok").map_err(|e| e.to_string())
            );
            println!("  => fails IN THE WAIT, so a kept entry needs something to retire it.");
        }
    }
    let _ = e.end_session();
}

/// Arm C: the contract. Abandon a launch, launch a **different program**, and ask whether that
/// second guard's own process is in the session when its `wait()` returns.
fn does_the_next_launch_get_its_own_process(round: usize) -> bool {
    let e = DebugEngine::new();
    let first = e.launch_process_begin("cmd.exe /c ping -n 30 127.0.0.1");
    drop(first); // abandoned before anything pumps: the create is still queued.

    let Ok(second) = e.launch_process_begin("ping.exe -n 30 127.0.0.2") else {
        println!("  round {round}: the second launch would not begin");
        return true;
    };
    let waited = second.wait();
    let text = listing(&e);
    let mine = text.contains("ping.exe");
    println!(
        "  round {round}: wait() -> {:?}, {} process(es), own program present: {mine}{}",
        waited.as_ref().map(|()| "Ok").map_err(|e| e.to_string()),
        count(&text),
        if mine { "" } else { "   <-- SHORT" }
    );
    let _ = e.end_session();
    mine
}

fn main() {
    where_a_bad_image_fails();
    how_many_creates_one_pump_realises();
    println!("\n=== C. abandon a launch, then launch a different program ===");
    println!("  (SHORT = wait() returned before this guard's own process was there)");
    let short = (1..=10)
        .filter(|round| !does_the_next_launch_get_its_own_process(*round))
        .count();
    println!("  short in 10: {short}");
}
