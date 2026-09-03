//! Scratch measurement for dbgscope#136 stage 2: **does a post-wait `GetInterrupt` tell a request
//! that ended this wait from one that did not?**
//!
//! `SetInterrupt` is engine-wide. It carries no notion of *which* operation the host aimed at, so
//! whoever is inside `WaitForEvent` when the break lands is who gets stopped — and this crate's
//! bookkeeping can say which operation a request was *lodged against* but not which wait it
//! *ended*. The gap is small but it is the residue stage 2 cannot close by bookkeeping alone: a
//! break aimed at operation N that lands on N+1 stops N+1 without N+1 knowing why.
//!
//! `note_where_it_stopped` proposed a way to close it, in a comment that survived into #136:
//!
//! > an interrupt that *ended* a wait has been consumed by the time it returns, and one still
//! > pending did not end it
//!
//! That is a hypothesis about an undocumented behaviour, and it is stated the opposite way round
//! from how it first reads — a post-wait `true` would mean "**not** this wait's". #136 says to
//! measure it against a wait it actually ended before anything depends on it. This is that
//! measurement.
//!
//! ## Result (x64 bench, Windows 11 26200, in-box dbgeng, 2026-09-03; three runs, identical)
//!
//! **The hypothesis holds, and the four arms separate cleanly.**
//!
//! | arm | what was arranged | five `GetInterrupt` polls after |
//! |---|---|---|
//! | A | a `SetInterrupt` ended a running `WaitForEvent` | `[false, false, false, false, false]` |
//! | B | a `SetInterrupt` with nothing waiting (control) | `[true, false, false, false, false]` |
//! | C | two back to back, both aimed at one wait | `[false, false, false, false, false]` |
//! | D | a second lodged 400 ms *after* that wait returned | `[true, false, false, false, false]` |
//!
//! A is the hypothesis: a request that ended a wait has been consumed by the engine before the
//! wait returns. B is the control that makes A's `false` mean something — without it, a `false`
//! is indistinguishable from a probe that cannot read anything. C says the engine's request is a
//! **flag and not a counter** on this path too, matching `test_get_interrupt_drain_semantics`: two
//! requests and one wait leave nothing behind, so a survivor is never merely the second of a pair.
//! D is the residue in the flesh — a request aimed at an operation that has already ended is
//! readable afterwards, and it is the **next** operation that will be stopped by it.
//!
//! **C checks the interleaving it needs rather than assuming it**, which a review of this file was
//! right to insist on. Nothing stops the first break unwinding the wait before the second
//! `SetInterrupt` is issued — `interrupt()` releases its lock between the two, and the waiter is
//! inside DbgEng where no lock of ours can hold it — so a run that got that ordering would be arm D
//! wearing arm C's name. The arm compares when the wait returned against when the second request
//! went and prints `INCONCLUSIVE` rather than a conclusion if it lost the race. Three runs, all of
//! them with both requests in flight. (Note the observation discriminates too, which is why the
//! first three runs were not simply wrong: had the second request landed late it would have
//! survived and C would read `[true, …]` exactly as D does. The check is there so a future run
//! says so instead of leaving that inference to a reader.)
//!
//! (C was first written as D by accident, with a 50 ms gap between the two requests that turned
//! out to be far longer than the wait took to unwind. It measured a real thing and not the thing
//! its name claimed, which is why they are now two arms with the gap stated in each — and why the
//! check above exists rather than a third careful comment.)
//!
//! **What this licenses, and what it does not.** C and D together are the useful pair: a post-wait
//! `true` means *a request survives that this wait did not consume*, and the only thing it can
//! still stop is whatever runs next. That is a **forward** signal — it can warn the next operation
//! that a break is coming for it — and not a backward one. It does **not** identify who aimed the
//! surviving request, and a post-wait `false` says only "nothing survives", which is equally true
//! of a wait an interrupt ended and of a wait nobody aimed at. So provenance needs this reading
//! *plus* the operation bookkeeping, never this alone.
//!
//! Stage 2 does not depend on any of it: the erasure it closes is closed by making the record and
//! the operation boundary mutually exclusive, which needs no engine state at all. This is here so
//! that stage 3 starts from a measurement rather than from the comment that proposed one, and
//! because #136 asks for it in as many words: *measure it against a wait it actually ended before
//! anything depends on it.*
//!
//! One engine, one host, and undocumented by Microsoft. Re-run it before building on it.
//!
//! Run: cargo run --example interrupt_provenance

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use dbgscope::dbgeng::DebugEngine;

/// A target that stays alive long enough to be resumed and broken into.
fn a_target() -> Child {
    Command::new("cmd.exe")
        .args(["/c", "ping", "-n", "30", "127.0.0.1"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("could not start a target to attach to")
}

fn main() {
    println!("=== GetInterrupt provenance: does a consumed request read differently? ===\n");

    // --- A: a request that ended a wait -------------------------------------------------
    {
        let mut theirs = a_target();
        let e = DebugEngine::new();
        e.attach_process(theirs.id()).expect("attach failed");

        // Resumed, so the break a host asks for is an event the wait below can return on.
        e.execute_command("g").expect("could not set it running");

        let handle = e.interrupt_handle();
        let asked = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            handle.interrupt()
        });
        // The wait this interrupt ends. Bounded well above the sleep so the break, and not the
        // clock, is what returns it.
        let waited = e.wait_for_event(15_000);
        asked.join().expect("the asking thread panicked").ok();

        let polls: Vec<bool> = (0..5).map(|_| e.interrupted().unwrap()).collect();
        println!("A. a SetInterrupt that ended a running WaitForEvent");
        println!("   wait -> {waited:?}");
        println!("   five GetInterrupt polls afterwards: {polls:?}");
        println!(
            "   -> {}\n",
            if polls == [false; 5] {
                "consumed by the wait, as the hypothesis says"
            } else {
                "still pending after the wait it ended -- the hypothesis is WRONG"
            }
        );

        let _ = e.end_session();
        let _ = theirs.kill();
        let _ = theirs.wait();
    }

    // --- B: the control -- a request with nothing waiting -------------------------------
    {
        let mut theirs = a_target();
        let e = DebugEngine::new();
        e.attach_process(theirs.id()).expect("attach failed");

        // Stopped, and nothing is inside WaitForEvent, so this request is delivered to nobody.
        e.interrupt_handle().interrupt().expect("interrupt failed");

        let polls: Vec<bool> = (0..5).map(|_| e.interrupted().unwrap()).collect();
        println!("B. a SetInterrupt with nothing waiting (control)");
        println!("   five GetInterrupt polls: {polls:?}");
        println!(
            "   -> {}\n",
            if polls.first() == Some(&true) {
                "readable afterwards, so arm A's answer is the engine's and not a broken probe"
            } else {
                "NOT readable -- the probe says nothing about arm A"
            }
        );

        let _ = e.end_session();
        let _ = theirs.kill();
        let _ = theirs.wait();
    }

    // --- C: two requests back to back, both aimed at one wait ---------------------------
    {
        let mut theirs = a_target();
        let e = DebugEngine::new();
        e.attach_process(theirs.id()).expect("attach failed");
        e.execute_command("g").expect("could not set it running");

        let handle = e.interrupt_handle();
        let asked = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            // No gap: both are lodged before the break can plausibly have unwound the wait, so
            // this asks whether a *second* request survives the wait that consumed the first.
            let first = handle.interrupt();
            let second = handle.interrupt();
            (first, second, Instant::now())
        });
        let waited = e.wait_for_event(15_000);
        let returned = Instant::now();
        let (_, _, both_issued) = asked.join().expect("the asking thread panicked");

        let polls: Vec<bool> = (0..5).map(|_| e.interrupted().unwrap()).collect();
        // **Checked, not assumed**, which a review of this file was right to insist on: nothing
        // stops the first break unwinding the wait before the second `SetInterrupt` is issued --
        // `interrupt()` releases its lock between the two, and the waiter is inside DbgEng where no
        // lock of ours can hold it. Had that happened, this would be arm D wearing arm C's name.
        // So the arm says which interleaving it got rather than presuming one.
        let both_in_flight = returned >= both_issued;
        println!("C. two SetInterrupts back to back, both aimed at one wait");
        println!("   wait -> {waited:?}");
        println!(
            "   the wait returned {} the second request was issued",
            if both_in_flight { "after" } else { "BEFORE" }
        );
        println!("   five GetInterrupt polls afterwards: {polls:?}");
        println!(
            "   -> {}\n",
            match (both_in_flight, polls == [false; 5]) {
                (true, true) =>
                    "a flag and not a counter: one wait consumed both, nothing survives",
                (true, false) =>
                    "a second request survived the wait -- a survivor is not proof of a missed break",
                (false, _) =>
                    "INCONCLUSIVE: the wait was over before the second request went, so \
                               this ran arm D and proves nothing about simultaneous requests",
            }
        );

        let _ = e.end_session();
        let _ = theirs.kill();
        let _ = theirs.wait();
    }

    // --- D: a request lodged after the wait it was too late for -------------------------
    {
        let mut theirs = a_target();
        let e = DebugEngine::new();
        e.attach_process(theirs.id()).expect("attach failed");
        e.execute_command("g").expect("could not set it running");

        let handle = e.interrupt_handle();
        let asked = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            let first = handle.interrupt();
            // Long enough that the wait has certainly returned on the first: this second request
            // is aimed at an operation that has already ended, which is exactly the residue
            // bookkeeping cannot close.
            std::thread::sleep(Duration::from_millis(400));
            let second = handle.interrupt();
            (first, second)
        });
        let waited = e.wait_for_event(15_000);
        let _ = asked.join().expect("the asking thread panicked");

        let polls: Vec<bool> = (0..5).map(|_| e.interrupted().unwrap()).collect();
        println!("D. a request lodged 400ms after the wait it was too late for");
        println!("   wait -> {waited:?}");
        println!("   five GetInterrupt polls: {polls:?}");
        println!(
            "   -> {}\n",
            if polls.first() == Some(&true) {
                "readable, and it is the next operation that would be stopped by it"
            } else {
                "not readable, so a late request leaves no trace to find it by"
            }
        );

        let _ = e.end_session();
        let _ = theirs.kill();
        let _ = theirs.wait();
    }

    println!("done");
}
