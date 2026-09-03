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
//! ## Result (x64 bench, Windows 11 26200, in-box dbgeng, 2026-09-03; runs identical)
//!
//! **The hypothesis holds, and the four arms separate cleanly.**
//!
//! | arm | what was arranged | five `GetInterrupt` polls after |
//! |---|---|---|
//! | A | a `SetInterrupt` ended a running `WaitForEvent` | `[false, false, false, false, false]` |
//! | B | a `SetInterrupt` with nothing waiting (control) | `[true, false, false, false, false]` |
//! | C | two back to back, around one wait (corroborating) | `[false, false, false, false, false]` |
//! | D | a second lodged 400 ms *after* that wait returned | `[true, false, false, false, false]` |
//!
//! A is the hypothesis: a request that ended a wait has been consumed by the engine before the
//! wait returns. B is the control that makes A's `false` mean something — without it, a `false`
//! is indistinguishable from a probe that cannot read anything. D is the residue in the flesh: a
//! request aimed at an operation that has already ended is filed against nothing (it reports
//! `NothingRunning`), is still delivered, and is still readable afterwards — so it is the **next**
//! operation that will be stopped by it.
//!
//! **C corroborates and does not establish**, which took two review rounds to get right. It asks
//! whether a second request survives a wait that consumed the first, and it cannot control the
//! interleaving it needs: `interrupt()` releases its lock between the two calls, and the waiter is
//! blocked inside `WaitForEvent` where no lock on this side can hold it, so DbgEng may already have
//! consumed the first request and begun unwinding while the second is delivered. The timestamp
//! check the arm prints is **necessary and not sufficient** — it rules the bad ordering out when it
//! fails, and does not rule it in when it passes. The deterministic version of the question is
//! `test_get_interrupt_drain_semantics`, which needs no wait and therefore no race: three
//! `SetInterrupt`s then five polls read `[true, false, false, false, false]`, so the engine's
//! pending request is **a flag and not a counter**. That is what says D's `true` cannot merely be
//! the leftover second of a pair — there is no second, only one flag.
//!
//! (C was first written as D by accident, with a 50 ms gap between the two requests that turned out
//! to be far longer than the wait took to unwind. It measured a real thing and not the thing its
//! name claimed. Two arms now, with the gap stated in each.)
//!
//! **Every arm asserts its preconditions before it draws a conclusion**, because each has a vacuous
//! pass in the direction that matters: an interrupt that was never delivered leaves the wait to
//! expire on its own clock and every poll then reads `false`, which is exactly the shape of "the
//! hypothesis holds". So each arm requires the delivery it needs (a `BreakRequest`) and the ending
//! it needs (`WaitOutcome::OnRequest`) before it reads a poll. Printing them beside the conclusion
//! is not enough — a conclusion a reader has to audit is one this file should not be drawing.
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

use dbgscope::dbgeng::{BreakRequest, DebugEngine, WaitOutcome};

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
        let filed = asked.join().expect("the asking thread panicked");

        // **Both halves asserted before a single poll is read.** Without them this arm passes
        // vacuously in the one direction that matters: a `SetInterrupt` that *failed* leaves the
        // wait to expire on its own clock, the five polls all read `false` for want of any request
        // at all, and the arm prints that the hypothesis holds having tested nothing. Printing the
        // wait beside the conclusion is not enough -- a conclusion a reader has to audit is one
        // this file should not be drawing.
        let filed = filed.expect("the interrupt was not delivered, so this arm tested nothing");
        assert!(
            matches!(filed, BreakRequest::Raised { .. }),
            "the interrupt was filed as {filed:?}, so no operation was there to be ended by it"
        );
        assert_eq!(
            waited.as_ref().ok(),
            Some(&WaitOutcome::OnRequest),
            "the wait ended as {waited:?} rather than on the break, so nothing here is under test"
        );

        let polls: Vec<bool> = (0..5).map(|_| e.interrupted().unwrap()).collect();
        println!("A. a SetInterrupt that ended a running WaitForEvent");
        println!("   wait -> {waited:?}, request {filed:?}");
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
        let filed = e.interrupt_handle().interrupt().expect("interrupt failed");
        // Asserted for the same reason as arm A: a request that never went would read `false` here
        // and be reported as a probe that cannot read anything, which is the opposite of what this
        // control is for.
        assert_eq!(
            filed,
            BreakRequest::NothingRunning,
            "the engine had an operation running, so this is not the control it claims to be"
        );

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

    // --- C: two requests back to back, around one wait ----------------------------------
    //
    // **This arm corroborates; it does not establish.** Two review rounds landed on it, and the
    // second was right that the first fix was not enough: the timestamp below proves only that the
    // second `interrupt()` returned before the *Rust* caller timestamped the completed wait, and
    // DbgEng may already have consumed the first request and begun unwinding while the second was
    // delivered. There is no fix for that here -- the waiter is blocked inside `WaitForEvent`, so
    // no lock on this side can stop it progressing between the two deliveries. So what changes is
    // the claim, not the code.
    //
    // The deterministic version of the question is `test_get_interrupt_drain_semantics`, which
    // needs no wait and therefore no race: three `SetInterrupt`s followed by five polls read
    // `[true, false, false, false, false]`, so the engine's pending request is **a flag and not a
    // counter**. That is what says arm D's post-wait `true` cannot merely be "the leftover second
    // of a pair" -- there is no second, only one flag. This arm adds the observation under a wait,
    // and its check below is necessary rather than sufficient.
    {
        let mut theirs = a_target();
        let e = DebugEngine::new();
        e.attach_process(theirs.id()).expect("attach failed");
        e.execute_command("g").expect("could not set it running");

        let handle = e.interrupt_handle();
        let asked = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            // No gap, so both have the best chance of being in flight at once.
            let first = handle.interrupt();
            let second = handle.interrupt();
            (first, second, Instant::now())
        });
        let waited = e.wait_for_event(15_000);
        let returned = Instant::now();
        let (first, second, both_issued) = asked.join().expect("the asking thread panicked");

        // Both delivered, or this arm is about one request and should say so. Same reason as A.
        first.expect("the first interrupt was not delivered");
        second.expect("the second interrupt was not delivered");
        assert_eq!(
            waited.as_ref().ok(),
            Some(&WaitOutcome::OnRequest),
            "the wait ended as {waited:?} rather than on a break, so nothing here is under test"
        );

        let polls: Vec<bool> = (0..5).map(|_| e.interrupted().unwrap()).collect();
        // Necessary and not sufficient, which is what the second review round was about: `false`
        // here rules the bad interleaving out, `true` does not rule it in.
        let both_in_flight = returned >= both_issued;
        println!("C. two SetInterrupts back to back, around one wait");
        println!("   wait -> {waited:?}");
        println!(
            "   the wait returned to Rust {} the second request was issued{}",
            if both_in_flight { "after" } else { "BEFORE" },
            if both_in_flight {
                " (necessary for both to have been in flight, not sufficient)"
            } else {
                ""
            }
        );
        println!("   five GetInterrupt polls afterwards: {polls:?}");
        println!(
            "   -> {}\n",
            match (both_in_flight, polls == [false; 5]) {
                (true, true) =>
                    "nothing survived -- consistent with the flag semantics \
                                 test_get_interrupt_drain_semantics pins deterministically",
                (true, false) =>
                    "a second request survived the wait, which a flag cannot do -- \
                                  worth chasing against that test",
                (false, _) =>
                    "INCONCLUSIVE: the wait was over before the second request went, so \
                               this ran arm D and says nothing about two at once",
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
        let (first, second) = asked.join().expect("the asking thread panicked");

        // Same reason as arm A, and here it is the sharper trap: a *second* interrupt that never
        // went would read `false` below and be reported as "a late request leaves no trace", which
        // is the opposite of what this arm found and the one conclusion stage 3 would build on.
        first.expect("the first interrupt was not delivered");
        let late =
            second.expect("the late interrupt was not delivered, so this arm tested nothing");
        assert_eq!(
            waited.as_ref().ok(),
            Some(&WaitOutcome::OnRequest),
            "the wait ended as {waited:?} rather than on the first break, so the second was not late"
        );

        let polls: Vec<bool> = (0..5).map(|_| e.interrupted().unwrap()).collect();
        println!("D. a request lodged 400ms after the wait it was too late for");
        println!("   wait -> {waited:?}, the late request {late:?}");
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
