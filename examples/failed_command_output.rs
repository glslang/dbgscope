//! Scratch experiment (not part of the public API), and the record behind
//! [`DbgEngError::CommandFailedWithOutput`].
//!
//! The question: when `Execute` returns a failure, is the engine's own account of why in the
//! output this crate captures for the call, or only on some other client's console? `cdb` prints
//! it — `^ Illegal debuggee error in '||1s'` — and that shows the engine emits the line, not that
//! it lands in a capture made with `DEBUG_OUTCTL_THIS_CLIENT`. Until the variant existed the
//! capture was dropped on the error path, so nothing could have said.
//!
//! **It does land there.** Measured 2026-10-14 on an ARM64 host against a user-mode dump, on
//! dbgeng 10.0.29617.1000 and on 10.0.26100.1742, and the two answered byte for byte alike. Every
//! failure below is `0x80040205`, and the capture is what tells them apart:
//!
//! | command | path | captured |
//! |---|---|---|
//! | `zzzz` | both | `Couldn't resolve error at 'zzz'` |
//! | `? ntdll!Nope`, `u ntdll!Nope`, `dd ntdll!Nope` | bounded | `Couldn't resolve error at 'ntdll!Nope'` |
//! | `.echo before the failure; zzzz` | bounded | `before the failure`, then the line above |
//! | `g` | `execute_and_wait` | `^ No runnable debuggees error in 'g'` |
//! | `||1s`, after `.opendump` of a second dump | bounded | `^ Illegal debuggee error in '||1s'` |
//!
//! Each capture starts with the command's own echo, as a successful one does. The unbounded
//! `zzzz` also carried a symbol warning the bounded one did not, because it ran first and the
//! engine loads the image's symbols on first use: a capture is whatever the call printed, not only
//! the complaint.
//!
//! **And these do not fail at all**, which is the half to know before asserting on a refusal:
//! `dd 0 L4` answers `????????` four times, `dt ntdll!_NOPE` answers `Symbol ntdll!_NOPE not
//! found.`, `!nosuchextension` answers `No export nosuchextension found`, and `x ntdll!Nope` and
//! `lm m nope` answer with no match — every one of them `Ok`. Among the lookups measured, then, an
//! argument the expression evaluator cannot resolve fails, while a command that looked something up
//! and found nothing succeeds and says so. That is a reading of the commands in this file, not a
//! rule the engine documents.
//!
//! ```text
//! cargo run --example failed_command_output -- <dump> [<second dump>]
//! ```
//!
//! With a second dump it also adds that dump as a second system (`.opendump`) and asks for it
//! before any wait has loaded it, which is the `||1s` case. Any user-mode dump will do for both.
//!
//! **The engine has to be in `target/debug/examples`** — see `breakpoint_probe.rs`. Nothing here
//! depends on symbols, but the answer is a reading of whichever `dbgeng.dll` loaded, so the first
//! thing printed is its version.

use dbgscope::dbgeng::{DbgEngError, DebugEngine};

/// Long enough for the engine to read a dump off a cold disk. A bound, not a measurement.
const WAIT_MS: u32 = 60_000;

/// What `execute_command_bounded` is given. Nothing here should take more than a moment.
const BOUND_MS: u32 = 10_000;

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(first) = args.next() else {
        println!("usage: failed_command_output <dump> [<second dump>]");
        return;
    };
    let second = args.next();

    let engine = DebugEngine::new();
    if let Err(e) = engine.open_dump(&first) {
        println!("could not open {first}: {e}");
        return;
    }
    if let Err(e) = engine.wait_for_event(WAIT_MS) {
        println!("the load wait failed: {e}");
        return;
    }
    match engine.execute_command("version") {
        Ok(text) => text
            .lines()
            .filter(|line| line.contains("dbgeng") || line.contains("Version"))
            .for_each(|line| println!("engine: {}", line.trim())),
        Err(e) => println!("engine: `version` failed: {e}"),
    }

    // A mistyped command, on both of the paths a caller's text takes.
    unbounded(&engine, "zzzz");
    bounded(&engine, "zzzz");
    // Output the command list produced before the segment that failed.
    bounded(&engine, ".echo before the failure; zzzz");
    // Which failures come back as an error at all. Each of these names something that is not
    // there, and the engine says so in every case; what differs is whether `Execute` also fails.
    for command in [
        "dd 0 L4",
        "? ntdll!Nope",
        "u ntdll!Nope",
        "dd ntdll!Nope",
        "x ntdll!Nope",
        "dt ntdll!_NOPE",
        "lm m nope",
        "!nosuchextension",
    ] {
        bounded(&engine, command);
    }
    // Execution control on a target that cannot run.
    match engine.execute_and_wait("g", BOUND_MS) {
        Ok(run) => println!("\n== execute_and_wait `g`: Ok\n{}", run.output),
        Err(e) => failed("execute_and_wait `g`", &e),
    }

    if let Some(second) = second {
        bounded(&engine, &format!(".opendump {second}"));
        bounded(&engine, "||");
        // Named before any wait has loaded it.
        bounded(&engine, "||1s");
    }
}

fn unbounded(engine: &DebugEngine, command: &str) {
    match engine.execute_command(command) {
        Ok(text) => println!("\n== execute_command `{command}`: Ok\n{text}"),
        Err(e) => failed(&format!("execute_command `{command}`"), &e),
    }
}

fn bounded(engine: &DebugEngine, command: &str) {
    match engine.execute_command_bounded(command, BOUND_MS) {
        Ok(run) => println!(
            "\n== execute_command_bounded `{command}`: Ok (cut short: {:?})\n{}",
            run.cut_short, run.output
        ),
        Err(e) => failed(&format!("execute_command_bounded `{command}`"), &e),
    }
}

fn failed(what: &str, error: &DbgEngError) {
    println!("\n== {what}: Err `{error}`");
    match error.output() {
        Some(output) => println!("captured {} bytes:\n{output:?}", output.len()),
        None => println!("no capture on this error"),
    }
}
