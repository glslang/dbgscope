//! Scratch experiment (not part of the public API): what a **child-process** event does to the
//! two things a caller might use as a target identity — the session's process *set*
//! ([`DebugEngine::session_processes`]) and the engine's *current* process
//! ([`DebugEngine::current_process_system_id`]).
//!
//! The question it settles is not whether the set changes — of course it does — but whether the
//! **selection moves with it**. If a child appearing also makes the child current, then every
//! read a caller makes afterwards is of the child rather than of the process they opened, and a
//! handle that went on certifying the original is certifying something it cannot deliver. If the
//! selection stays put, a child is a bystander and the set changing is a false alarm.
//!
//! ```text
//! cargo run --example child_process_identity
//! ```
//!
//! The engine has to be in `target/debug/examples`; see `breakpoint_probe`'s header.
//!
//! Measured on dbgeng 10.0.26100.1 (ARM64, 2026-09-25), launching `cmd.exe /c ping -n 2`:
//!
//! ```text
//!   at the initial break         set=[2368]       current=2368
//!   after .childdbg 1            set=[2368]       current=2368
//!   g #1 -> Break instruction exception
//!   after g #1                   set=[1000, 2368] current=1000   <-- the child is current
//!   g #2 -> target_gone true
//! ```
//!
//! **The selection moves with the set.** The engine stops at the child's create event and makes
//! the *child* the current process, so every register read, memory read and stack walk after that
//! point is of the child rather than of the process the session was opened for — without anything
//! having been asked of the debugger. That is the answer a caller needs: a child appearing is not
//! a bystander it can ignore, because the thing its own reads resolve against has moved.

use dbgscope::dbgeng::DebugEngine;

/// A launch that spawns a child promptly: `cmd.exe` runs `ping` as a separate process.
const LAUNCH: &str = "cmd.exe /c ping -n 2 127.0.0.1";

fn show(e: &DebugEngine, tag: &str) {
    let set = e
        .session_processes()
        .map(|held| {
            let mut pids: Vec<u32> = held.into_iter().map(|(_id, pid)| pid).collect();
            pids.sort_unstable();
            pids
        })
        .map_err(|e| e.to_string());
    println!(
        "  {tag:<28} set={:?} current={:?}",
        set,
        e.current_process_system_id().map_err(|e| e.to_string())
    );
}

fn main() {
    let e = DebugEngine::new();
    if let Err(err) = e.launch_process(LAUNCH) {
        println!("launch failed: {err}");
        return;
    }
    show(&e, "at the initial break");

    // `.childdbg 1` is the only way a session here acquires a second process without a caller
    // naming `.attach` or `.create`. It is never issued by the server; it is reachable through
    // the raw command hatch, which is what makes it worth measuring.
    match e.execute_command(".childdbg 1") {
        Ok(out) => println!("  .childdbg 1 -> {}", out.trim()),
        Err(err) => println!("  .childdbg 1 ERR: {err}"),
    }
    show(&e, "after .childdbg 1");

    // Run on. With child debugging enabled the engine stops at the child's create event.
    for step in 1..=4 {
        match e.execute_and_wait("g", 20_000) {
            Ok(run) => println!(
                "  g #{step} -> target_gone {} | {}",
                run.target_gone,
                run.output.trim().lines().last().unwrap_or("").trim()
            ),
            Err(err) => {
                println!("  g #{step} ERR: {err}");
                break;
            }
        }
        show(&e, &format!("after g #{step}"));
        if !e.has_target().unwrap_or(false) {
            println!("  (no target left)");
            break;
        }
    }
}
