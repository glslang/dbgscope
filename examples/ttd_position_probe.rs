//! Scratch experiment (not part of the public API), and the record behind [`ReplayLanding`]: what
//! a TTD replay is left at when a run on it is cut short, and whether it can be put back.
//!
//! The question came from windbg-mcp item 125. A run broken in on a replay — at its bound or by a
//! host — prints *"Replay was interrupted by the user. The current position is approximately how
//! far we had gone"*, and then the cursor is usually at the trace's **end**, past every breakpoint
//! the run had not reached, with no hit reported for any of them.
//!
//! **Measured 2026-11-06 on an x64 host**, `dbgeng` 10.0.29547.1002 and TTD 1.11.617.0, against
//! two unindexed traces recorded there: `hostname.exe` (28 MiB, three threads) and
//! `cmd.exe /c for /L %i in (1,1,20000) do @rem` (48 MiB, two threads), with a breakpoint on
//! `ntdll!RtlExitUserProcess`. The left column was read before the pumps put anything back, by an
//! earlier version of this file that drove the data model directly; the right is this one:
//!
//! | run | where TTD left it | after this change |
//! |---|---|---|
//! | `g`, unbounded | at the breakpoint: `894:1580`, `AD43:1691` | the same |
//! | `g`, 1 ms | the **end**, `8E6:0` / `AE24:0` — six runs of six | put back where it started |
//! | `g`, 5 ms | the end twice; **at** the breakpoint once (`hostname`), no hit printed | put back |
//! | `g`, 20 ms | at the breakpoint twice (`hostname`), the end once (`cmd`) | put back |
//! | `g-`, 1 ms from the breakpoint | one step back: `894:157F`, `AD43:1690` | put back |
//! | `settle` and `run_to_address`, 1 ms | — | put back; `run_to_address` says `Timeout` |
//!
//! The data model's `@$curthread.TTD.Position` reads as `Sequence`/`Steps` `VT_UI8`, and a
//! position object read **before** a run seeks back to its own position after it (`SeekTo`): about
//! 1.5 ms each time, the engine left at `DEBUG_STATUS_BREAK` with nothing to pump, the current
//! thread unchanged, and the next `g` stopping at the breakpoint. `settle` can take its mark after
//! `Execute` has set the run state: the engine reads `DEBUG_STATUS_GO` and the position still
//! reads, where the replay stood.
//!
//! And the target type says which targets are replays, which the API does not suggest: a trace
//! opened with `open_trace` answers class 2, **qualifier 2** — `DEBUG_USER_WINDOWS_IDNA` — where a
//! user minidump answers 2 / 1024 (`DebuggeeType::is_ttd_replay`). On that dump the position read
//! answers `None`.
//!
//! ```text
//! cargo run --example ttd_position_probe -- <trace.run> [<breakpoint expression>] [<dump>]
//! ```
//!
//! **The engine and TTD's replay DLLs have to be in `target/debug/examples`** (the `ttd`
//! directory beside `dbgeng.dll`) — see `breakpoint_probe.rs`. A trace is made with
//! `TTD.exe -out <dir> <program>`, elevated.

use dbgscope::dbgeng::{DebugEngine, ReplayLanding};

const WAIT_MS: u32 = 60_000;

fn report(engine: &DebugEngine, label: &str) {
    println!(
        "{label}: status {:?}, thread {:?}, ip {:x?}, position {}",
        engine.execution_status(),
        engine.current_thread_system_id(),
        engine.instruction_pointer(),
        match engine.ttd_position() {
            Ok(Some(position)) => position.to_string(),
            other => format!("{other:?}"),
        }
    );
}

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(trace) = args.next() else {
        println!("usage: ttd_position_probe <trace.run> [<breakpoint>] [<dump>]");
        return;
    };
    let breakpoint = args
        .next()
        .unwrap_or_else(|| "ntdll!RtlExitUserProcess".to_string());
    let dump = args.next();

    let engine = DebugEngine::new();
    engine.open_trace(&trace).expect("open the trace");
    println!("load: {:?}", engine.wait_for_event(WAIT_MS));
    println!(
        "type: {:?}, replay {:?}",
        engine.debuggee_type(),
        engine.debuggee_type().map(|t| t.is_ttd_replay())
    );
    let start = engine
        .ttd_position()
        .expect("read the position")
        .expect("a trace has one");
    report(&engine, "opened");
    println!(
        "bp: {:?}",
        engine.execute_command(&format!("bp {breakpoint}"))
    );

    // The control: unbounded, the replay stops at the breakpoint.
    let run = engine.execute_and_wait("g", WAIT_MS).expect("g");
    println!(
        "\nunbounded g: cut_short {:?}, replay {:?}",
        run.cut_short, run.replay
    );
    report(&engine, "  stopped");
    let hit = engine.ttd_position().ok().flatten();

    for (command, bound) in [("g", 1u32), ("g", 1), ("g", 5), ("g", 20), ("g-", 1)] {
        // Forward from the start, backward from the breakpoint, travelled to through the same
        // path a caller has.
        let origin = match command {
            "g" => Some(start),
            _ => hit,
        };
        if let Some(origin) = origin {
            let _ = engine.execute_command(&format!("!tt {origin}"));
            let _ = engine.settle(WAIT_MS);
        }
        let before = engine.ttd_position().ok().flatten();
        let run = engine
            .execute_and_wait(command, bound)
            .expect("bounded run");
        println!(
            "\n{command} bounded {bound} ms from {before:?}: cut_short {:?}, replay {:?}",
            run.cut_short, run.replay
        );
        report(&engine, "  left at");
        if let Some(ReplayLanding::Rewound { to }) = run.replay {
            assert_eq!(Some(to), before, "rewound somewhere it did not start");
        }
        if command == "g" {
            let on = engine.execute_and_wait("g", WAIT_MS).expect("g");
            println!("  then g: cut_short {:?}", on.cut_short);
            report(&engine, "  then");
            if run.replay.is_some() {
                assert_eq!(
                    engine.ttd_position().ok().flatten(),
                    hit,
                    "going on from a put-back replay did not reach the breakpoint"
                );
            }
        }
    }

    // `settle`, which reads the position after `Execute` has set the run state.
    let _ = engine.execute_command(&format!("!tt {start}"));
    let _ = engine.settle(WAIT_MS);
    let _ = engine.execute_command("g");
    report(&engine, "\nafter Execute(g), unpumped");
    let settled = engine.settle(1).expect("settle");
    println!(
        "settle 1 ms: {:?}",
        settled.map(|run| (run.cut_short, run.replay))
    );
    report(&engine, "  after settle");

    // `run_to_address`, at an address the replay reaches only at its end.
    let _ = engine.execute_command(&format!("!tt {start}"));
    let _ = engine.settle(WAIT_MS);
    if let Some(address) = hit.and_then(|_| {
        let _ = engine.execute_and_wait("g", WAIT_MS);
        let ip = engine.instruction_pointer().ok();
        let _ = engine.execute_command(&format!("!tt {start}"));
        let _ = engine.settle(WAIT_MS);
        ip
    }) {
        let _ = engine.execute_command("bc *");
        let reached = engine.run_to_address(address, 1).expect("run_to_address");
        println!(
            "\nrun_to_address {address:x}, 1 ms: {:?}, replay {:?}",
            reached.outcome, reached.replay
        );
        report(&engine, "  left at");
    }
    let _ = engine.end_session();

    if let Some(dump) = dump {
        let engine = DebugEngine::new();
        engine.open_dump(&dump).expect("open the dump");
        let _ = engine.wait_for_event(WAIT_MS);
        println!(
            "\nan ordinary dump: ttd_position {:?}",
            engine.ttd_position()
        );
        let _ = engine.end_session();
    }
}
