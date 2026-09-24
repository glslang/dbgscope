//! Opt-in live probe: what, if anything, holds a user heap walk short of `Complete`.
//!
//! ```text
//! cargo run --example heap_coverage -- 6176                 # a live process, by pid
//! cargo run --example heap_coverage -- C:\dumps\sihost.dmp  # or a user-mode dump
//! cargo run --example heap_coverage -- C:\dumps\sihost.dmp 0x1ec81102040
//! ```
//!
//! Walks every Segment Heap in the target, then asks the **memory manager** about every gap the
//! walk filed — which is the question `PoolState::Uncommitted` turns on, and the only way to
//! tell a reserved subsegment tail from a page the process has and the debugger could not read.
//! With an address as a second argument it answers that one question and nothing else, which is
//! how the dump direction is checked: a page a thin dump does not carry still answers
//! `Committed`, and reading it still fails.
//!
//! Nothing here is asserted, because nothing here is a property of this crate — it is a reading
//! of whatever target it is pointed at. Set `_NT_SYMBOL_PATH`, or the public symbol server is
//! used.

use std::collections::BTreeMap;
use std::time::Duration;

use dbgscope::dbgeng::{DebugEngine, VirtualState};
use dbgscope::heap::{self, HeapState, HeapWalk};

/// The walk's budget. Generous: this is a probe, and a run that expires reports the budget
/// rather than the target.
const BUDGET: Duration = Duration::from_secs(120);

fn open(target: &str) -> Result<DebugEngine, Box<dyn std::error::Error>> {
    let engine = DebugEngine::new();
    engine.set_symbol_path(&std::env::var("_NT_SYMBOL_PATH").unwrap_or_else(|_| {
        "srv*C:\\ProgramData\\dbg\\sym*https://msdl.microsoft.com/download/symbols".into()
    }))?;
    match target.parse::<u32>() {
        // Already includes the break-in wait.
        Ok(pid) => engine.attach_process(pid)?,
        Err(_) => {
            engine.open_dump(target)?;
            engine.wait_for_event(60_000)?;
        }
    }
    // The heap walker needs `ntdll`'s private types, and a deferred module has none.
    engine.execute_command(".reload /f ntdll.dll")?;
    Ok(engine)
}

fn describe(state: VirtualState) -> String {
    match state {
        VirtualState::Committed => "committed".to_string(),
        VirtualState::Reserved => "reserved".to_string(),
        VirtualState::Free => "free".to_string(),
        VirtualState::Unknown(state) => format!("unknown state {state:#x}"),
    }
}

fn coverage(target: &str) -> Result<(), Box<dyn std::error::Error>> {
    let engine = open(target)?;
    let answer = heap::allocations(&engine, HeapWalk::refreshed().within(BUDGET))?;
    println!(
        "coverage {:?}: {} chunks, {} unreadable gaps, {} uncommitted gaps",
        answer.walk.coverage,
        answer.found.len(),
        answer.walk.unreadable_gaps,
        answer.walk.uncommitted_gaps
    );
    println!(
        "  refused {} headers, {:#x} unplaced bytes, {:?}",
        answer.walk.refused_headers, answer.walk.unplaced_bytes, answer.walk.stalls
    );

    // Every gap, against the memory manager — one row per answer, sized. A walk that reports
    // `Complete` should have nothing but reserved runs here; anything committed is memory the
    // target has and the walk did not see, and is what the coverage figure is about.
    let mut tally: BTreeMap<String, (usize, u64)> = BTreeMap::new();
    let mut note = |label: String, bytes: u64| {
        let row = tally.entry(label).or_insert((0, 0));
        row.0 += 1;
        row.1 += bytes;
    };
    for gap in answer.found.iter().filter(|gap| !gap.state.is_chunk()) {
        let mut cursor = gap.header_address;
        let end = gap.end();
        while cursor < end {
            match engine.virtual_region(cursor) {
                Ok(region) if region.contains(cursor) => {
                    let stop = region.end().unwrap_or(end).min(end).max(cursor + 1);
                    note(
                        format!("{:?} / {}", gap.state, describe(region.state)),
                        stop - cursor,
                    );
                    cursor = stop;
                }
                Ok(region) => {
                    note(
                        format!(
                            "{:?} / answered about {:#x}+{:#x}",
                            gap.state, region.base, region.size
                        ),
                        end - cursor,
                    );
                    break;
                }
                Err(why) => {
                    note(format!("{:?} / no answer: {why}", gap.state), end - cursor);
                    break;
                }
            }
        }
    }
    for (label, (runs, bytes)) in &tally {
        println!("  {label}: {runs} runs, {bytes:#x} bytes");
    }

    // Controls. A chunk the walk *did* read has to come back committed; if it does not, the
    // rows above are measuring the query rather than the target.
    for state in [HeapState::Allocated, HeapState::ReusableFree] {
        if let Some(chunk) = answer.found.iter().find(|chunk| chunk.state == state) {
            println!(
                "  control {state:?} {:#x}: {}",
                chunk.user_address,
                engine.virtual_region(chunk.user_address).map_or_else(
                    |why| format!("no answer: {why}"),
                    |region| describe(region.state)
                )
            );
        }
    }

    let diagnostics = heap::diagnostics(&engine, HeapWalk::cached())?;
    for shape in &diagnostics.found.categories {
        println!("  {} x {}", shape.total, shape.shape);
    }
    engine.end_session()?;
    Ok(())
}

fn one_address(target: &str, address: u64) -> Result<(), Box<dyn std::error::Error>> {
    let engine = open(target)?;
    println!("{address:#x}: {:?}", engine.virtual_region(address));
    println!(
        "  read: {:?}",
        engine.read_memory(address, 8).map(|bytes| bytes.len())
    );
    engine.end_session()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.as_slice() {
        [target] => coverage(target),
        [target, address] => one_address(
            target,
            u64::from_str_radix(address.trim_start_matches("0x"), 16)?,
        ),
        _ => Err("usage: heap_coverage <pid|dump> [address]".into()),
    }
}
