//! Scratch experiment (not part of the public API), and the record behind
//! [dbgscope#126](https://github.com/glslang/dbgscope/issues/126).
//!
//! It answers three questions about breakpoints that no unit test can, because each is a question
//! about what a real `dbgeng.dll` does:
//!
//! 1. **Does a symbolic location resolve eagerly, and can the resolve be interrupted?** It does,
//!    and it can. That is what makes [`DebugEngine::set_breakpoint_bounded`] a real bound rather
//!    than a promise — and the reason its result carries `cut_short` instead of being a bare
//!    `Result<(), _>`: a break comes back looking exactly like success.
//! 2. **Does the engine deduplicate breakpoints at one address?** It does not. `bp` and `bu` do,
//!    which is a different claim, and [`OnExisting`] is the answer to it.
//! 3. **What does a duplicate cost?** One stop, two activations.
//!
//! Every arm needs a live user-mode target, which it launches itself, so this needs no dump and no
//! VM. The timing arms additionally want a symbol server and an **empty** downstream store, or
//! they measure a cache hit.
//!
//! ```text
//! cargo run --example breakpoint_probe -- <arm> [symbol] [--store <dir>]
//! ```
//!
//! Arms: `resolve`, `resolve-bounded`, `dedup`, `duplicate-cost`, `command`, `data`, `all`.
//!
//! **The engine has to be in `target/debug/examples`, not `target/debug`.** An example binary runs
//! from its own directory, so a `dbgeng.dll` beside the *library's* output is not the one this
//! loads — it gets System32's, which on a host with no `symsrv.dll` cannot fetch a PDB and with no
//! `msdia140.dll` cannot parse one. Nothing fails: a symbol that happens to be **exported**
//! resolves from the export table and every other one defers, so a cold fetch that should take
//! seconds comes back in 3 ms having downloaded nothing, and every arm below quietly measures the
//! wrong engine. That is how the first run of this file "disproved" the measurement it exists to
//! record. If `resolve` reports a cold PDB in single-digit milliseconds, this is why.
//!
//! **One arm per process, and a fresh store per timing arm.** A resolve is timed only the first
//! time; everything afterwards in that session — including a second arm — reads a warm cache and
//! measures nothing. `--store <dir>` overrides the temporary directory each run makes for itself.
//! Do not print `lm` before a timing arm either: rendering the module list makes the engine fetch
//! what it needs to answer, which warms the very store being measured. That mistake cost the first
//! draft of this file its result too.
//!
//! Measured on dbgeng 10.0.29547.1002, x64, Windows 11 26200: `resolve` reports 2445 ms for a cold
//! `KERNELBASE!CreateFileW`, 151 ms warm, 0 ms for an address and 0 ms to defer.

use std::path::PathBuf;
use std::time::Instant;

use dbgscope::dbgeng::{
    BreakpointAt, BreakpointSpec, DataAccess, DataWatch, DbgEngError, DebugEngine,
};

/// A target that lives long enough to be stepped and stopped, and exits on its own if this
/// program dies holding it.
const TARGET: &str = "cmd.exe /c ping -n 60 127.0.0.1";

/// Resolved against a cold store in the timing arms.
///
/// `KERNELBASE` rather than `ntdll` because the loader break leaves `ntdll`'s symbols already
/// loaded — timing a resolve there measures a hit. Note it is an **exported** function, so an
/// engine that cannot reach a symbol server still resolves it, from the export table, in
/// milliseconds: that is a feature here, since it is what makes a wrong-engine run look plausible
/// rather than broken, and the header says how to spot one.
const COLD_SYMBOL: &str = "KERNELBASE!CreateFileW";

fn main() {
    let mut args = std::env::args().skip(1);
    let arm = args.next().unwrap_or_else(|| "all".into());
    let mut symbol = None;
    let mut store = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--store" => store = args.next().map(PathBuf::from),
            other => symbol = Some(other.to_string()),
        }
    }
    let symbol = symbol.unwrap_or_else(|| COLD_SYMBOL.to_string());

    let run = |name: &str, f: &dyn Fn(&DebugEngine, &str)| {
        println!("\n======== {name} ========");
        // A store per arm, not per run: two arms sharing one would make the second measure a hit.
        let store = store.clone().unwrap_or_else(|| {
            std::env::temp_dir().join(format!("dbgscope-bp-probe-{name}-{}", std::process::id()))
        });
        let _ = std::fs::remove_dir_all(&store);
        if let Err(e) = std::fs::create_dir_all(&store) {
            println!("could not make a symbol store at {}: {e}", store.display());
            return;
        }
        let engine = DebugEngine::new();
        let path = format!(
            "srv*{}*https://msdl.microsoft.com/download/symbols",
            store.display()
        );
        if let Err(e) = engine.set_symbol_path(&path) {
            println!("could not set the symbol path: {e}");
            return;
        }
        match engine.launch_process(TARGET) {
            Ok(()) => f(&engine, &symbol),
            Err(e) => println!("could not launch {TARGET}: {e}"),
        }
    };

    match arm.as_str() {
        "resolve" => run("resolve", &resolve),
        "resolve-bounded" => run("resolve-bounded", &resolve_bounded),
        "dedup" => run("dedup", &dedup),
        "duplicate-cost" => run("duplicate-cost", &duplicate_cost),
        "command" => run("command", &command),
        "data" => run("data", &data),
        "all" => {
            run("resolve", &resolve);
            run("resolve-bounded", &resolve_bounded);
            run("dedup", &dedup);
            run("duplicate-cost", &duplicate_cost);
            run("command", &command);
            run("data", &data);
        }
        other => {
            println!("unknown arm {other}");
            println!("arms: resolve, resolve-bounded, dedup, duplicate-cost, command, data, all");
        }
    }
}

/// Prints what the session holds, as the engine reports it.
fn held(engine: &DebugEngine, tag: &str) {
    match engine.breakpoints() {
        Ok(list) if list.is_empty() => println!("  [{tag}] no breakpoints"),
        Ok(list) => {
            for bp in list {
                println!(
                    "  [{tag}] id={} addr={} expr={:?} enabled={} deferred={} cmd={:?}",
                    bp.id,
                    bp.address
                        .map_or_else(|| "(unresolved)".into(), |a| format!("{a:#x}")),
                    bp.expression,
                    bp.enabled,
                    bp.deferred,
                    bp.command,
                );
            }
        }
        Err(e) => println!("  [{tag}] breakpoints() failed: {e}"),
    }
}

/// **Question 1a.** A symbolic location resolves eagerly, so setting a breakpoint on a symbol
/// whose PDB is not local is a symbol-server fetch with the engine held for all of it.
///
/// Three locations, cold. The contrast is the whole measurement: an address cannot block, a
/// resolvable symbol blocks for as long as the download takes, and a symbol whose *module* is
/// absent returns instantly because there is nothing to look in — it defers instead.
fn resolve(engine: &DebugEngine, symbol: &str) {
    let at = |what: &str, at: BreakpointAt| {
        let started = Instant::now();
        let result = engine.set_breakpoint(&BreakpointSpec::code(at));
        let ms = started.elapsed().as_millis();
        match result {
            Ok(set) => println!(
                "  {what}: {ms} ms -> id={} addr={} deferred={} expr={:?}",
                set.breakpoint.id,
                set.breakpoint
                    .address
                    .map_or_else(|| "(unresolved)".into(), |a| format!("{a:#x}")),
                set.breakpoint.deferred,
                set.breakpoint.expression,
            ),
            Err(e) => println!("  {what}: {ms} ms -> {e}"),
        }
    };
    at(
        "a symbol needing a cold PDB",
        BreakpointAt::Expression(symbol.into()),
    );
    at("an address", BreakpointAt::Address(0x1000));
    at(
        "a symbol whose module is absent",
        BreakpointAt::Expression("nosuchmod!NoSuchSymbol".into()),
    );
    // And again, warm — the same call against a store the line above filled.
    at(
        "the same symbol, warm",
        BreakpointAt::Expression(symbol.into()),
    );
    held(engine, "held");
}

/// **Question 1b.** The resolve is reachable by `SetInterrupt`, so the bound is real — and a break
/// is *silent*, which is why the result carries `cut_short`.
///
/// Two things to read here. The call comes back `Ok` with a breakpoint, so nothing but
/// `cut_short` distinguishes a break from a completed resolve. And the abandoned fetch is not
/// retried: the module stays on export symbols for the rest of the session, so a caller that
/// needs the PDB has to reload it.
fn resolve_bounded(engine: &DebugEngine, symbol: &str) {
    let started = Instant::now();
    let result = engine.set_breakpoint_bounded(
        &BreakpointSpec::code(BreakpointAt::Expression(symbol.into())),
        250,
    );
    let ms = started.elapsed().as_millis();
    match result {
        Ok(set) => {
            println!(
                "  bounded at 250 ms: returned after {ms} ms, cut_short={:?}",
                set.cut_short
            );
            println!(
                "  the breakpoint exists either way: id={} addr={} deferred={}",
                set.breakpoint.id,
                set.breakpoint
                    .address
                    .map_or_else(|| "(unresolved)".into(), |a| format!("{a:#x}")),
                set.breakpoint.deferred,
            );
            if set.cut_short.is_none() {
                println!(
                    "  NOTE: the resolve finished inside the bound, so this arm measured nothing. \
                     Empty the store, or lower the bound."
                );
            }
        }
        Err(e) => println!("  bounded at 250 ms: {ms} ms -> {e}"),
    }
    // The engine is healthy afterwards — a following call is not poisoned by the break.
    let started = Instant::now();
    match engine.set_breakpoint(&BreakpointSpec::code(BreakpointAt::Address(0x1000))) {
        Ok(set) => println!(
            "  a following set still works: id={} in {} ms",
            set.breakpoint.id,
            started.elapsed().as_millis()
        ),
        Err(e) => println!("  a following set failed: {e}"),
    }
    match engine.execute_command("lm m KERNELBASE") {
        Ok(out) => println!("  the module's symbol state after the break:\n{out}"),
        Err(e) => println!("  lm failed: {e}"),
    }
}

/// **Question 2.** The engine does not deduplicate; `bp` does.
///
/// Four sequences, each read through `breakpoints()` rather than through `bl`'s text. The last two
/// are the asymmetry: a `bp` collapses breakpoints this API added, and this API collapses nothing
/// unless asked.
fn dedup(engine: &DebugEngine, _symbol: &str) {
    let ntdll = "ntdll!NtCreateFile";
    let spec = || BreakpointSpec::code(BreakpointAt::Expression(ntdll.into()));

    println!("-- three typed sets, OnExisting::Add (the engine's own behaviour)");
    for _ in 0..3 {
        if let Err(e) = engine.set_breakpoint(&spec()) {
            println!("  set failed: {e}");
        }
    }
    held(engine, "after three adds");

    println!("-- one typed set with OnExisting::Replace");
    match engine.set_breakpoint(&spec().replacing_existing()) {
        Ok(set) => println!("  id={} replaced={:?}", set.breakpoint.id, set.replaced),
        Err(e) => println!("  set failed: {e}"),
    }
    held(engine, "after the replace");

    println!("-- `bp` over the top of it");
    match engine.execute_command(&format!("bp {ntdll}")) {
        Ok(out) => println!("  bp said: {out:?}"),
        Err(e) => println!("  bp failed: {e}"),
    }
    held(engine, "after bp");

    // A deferred expression has no address to key on, so nothing can deduplicate it — which is
    // why `Replace` reports an empty `replaced` here rather than pretending.
    println!("-- three deferred sets, OnExisting::Replace");
    for _ in 0..3 {
        match engine.set_breakpoint(
            &BreakpointSpec::code(BreakpointAt::Expression("nosuchmod!Sym".into()))
                .replacing_existing(),
        ) {
            Ok(set) => println!(
                "  id={} deferred={} replaced={:?}",
                set.breakpoint.id, set.breakpoint.deferred, set.replaced
            ),
            Err(e) => println!("  set failed: {e}"),
        }
    }
    held(engine, "after three deferred");
}

/// **Question 3.** Two breakpoints at one address stop the target **once** and activate **both**.
///
/// So a duplicate is not a double stop — but every breakpoint there runs its own command, and
/// removing one by id leaves the address armed by the other. That pair of facts is what
/// [`OnExisting::Replace`] exists for, and what makes a duplicate matter to a caller installing a
/// logging breakpoint rather than merely untidy.
fn duplicate_cost(engine: &DebugEngine, _symbol: &str) {
    let ntdll = "ntdll!NtCreateFile";
    let mut ids = Vec::new();
    for n in 0..2 {
        match engine.set_breakpoint(
            &BreakpointSpec::code(BreakpointAt::Expression(ntdll.into()))
                .with_command(format!(".echo breakpoint {n} ran its command")),
        ) {
            Ok(set) => ids.push(set.breakpoint.id),
            Err(e) => println!("  set failed: {e}"),
        }
    }
    println!("  armed two breakpoints at one address: {ids:?}");
    held(engine, "armed");

    match engine.execute_and_wait("g", 20_000) {
        Ok(run) => {
            println!("  the stop reported:");
            for line in run
                .output
                .lines()
                .filter(|l| l.contains("Breakpoint") || l.contains("ran its command"))
            {
                println!("    {line}");
            }
            println!(
                "  cut_short={:?} target_gone={}",
                run.cut_short, run.target_gone
            );
        }
        Err(e) => println!("  g failed: {e}"),
    }
    match engine.instruction_pointer() {
        Ok(pc) => println!("  stopped once, at {pc:#x}"),
        Err(e) => println!("  could not read the instruction pointer: {e}"),
    }

    // And the hazard: removing one leaves the address armed by the other.
    if let Some(first) = ids.first() {
        match engine.remove_breakpoint(*first) {
            Ok(()) => println!("  removed breakpoint {first}"),
            Err(e) => println!("  removing {first} failed: {e}"),
        }
        held(engine, "after removing one of the two");
    }
}

/// A command string arrives **intact**, which is the point of the whole primitive.
///
/// The one this sets contains both characters that make the text hatch dangerous: a `;`, which
/// DbgEng reads as a command separator, and a `"`, which opens the quoted command string that
/// `bp` takes. Built as text, a caller's operand carrying either is either an injection or has to
/// be escaped by hand; as a **parameter** it is neither, and reading it back through `GetCommand`
/// is what says so.
///
/// This is the case `windbg-mcp`'s `ioctl_trace` hand-builds today, quotes and all.
fn command(engine: &DebugEngine, _symbol: &str) {
    let wanted = r#".printf "IOCTL %08x\n", dwo(@rdx+0x18); gc"#;
    match engine.set_breakpoint(
        &BreakpointSpec::code(BreakpointAt::Expression(
            "ntdll!NtDeviceIoControlFile".into(),
        ))
        .with_command(wanted),
    ) {
        Ok(set) => {
            let got = set.breakpoint.command.as_deref();
            println!("  asked for: {wanted}");
            println!("  engine has: {}", got.unwrap_or("(nothing)"));
            println!(
                "  identical: {}",
                if got == Some(wanted) {
                    "yes — nothing was escaped, quoted or split"
                } else {
                    "NO — the command did not survive"
                }
            );
        }
        Err(e) => println!("  could not set a command breakpoint: {e}"),
    }
}

/// A data breakpoint, which the read side has always been able to *report* and nothing could set.
///
/// Also the refusals: a size the processor has no register for, and an address not aligned to it.
/// Both are refused here rather than by the engine, which takes them and then rejects the
/// **resume**.
fn data(engine: &DebugEngine, _symbol: &str) {
    let watch = DataWatch {
        access: DataAccess::Write,
        size: 8,
    };
    // An address in the target that certainly exists and is aligned: where it is stopped. A write
    // watch there is unusual and beside the point — what this arm is about is that a data
    // breakpoint can be *set* at all, which nothing in this crate could do before.
    let Ok(address) = engine.instruction_pointer().map(|pc| pc & !7) else {
        println!("  could not read the instruction pointer; skipping the live half");
        return;
    };
    match engine.set_breakpoint(&BreakpointSpec::data(BreakpointAt::Address(address), watch)) {
        Ok(set) => println!(
            "  8-byte write watch at {address:#x}: id={} kind={:?}",
            set.breakpoint.id, set.breakpoint.kind
        ),
        Err(e) => println!("  could not set a data breakpoint: {e}"),
    }
    held(engine, "held");

    for (why, spec) in [
        (
            "a 3-byte watch",
            BreakpointSpec::data(
                BreakpointAt::Address(address),
                DataWatch {
                    access: DataAccess::ReadWrite,
                    size: 3,
                },
            ),
        ),
        (
            "an unaligned 8-byte watch",
            BreakpointSpec::data(BreakpointAt::Address(address | 1), watch),
        ),
    ] {
        match engine.set_breakpoint(&spec) {
            Ok(_) => println!("  {why} was ACCEPTED — the validation has regressed"),
            Err(DbgEngError::InvalidBreakpoint(why_not)) => {
                println!("  {why} refused before the engine saw it: {why_not}")
            }
            Err(e) => println!("  {why} failed for another reason: {e}"),
        }
    }
}
