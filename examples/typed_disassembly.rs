//! Measurement for the typed-disassembly fields: does the operand reading survive what the engine
//! actually renders, rather than what a test composed?
//!
//! The unit tests in `dbgeng.rs` are written against renderings copied by hand. That is enough to
//! pin the *rules* and not enough to claim the parser works, because a hand-copied rendering is
//! chosen from the shapes its author already knew about. This runs the reader over a whole real
//! dispatch routine and reports what it could **not** read — the number that matters is the
//! `Other` count and the `Unknown` flow count, both of which should be zero on x64.
//!
//! It also answers the question the reading exists for: how many `cmp`/`sub` immediates inside an
//! IOCTL dispatch routine decode as plausible `CTL_CODE` values, which is the premise a static
//! IOCTL map rests on.
//!
//! ```text
//! cargo run --example typed_disassembly -- <dump> <module>!<symbol> [image search path]
//! cargo run --example typed_disassembly -- C:\dumps\kernel.dmp mountmgr!MountMgrDeviceControl \
//!     SRV*C:\sym*https://msdl.microsoft.com/download/symbols
//! ```
//!
//! A kernel minidump carries no driver code pages, so the image search path is not optional for a
//! driver that is not `nt`: without it every instruction reads `???` and the run reports exactly
//! that, which is itself the measurement of what a dump alone can answer.

use dbgscope::dbgeng::{DebugEngine, Flow, FunctionExtent, Operand};

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(dump), Some(symbol)) = (args.next(), args.next()) else {
        eprintln!("usage: typed_disassembly <dump> <module>!<symbol> [image search path]");
        std::process::exit(2);
    };
    let image_path = args.next();

    let e = DebugEngine::new();
    e.open_dump(&dump).expect("opening the dump failed");
    // `OpenDumpFileWide` only names the file; the target is loaded by the first wait, and until
    // it is there is no debuggee for a command to run against.
    e.wait_for_event(30_000)
        .expect("the dump did not load within thirty seconds");

    if let Some(path) = &image_path {
        // The engine takes an image search path the same way it takes a symbol one, and a symbol
        // server serves the image binary as well as the PDB.
        e.execute_command(&format!(".exepath+ {path}"))
            .expect("setting the image search path failed");
        e.reload_symbols("/f").expect("reloading failed");
    }

    let set = e.instruction_set();
    println!(
        "instruction set: {set:?} (operands read: {})",
        set.operands_are_read()
    );

    let entry = e
        .symbol_offset(&symbol)
        .unwrap_or_else(|error| panic!("{symbol} did not resolve: {error}"));
    println!("{symbol} at {entry:#x}");

    match e.function_extent(entry) {
        Ok(FunctionExtent::Region { begin, end }) => println!(
            "unwind region: {begin:#x}..{end:#x} ({} bytes) — a region, not the function",
            end - begin
        ),
        Ok(FunctionExtent::NoEntry) => println!("unwind region: no entry (leaf, or not code)"),
        Ok(FunctionExtent::Unsupported(set)) => {
            println!("unwind region: not decoded for {set:?}")
        }
        Err(error) => println!("unwind region: unavailable ({error})"),
    }

    // Follow the flow rather than reading forward. A linear read runs into whatever follows the
    // function and fills the candidate list with other routines' constants; the unwind region is
    // no substitute, because MSVC splits one function across several of them. The module bounds
    // the walk so a tail jump out of the driver does not take it with them.
    let module = e
        .module_at(entry)
        .ok()
        .flatten()
        .expect("the entry is in no module");
    let (low, high) = (module.base, module.base + module.size as u64);

    let mut seen = std::collections::HashSet::new();
    let mut queue = vec![entry];
    let mut instructions = Vec::new();
    while let Some(at) = queue.pop() {
        if at < low || at >= high || !seen.insert(at) || seen.len() > 20_000 {
            continue;
        }
        // Two, so the second one's address is this one's fall-through — the engine's own
        // arithmetic rather than a length guessed from the encoding.
        let Ok(pair) = e.disassemble(at, 2) else {
            continue;
        };
        let fall_through = pair.get(1).map(|next| next.address);
        let Some(instruction) = pair.into_iter().next() else {
            continue;
        };
        if let Some(target) = instruction.flow.target() {
            // A call leaves this function; every other edge stays in it.
            if !matches!(instruction.flow, Flow::Call(_)) {
                queue.push(target);
            }
        }
        if instruction.flow.falls_through() {
            queue.extend(fall_through);
        }
        instructions.push(instruction);
    }
    instructions.sort_by_key(|instruction| instruction.address);
    println!("walked {} instructions\n", instructions.len());

    let (mut unreadable, mut other_operands, mut unknown_flow) = (0usize, 0usize, 0usize);
    let mut candidates: Vec<(u64, u64)> = Vec::new();
    let mut calls: Vec<(u64, String)> = Vec::new();

    for instruction in &instructions {
        if instruction.text.starts_with('?') {
            unreadable += 1;
            continue;
        }
        if instruction.flow == Flow::Unknown {
            unknown_flow += 1;
            println!(
                "  UNKNOWN FLOW {:#x}  {}",
                instruction.address, instruction.text
            );
        }
        for operand in &instruction.operands {
            if let Operand::Other(text) = operand {
                other_operands += 1;
                println!(
                    "  UNREAD OPERAND {:#x}  {}  <- {text:?}",
                    instruction.address, instruction.text
                );
            }
        }

        // The premise: a compare against a control code, recovered as a value.
        if matches!(instruction.mnemonic.as_str(), "cmp" | "sub" | "xor" | "add")
            && let Some(Operand::Immediate(value)) = instruction.operands.get(1)
            && plausible_ioctl(*value)
        {
            candidates.push((instruction.address, *value));
        }
        if let Flow::Call(Some(target)) = instruction.flow {
            let name = e
                .symbol_for(target)
                .map(|(name, _)| name)
                .unwrap_or_else(|| format!("{target:#x}"));
            calls.push((instruction.address, name));
        }
        if let Some(Operand::Memory(memory)) = instruction.operands.first()
            && let (Flow::Call(None), Some(symbol)) = (instruction.flow, &memory.symbol)
        {
            calls.push((instruction.address, format!("[{symbol}]")));
        }
    }

    println!("\n--- what the reading could not read ---");
    println!("instructions the engine could not render: {unreadable}");
    println!("operands kept as Other:                   {other_operands}");
    println!("instructions with Unknown flow:           {unknown_flow}");

    println!(
        "\n--- plausible CTL_CODE immediates ({}) ---",
        candidates.len()
    );
    for (address, value) in &candidates {
        let value = *value;
        println!(
            "  {address:#x}  {value:#010x}  device {:#06x} function {:#05x} method {} access {}",
            (value >> 16) & 0xffff,
            (value >> 2) & 0xfff,
            value & 3,
            (value >> 14) & 3
        );
    }

    println!("\n--- direct and thunked calls ({}) ---", calls.len());
    for (address, name) in &calls {
        println!("  {address:#x}  {name}");
    }
}

/// The `CTL_CODE` shape: a device type that is not zero, and a value that is not something else
/// with the same bit width.
///
/// The exclusions are measured, not defensive. An unbounded first run over `mountmgr` offered
/// `0x80000005` and `0xc0000023` as control codes; both are `NTSTATUS` — `STATUS_BUFFER_OVERFLOW`
/// and `STATUS_BUFFER_TOO_SMALL` — compared against a return value in a routine further down the
/// image, and `0xffffffff` came from a compare against -1. A control code's top bit is clear in
/// every code Windows defines, which is what separates the three.
fn plausible_ioctl(value: u64) -> bool {
    if value == 0 || value > u32::MAX as u64 {
        return false;
    }
    // `NTSTATUS` severity lives in the top two bits; a defined control code has none set.
    if value & 0x8000_0000 != 0 {
        return false;
    }
    (value >> 16) & 0xffff != 0
}
