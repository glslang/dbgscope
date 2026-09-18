//! Measurement for the typed-disassembly fields: does the operand reading survive what the engine
//! actually renders, rather than what a test composed?
//!
//! The unit tests in `dbgeng.rs` are written against renderings copied by hand. That is enough to
//! pin the *rules* and not enough to claim the parser works, because a hand-copied rendering is
//! chosen from the shapes its author already knew about. This runs the reader over a whole real
//! dispatch routine and reports what it could **not** read — the number that matters is the
//! `Other` count and the `Unknown` flow count, both of which should be zero on x64.
//!
//! **On ARM64 the `Other` count is not expected to be zero, and that is the contract rather than a
//! shortfall** — so the run prints *what* each one was and not only how many, because the two
//! kinds of `Other` mean opposite things and the count alone cannot tell them apart:
//!
//! * an **operand kind this type has no shape for**, named rather than dropped — a system
//!   register (`s3_0_c1_c0_0`), a barrier's domain (`sy`), a shift folded into an arithmetic
//!   operand (`lsl #0x38`), a vector lane (`v17.d[1]`). The instruction around it is fully
//!   decoded and this is the operand's name.
//! * an **instruction in a space the decoder does not shape**, which is the whole operand list and
//!   carries that space's name — `advanced-simd`, `sve`, `unallocated`. This is the count the
//!   issue was about, and over an IOCTL dispatch routine, which is integer code, it should be
//!   nothing at all.
//!
//! It also answers the question the reading exists for: how many `cmp`/`sub` immediates inside an
//! IOCTL dispatch routine decode as plausible `CTL_CODE` values, which is the premise a static
//! IOCTL map rests on.
//!
//! Measured on `mountmgr!MountMgrDeviceControl` in the 26100 **ARM64** kernel dump: 582
//! instructions walked, no unknown flow, the two decode paths agreeing on every one of them, six
//! `Other` operands — three shift modifiers, two post-index amounts and a vector lane, every one
//! of them a *named* operand kind and none of them an instruction left unshaped — and five
//! recovered control codes.
//! The compare that recovers them is `cmp w19,#0x6DC,lsl #0xC`, which is the shifted literal
//! dbgscope#170 was about: the immediate has to reach the caller as `0x6dc000` and not as
//! `0x6dc`, or the map is of a driver that accepts nothing.
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
    // no substitute, because MSVC splits one function across several of them.
    //
    // A module bound alone is not enough either. A tail `jmp` to a neighbour is *inside* the
    // module, so the walk would follow it into that function and its own tail calls, and every
    // number below would describe more than the routine that was asked about. So a non-call edge
    // is taken only while it stays inside the entry's own symbol. Where the entry has no symbol —
    // a stripped driver — there is no ownership to test and the module bound is all there is,
    // which the run says out loud rather than reporting a narrower walk as the same thing.
    let module = e
        .module_at(entry)
        .ok()
        .flatten()
        .expect("the entry is in no module");
    let (low, high) = (module.base, module.base + module.size as u64);
    let owner = e.symbol_for(entry).map(|(name, _)| name);
    println!(
        "ownership: {}",
        match &owner {
            Some(name) => format!("edges kept inside {name}"),
            None => "no symbol for the entry — module bounds only".to_string(),
        }
    );

    let mut seen = std::collections::HashSet::new();
    let mut queue = vec![entry];
    let mut instructions = Vec::new();
    let mut left_the_function = Vec::new();
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
        if let Some(target) = instruction.flow.target()
            && !matches!(instruction.flow, Flow::Call(_))
        {
            let stays = match &owner {
                Some(owner) => e.symbol_for(target).is_some_and(|(name, _)| &name == owner),
                None => true,
            };
            if stays {
                queue.push(target);
            } else {
                left_the_function.push((instruction.address, target));
            }
        }
        if instruction.flow.falls_through() {
            queue.extend(fall_through);
        }
        instructions.push(instruction);
    }
    instructions.sort_by_key(|instruction| instruction.address);
    println!("walked {} instructions", instructions.len());
    println!(
        "cross-function jumps declined: {}\n",
        left_the_function.len()
    );

    let (mut unreadable, mut other_operands, mut unknown_flow) = (0usize, 0usize, 0usize);
    let mut other_kinds: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
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
                *other_kinds.entry(text.clone()).or_insert(0usize) += 1;
                println!(
                    "  OTHER OPERAND {:#x}  {}  <- {text:?}",
                    instruction.address, instruction.text
                );
            }
        }

        // The premise: a compare against a control code, recovered as a value.
        //
        // **Any immediate operand, not the second one.** x64's arithmetic is two-operand, so the
        // immediate is always at index 1 there and this reads the same; A64's is three-operand
        // (`sub w0,w0,#0x221`), and an index would find a register and report that the routine
        // recognises nothing.
        if matches!(
            instruction.mnemonic.as_str(),
            "cmp" | "sub" | "xor" | "add" | "subs" | "adds"
        ) && let Some(Operand::Immediate(value)) = instruction
            .operands
            .iter()
            .find(|operand| matches!(operand, Operand::Immediate(_)))
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
        // An import thunk: an indirect call through a slot whose address the encoding pins. The
        // operand carries no symbol — nothing here parses one — so the slot is named by asking.
        if let Some(Operand::Memory(memory)) = instruction.operands.first()
            && let (Flow::Call(None), Some(slot)) = (instruction.flow, memory.address)
        {
            let name = e
                .symbol_for(slot)
                .map(|(name, _)| name)
                .unwrap_or_else(|| format!("{slot:#x}"));
            calls.push((instruction.address, format!("[{name}]")));
        }
    }

    // The two decode paths, over the same bytes, compared. `disassemble` asks the engine to render
    // each instruction and walks by the end it reports; `decode_range` reads the span once and
    // decodes it locally. They should agree instruction for instruction, and a disagreement is
    // worth more than either count on its own — it is the only signal that the local decoder and
    // the engine's own read of the same bytes have diverged.
    if let Ok(FunctionExtent::Region { begin, end }) = e.function_extent(entry) {
        match e.decode_range(begin, (end - begin) as usize) {
            Ok(ranged) => {
                let walked: std::collections::HashMap<u64, &dbgscope::dbgeng::Instruction> =
                    instructions
                        .iter()
                        .map(|instruction| (instruction.address, instruction))
                        .collect();
                let mut compared = 0usize;
                let mut disagreed = 0usize;
                for one in &ranged {
                    let Some(other) = walked.get(&one.address) else {
                        continue;
                    };
                    compared += 1;
                    // **The mnemonic is only compared where both paths decoded one.** On a set
                    // whose operands are not read, `disassemble` takes it from the rendering's
                    // first token and `decode_range` has no rendering to take it from, so the two
                    // differ on every instruction by construction — which used to report thirty
                    // disagreements over a thirty-instruction ARM64 routine and would have hidden
                    // a real one. ARM64 decodes its operands now, so this compares there too; the
                    // empty check is what is left of the same rule, and it still fires per
                    // instruction, for the ones in a space the decoder names rather than shapes.
                    // An empty mnemonic is "this path had nothing to name it" and not a
                    // disagreement about the bytes, which the `bytes` comparison beside it covers.
                    let mnemonics_differ = set.operands_are_read()
                        && !one.mnemonic.is_empty()
                        && !other.mnemonic.is_empty()
                        && one.mnemonic != other.mnemonic;
                    if one.bytes != other.bytes || mnemonics_differ || one.flow != other.flow {
                        disagreed += 1;
                        println!(
                            "  DISAGREE {:#x}  ranged {} {:?}  walked {} {:?}",
                            one.address, one.mnemonic, one.flow, other.mnemonic, other.flow
                        );
                    }
                }
                println!(
                    "\n--- the two decode paths over the first region ---\nrange-decoded {}, \
                     compared {compared}, disagreed {disagreed}",
                    ranged.len()
                );
            }
            Err(error) => println!("\nrange decode unavailable: {error}"),
        }
    }

    println!("\n--- what the reading could not read ---");
    println!("instructions the engine could not render: {unreadable}");
    println!("operands kept as Other:                   {other_operands}");
    println!("instructions with Unknown flow:           {unknown_flow}");
    // The breakdown, because the count above carries two different meanings -- see the header.
    for (text, count) in &other_kinds {
        println!("    {count:>5}  {text}");
    }

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
