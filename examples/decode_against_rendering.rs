//! Measurement for the whole instruction decoder: does it still agree with the engine over a
//! *module*, rather than over the routines somebody thought to write a fixture for?
//!
//! `typed_disassembly.rs` walks one function's control flow and reports what it could not read.
//! This walks every executable section of an image linearly — data, padding and all — and cross-
//! checks each decoded [`Instruction`] against the engine's own rendering of the same bytes. The
//! two are complementary: that one measures what an *analysis* can read on a routine it cares
//! about, this one is a net under the decoder itself.
//!
//! **The engine's rendering is the only independent reading of those bytes this crate has.** The
//! fields come from decoding the encoding and the rendering comes from DbgEng, so where they
//! disagree one of them is wrong, and a corpus of a million real instructions finds the shapes a
//! hand-written fixture was never going to contain. Written against the A64 decoder
//! (dbgscope#170), where over a 26100 kernel's `nt` it found seven defects the unit tests had not —
//! among them a `ccmp` whose fixed bit was read the wrong way round, which rejected every one of
//! the 3,009 in the image.
//!
//! ```text
//! cargo run --example decode_against_rendering -- <dump> <module> [max] [image search path]
//! cargo run --example decode_against_rendering -- C:\dumps\kernel.dmp nt
//! cargo run --example decode_against_rendering -- C:\dumps\kernel.dmp mountmgr 0 \
//!     SRV*C:\sym*https://msdl.microsoft.com/download/symbols
//! ```
//!
//! `max` caps how many instructions are read; `0` means the whole image, which on a kernel's `nt`
//! is upwards of a million and takes minutes. A driver's code pages are not in a kernel minidump,
//! so anything but `nt` needs the image search path — without one every instruction reads `???`
//! and the run reports exactly that, which is itself the measurement of what a dump alone answers.
//!
//! # Nothing here is a pass or a fail
//!
//! Every count below has a floor that is not zero and is not a defect, and the run prints *what*
//! each one was so a reader can tell the floor from a regression:
//!
//! * **`Other` operands** are two different things. An operand kind [`Operand`] has no shape for —
//!   an A64 system register, a barrier's domain, a shift folded into an arithmetic operand — is
//!   named rather than dropped, and the instruction around it is fully decoded. An *instruction*
//!   in a space the decoder does not shape is a single `Other` carrying that space's name. The
//!   breakdown separates them by eye; the counts cannot.
//! * **Immediates and displacements the rendering does not contain** include every one the decoder
//!   deliberately reports differently from how it was printed — A64 folds `#0x222,lsl #12` into
//!   `0x222000`, and a `sys` operation's name is reported as the register space it reaches.
//! * **Mnemonics** differ wherever the debugger's preferred spelling is not the architecture's.
//!
//! What *should* be zero, on any target: an instruction with [`Flow::Unknown`], a register the
//! rendering names that the decode did not touch, a resolved address that is not the one the
//! engine printed, and a disagreement between the two decode paths.

use dbgscope::dbgeng::{DebugEngine, Flow, Instruction, InstructionSet, Operand};
use std::collections::{BTreeMap, HashMap, HashSet};

/// How much of a section is decoded at a time. Bounds the memory a whole-image run holds, and is
/// what lets the linear walk and [`DebugEngine::decode_range`] be compared over the same span
/// without either of them materialising a million instructions.
///
/// **A page, because that is the granularity a dump is missing things at.**
/// [`DebugEngine::decode_range`] reads its whole span in one call and fails if any of it is
/// unreadable, so a wider window loses the comparison for every instruction beside one absent
/// page — on this kernel's `nt`, 64 KiB windows left 54,272 instructions uncompared and a page
/// leaves the ones actually missing.
const WINDOW: usize = 0x1000;

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(dump), Some(module)) = (args.next(), args.next()) else {
        eprintln!("usage: decode_against_rendering <dump> <module> [max] [image search path]");
        std::process::exit(2);
    };
    let max: usize = args
        .next()
        .map(|text| text.parse().expect("max must be a number"))
        .unwrap_or(0);
    let image_path = args.next();

    let e = DebugEngine::new();
    e.open_dump(&dump).expect("opening the dump failed");
    e.wait_for_event(30_000)
        .expect("the dump did not load within thirty seconds");
    if let Some(path) = &image_path {
        e.execute_command(&format!(".exepath+ {path}"))
            .expect("setting the image search path failed");
        e.reload_symbols("/f").expect("reloading failed");
    }

    let set = e.instruction_set();
    println!(
        "instruction set: {set:?} (flow read: {}, operands read: {})",
        set.flow_is_read(),
        set.operands_are_read()
    );

    let loaded = e.modules().expect("the module list");
    let Some(image) = loaded
        .iter()
        .find(|candidate| candidate.name.eq_ignore_ascii_case(&module))
    else {
        eprintln!("no module named `{module}` is loaded");
        std::process::exit(1);
    };
    println!("{} at {:#x}, {} bytes", image.name, image.base, image.size);

    // The **executable sections**, not the loader's extent: `.rdata` and `.data` are inside that
    // and decoding them measures how this reads a jump table, which is not the question.
    let headers = dbgscope::pe::read_image(image.base, |at, len| e.read_memory(at, len).ok())
        .expect("the image headers did not read — a driver needs an image search path");
    let ranges = headers.executable_ranges();
    println!(
        "executable sections: {}",
        ranges
            .iter()
            .map(|range| format!("{:#x}..{:#x}", range.start, range.end))
            .collect::<Vec<_>>()
            .join(" ")
    );

    let mut report = Report::default();
    'sections: for range in &ranges {
        let mut at = range.start;
        while at < range.end {
            let length = WINDOW.min((range.end - at) as usize);
            report.window(&e, at, length, set);
            at += length as u64;
            if max != 0 && report.rendered >= max as u64 {
                break 'sections;
            }
        }
    }
    report.print();
}

/// One window's worth of work, and the running totals it adds to.
#[derive(Default)]
struct Report {
    read: u64,
    rendered: u64,
    unreadable: u64,
    unknown_flow: u64,
    /// Instructions in a space the decoder names rather than shapes, and how many were in a
    /// position to be asked. This is the number dbgscope#170 was about, and the ranged decode is
    /// what can answer it: having no rendering to fall back on, an empty mnemonic there means the
    /// decoder itself produced none.
    unshaped: u64,
    shapeable: u64,
    /// Every register spelling the decoder has produced so far, which is what the rendering's
    /// tokens are recognised against.
    ///
    /// **Built from the decoder's own output rather than from a table**, so this example knows no
    /// architecture's register names — the run discovers them. It converges within a few hundred
    /// instructions, and until it has, a register named in a rendering and missed by the decode
    /// goes unreported rather than misreported.
    vocabulary: HashSet<String>,
    other: Counted,
    mnemonics: Counted,
    registers: Counted,
    immediates: Counted,
    displacements: Counted,
    addresses: Counted,
    counts: Counted,
    paths: Counted,
}

/// A category of finding: how many, and one rendering of each distinct shape.
#[derive(Default)]
struct Counted {
    total: u64,
    checked: u64,
    by_shape: BTreeMap<String, (u64, String)>,
}

impl Counted {
    fn hit(&mut self, shape: String, sample: impl FnOnce() -> String) {
        self.total += 1;
        self.by_shape
            .entry(shape)
            .or_insert_with(|| (0, sample()))
            .0 += 1;
    }

    fn print(&self, title: &str, limit: usize) {
        match self.checked {
            0 => println!("{title}: {}", self.total),
            checked => println!("{title}: {} of {checked}", self.total),
        }
        let mut shapes: Vec<_> = self.by_shape.iter().collect();
        shapes.sort_by_key(|(_, (count, _))| std::cmp::Reverse(*count));
        for (shape, (count, sample)) in shapes.iter().take(limit) {
            println!("    {count:>9}  {shape:<28} {sample}");
        }
        if shapes.len() > limit {
            println!("    {:>9}  … {} more shapes", "", shapes.len() - limit);
        }
    }
}

impl Report {
    fn window(&mut self, e: &DebugEngine, start: u64, length: usize, set: InstructionSet) {
        // Both readings are linear and both begin here, so they are comparable: a divergence is
        // the two disagreeing about an instruction's length or its fields, not about where the
        // stream began. A window boundary can cut a variable-length instruction in half, which is
        // why what is past the window is dropped rather than compared.
        let ranged: HashMap<u64, Instruction> = match e.decode_range(start, length) {
            Ok(decoded) => decoded.into_iter().map(|one| (one.address, one)).collect(),
            Err(_) => HashMap::new(),
        };
        let end = start + length as u64;
        let mut at = start;
        while at < end {
            // One past the batch, so the last instruction's end is the engine's own arithmetic
            // rather than a length guessed from the encoding.
            let Ok(batch) = e.disassemble(at, 65) else {
                return;
            };
            let Some(next) = batch.get(64).map(|one| one.address) else {
                for one in batch.iter().filter(|one| one.address < end) {
                    self.instruction(one, ranged.get(&one.address), set);
                }
                return;
            };
            for one in batch.iter().take(64).filter(|one| one.address < end) {
                self.instruction(one, ranged.get(&one.address), set);
            }
            if next <= at {
                return;
            }
            at = next;
        }
    }

    fn instruction(
        &mut self,
        one: &Instruction,
        ranged: Option<&Instruction>,
        set: InstructionSet,
    ) {
        self.read += 1;
        if one.flow == Flow::Unreadable {
            self.unreadable += 1;
            return;
        }
        self.rendered += 1;
        if one.flow == Flow::Unknown {
            self.unknown_flow += 1;
        }
        for operand in &one.operands {
            if let Operand::Register(register) = operand {
                self.vocabulary.insert(register.name.clone());
            }
        }

        let sample = || format!("{}  {}", one.bytes, one.text);
        let text = one.text.as_str();
        let printed = tokens(text);
        let numbers = numbers(text);

        // The two decode paths over the same bytes. A mnemonic is compared only where both paths
        // produced one: `disassemble` falls back to the rendering's first token and `decode_range`
        // has no rendering to fall back to, so an instruction the decoder does not shape has a
        // mnemonic on one side and not the other, which is not a disagreement about the bytes.
        if let Some(other) = ranged {
            self.paths.checked += 1;
            let mnemonics_differ = !one.mnemonic.is_empty()
                && !other.mnemonic.is_empty()
                && one.mnemonic != other.mnemonic;
            if one.bytes != other.bytes || mnemonics_differ || one.flow != other.flow {
                self.paths
                    .hit(format!("{} / {}", one.mnemonic, other.mnemonic), || {
                        format!(
                            "{}  walked {:?}  ranged {:?}",
                            sample(),
                            one.flow,
                            other.flow
                        )
                    });
            }
        }

        // **Whether the decoder shaped this instruction at all**, which the ranged copy is what
        // says: it has no rendering to take a mnemonic from, so an empty one there means nothing
        // was decoded and its single `Other` names the space rather than an operand. The checks
        // that compare an operand list against a rendering have nothing to say about those.
        // A word the engine renders `???` is the common case on A64 -- inter-function padding,
        // whose four bytes were read perfectly well and are a `udf`.
        let shaped = ranged.map_or(!text.starts_with('?'), |other| !other.mnemonic.is_empty());
        // **Counted against what the engine could render**, which is the denominator that makes
        // the fraction mean "of the code DbgEng calls code, how much does this decline". Over a
        // whole image the other denominator is mostly padding: a `udf` the engine renders `???`
        // is unshaped by construction, and this kernel has 113,915 of them.
        if let Some(other) = ranged.filter(|_| !text.starts_with('?')) {
            self.shapeable += 1;
            self.unshaped += u64::from(other.mnemonic.is_empty());
        }

        // **Nothing below compares against a rendering the engine did not produce.** `???` with a
        // byte column is an instruction the engine read and declined to name — on A64 that is
        // every `udf`, and over a whole image it is also every data word in an encoding this
        // decoder knows and DbgEng's does not. There is no rendering there to agree or disagree
        // with, and treating its absence as a disagreement buries the real ones.
        if set.operands_are_read() && !text.starts_with('?') {
            let engine_mnemonic = text.split(' ').next().unwrap_or_default();
            self.mnemonics.checked += 1;
            // **A condition spelled into the mnemonic is the same instruction.** A64 writes
            // `csel Xd,Xn,Xm,eq` and the debugger writes `cseleq`, which is a rendering choice
            // about where the condition goes rather than a different reading of the bytes --
            // [`Instruction::condition`] is what carries it here, and requiring one is what keeps
            // this from absorbing a real disagreement between two mnemonics that share a prefix.
            let condition_spelled_in =
                one.condition.is_some() && engine_mnemonic.starts_with(&one.mnemonic);
            if !one.mnemonic.is_empty()
                && engine_mnemonic != one.mnemonic
                && !condition_spelled_in
                // A64 spells a conditional branch `b.eq` and the debugger spells it `beq`.
                && engine_mnemonic != one.mnemonic.replace('.', "")
            {
                self.mnemonics
                    .hit(format!("{} / {engine_mnemonic}", one.mnemonic), sample);
            }

            for operand in &one.operands {
                match operand {
                    Operand::Other(name) => self.other.hit(name.clone(), sample),
                    Operand::Register(register) => {
                        self.registers.checked += 1;
                        if !printed.contains(&register.name) {
                            self.registers
                                .hit(format!("{}/{}", one.mnemonic, register.name), sample);
                        }
                    }
                    Operand::Immediate(value) => {
                        self.immediates.checked += 1;
                        if !numbers.contains(value) {
                            self.immediates.hit(one.mnemonic.clone(), sample);
                        }
                    }
                    Operand::Memory(memory) => {
                        // A post-indexed access reports the base and moves it afterwards, so its
                        // displacement is deliberately not the number beside the bracket.
                        if memory.displacement != 0
                            && !text.contains("],#")
                            && !numbers.contains(&(memory.displacement as u64))
                        {
                            self.displacements.hit(one.mnemonic.clone(), sample);
                        }
                        self.displacements.checked += 1;
                        if let Some(address) = memory.address {
                            self.addresses.checked += 1;
                            if !text.replace('`', "").contains(&format!("{address:x}")) {
                                self.addresses.hit(one.mnemonic.clone(), sample);
                            }
                        }
                    }
                    Operand::Target(_) => {}
                }
            }

            // Every register the rendering names must be one this decode saw — as an operand, or
            // in the access lists. This is the check that catches an operand the decoder walked
            // past, and it is the one on this run expected to be zero.
            //
            // **Matched against the printed spelling *and* the full-width one**, because the two
            // lists deliberately differ: an operand keeps the spelling the instruction was written
            // with while a write is recorded at the whole register, so `mov w9,#2` has an operand
            // spelled `w9` and a write spelled `x9`, and either is this token being seen. The
            // converse is not checked either: an implicit write — a call's link register — is in
            // the lists and rightly not in the rendering.
            let seen: HashSet<&str> = one
                .operands
                .iter()
                .flat_map(|operand| match operand {
                    Operand::Register(register) => vec![register],
                    Operand::Memory(memory) => memory
                        .base
                        .iter()
                        .chain(memory.index.iter())
                        .collect::<Vec<_>>(),
                    _ => Vec::new(),
                })
                .chain(one.reads.iter())
                .chain(one.writes.iter())
                .flat_map(|register| [register.name.as_str(), register.full.as_str()])
                .collect();
            if shaped {
                for token in &printed {
                    if self.vocabulary.contains(token) && !seen.contains(token.as_str()) {
                        self.registers
                            .hit(format!("{} unseen {token}", one.mnemonic), sample);
                    }
                }
            }

            // How many operands the rendering printed, counting a bracketed expression as one.
            //
            // **Only where the rendering names no symbol**, because a demangled one carries its
            // own commas — `std::map<int,int>` — and splitting on those is the reading this crate
            // gave up on. That it would break here too is the point rather than a limitation.
            //
            // And only where the decoder shaped the instruction, for the reason above.
            if shaped && !text.contains('!') {
                self.counts.checked += 1;
                let groups = operand_groups(text);
                if groups != one.operands.len() {
                    self.counts.hit(
                        format!("{} {}/{groups}", one.mnemonic, one.operands.len()),
                        sample,
                    );
                }
            }
        }
    }

    fn print(&self) {
        println!(
            "\n--- {} instructions read, {} rendered, {} unreadable ---",
            self.read, self.rendered, self.unreadable
        );
        println!(
            "instructions with Unknown flow:           {}",
            self.unknown_flow
        );
        println!(
            "unshaped, of those the engine rendered:   {} of {} ({:.3}%)",
            self.unshaped,
            self.shapeable,
            100.0 * self.unshaped as f64 / self.shapeable.max(1) as f64
        );
        println!(
            "register spellings the decoder produced:  {}",
            self.vocabulary.len()
        );
        println!();
        self.paths.print("the two decode paths disagreeing", 10);
        self.mnemonics
            .print("mnemonics differing from the rendering", 15);
        self.registers
            .print("registers the rendering and the decode disagree on", 15);
        self.addresses
            .print("resolved addresses not in the rendering", 10);
        self.immediates.print("immediates not in the rendering", 10);
        self.displacements
            .print("memory displacements not in the rendering", 10);
        self.counts
            .print("operand counts differing from the rendering", 15);
        self.other.print("operands kept as Other", 20);
    }
}

/// The identifier-like tokens of a rendering.
fn tokens(text: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut current = String::new();
    for character in text.chars() {
        if character.is_ascii_alphanumeric() || character == '_' {
            current.push(character);
        } else if !current.is_empty() {
            out.insert(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        out.insert(current);
    }
    out
}

/// Every numeric literal a rendering carries, as the unsigned value it would be.
///
/// A negative one is printed with a sign and the field holds its two's complement, so both
/// readings are offered at 32 and 64 bits; so is the bitwise complement, which is how a `movn`'s
/// value relates to the field it was printed from.
fn numbers(text: &str) -> HashSet<u64> {
    let mut out = HashSet::new();
    let characters: Vec<char> = text.chars().collect();
    let mut index = 0;
    while index < characters.len() {
        let negative = characters[index] == '-';
        let start = index + usize::from(negative);
        if start >= characters.len() {
            break;
        }
        if start + 1 < characters.len()
            && characters[start] == '0'
            && characters[start + 1].eq_ignore_ascii_case(&'x')
        {
            let mut end = start + 2;
            while end < characters.len() && characters[end].is_ascii_hexdigit() {
                end += 1;
            }
            if let Ok(value) =
                u64::from_str_radix(&characters[start + 2..end].iter().collect::<String>(), 16)
            {
                offer(&mut out, value, negative);
            }
            index = end;
            continue;
        }
        if characters[start].is_ascii_digit() {
            let mut end = start;
            while end < characters.len() && characters[end].is_ascii_digit() {
                end += 1;
            }
            // Only a literal the rendering introduced as one: a bare run of digits is as likely to
            // be part of a register's name or a symbol's.
            let introduced = start > 0 && characters[start - 1] == '#'
                || negative && start > 1 && characters[start - 2] == '#';
            if introduced
                && let Ok(value) = characters[start..end]
                    .iter()
                    .collect::<String>()
                    .parse::<u64>()
            {
                offer(&mut out, value, negative);
            }
            index = end;
            continue;
        }
        index += 1;
    }
    out
}

fn offer(out: &mut HashSet<u64>, value: u64, negative: bool) {
    out.insert(value);
    out.insert(!value);
    if negative {
        out.insert((value as i64).wrapping_neg() as u64);
        out.insert((value as u32).wrapping_neg() as u64);
    }
}

/// How many operands a rendering printed, a bracketed or braced expression counting as one.
fn operand_groups(text: &str) -> usize {
    let Some((_, rest)) = text.split_once(' ') else {
        return 0;
    };
    // The engine's resolved `(address)` suffix is not an operand.
    let rest = rest.split(" (").next().unwrap_or(rest).trim();
    if rest.is_empty() {
        return 0;
    }
    let mut depth = 0i32;
    let mut groups = 1;
    for character in rest.chars() {
        match character {
            '[' | '{' => depth += 1,
            ']' | '}' => depth -= 1,
            ',' if depth == 0 => groups += 1,
            _ => {}
        }
    }
    groups
}
