//! Which instruction families this crate's A64 decoder does not read, asked of a generated table
//! rather than of anyone's recollection.
//!
//! `decode_against_rendering.rs` measures the decoder against a *target*: it can only find what an
//! image contains, and a Windows ARM64 kernel contains no memory tagging, no `brab`, no `subps` and
//! no `cpyfp`. Review found each of those one at a time over several rounds on dbgscope#171, and
//! the last of them is what prompted this: the question "what else is missing" deserves a
//! mechanical answer and had been getting an anecdotal one.
//!
//! So this decodes **every** 32-bit word twice — once with [`dbgscope`]'s decoder and once with
//! `disarm64`, whose tables are generated from the architecture — and reports the disagreements in
//! **both** directions. Fifty-one seconds on eight threads, and no debugger, target or dump.
//!
//! - *Under-acceptance*: definitions the generated table holds that this one returns
//!   [`Operand::Undecoded`] for. A family nobody decoded.
//! - *Over-acceptance*: words this decoder shapes that the generated table refuses. A **field**
//!   nobody constrained — which the first listing structurally cannot find, because it compares
//!   definitions and an unconstrained field is not one. That listing is what found a post-indexed
//!   `prfm`, an unprivileged prefetch slot spelled `sttr`, a vector `ldtr`, an unauthenticated
//!   `braa` and a `casp` pairing a register with itself, none of which any corpus contains.
//!
//! ```text
//! cargo run --release --example undecoded_families
//! ```
//!
//! # Reading the output
//!
//! Rows are grouped by the architecture feature that introduced them, which is what separates a
//! family this crate *declines* from one it *missed*. The vector extensions are declined by
//! contract ([`dbgscope::dbgeng::InstructionSet::operands_are_read`] and the decoder's own module
//! documentation say where the line falls); an Armv8.8 general-purpose family in the load/store
//! space is not.
//!
//! **Two kinds of row are expected and are not gaps.** A mask-based table decodes field
//! combinations the architecture does not allocate, so a definition's canonical encoding — its
//! opcode with every variable bit zero — is sometimes not a legal instruction: a fixed-point
//! `fcvtzs` with a zero `scale` asks for more fraction bits than a 32-bit destination has, and an
//! Advanced SIMD `umov` with a zero `imm5` names no element size. Both are correctly refused here
//! and appear in this listing anyway. Only the *filtering* is approximate; the decoding is not.
//!
//! Rows are also restricted to definitions with a general-purpose operand, that being the surface
//! this crate's decoder claims.

use dbgscope::dbgeng::{InstructionSet, Operand, decode_instruction};
use disarm64::InsnOpcode;
use std::collections::BTreeMap;

/// A definition, keyed so that two encodings of one instruction collapse: the mnemonic and the
/// canonical opcode the table stores for it.
type Definitions = BTreeMap<(String, u32), (bool, String)>;

/// Mnemonics this crate shapes for words the generated table refuses, with how many such words
/// each covers and one of them to look at.
type OverAccepted = BTreeMap<String, (u64, u32)>;

fn main() {
    let threads: Vec<_> = (0..8u32)
        .map(|lane| std::thread::spawn(move || collect(lane)))
        .collect();
    let mut all = Definitions::new();
    let mut over = OverAccepted::new();
    for thread in threads {
        let (definitions, over_accepted) = thread.join().expect("a sweep thread panicked");
        all.extend(definitions);
        for (mnemonic, (count, example)) in over_accepted {
            let entry = over.entry(mnemonic).or_insert((0, example));
            entry.0 += count;
        }
    }
    println!("definitions in the generated table: {}", all.len());

    // Phase two: ask *this* decoder about each definition's canonical encoding, rather than about
    // every word that matched its mask. The difference matters — a mask covers combinations the
    // architecture leaves unallocated, and asking about all of them buries the answer.
    let mut by_feature: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut unread = 0usize;
    for ((mnemonic, opcode), (general, feature)) in &all {
        if !general {
            continue;
        }
        let mine = decode_instruction(&opcode.to_be_bytes(), 0x1000, InstructionSet::Arm64);
        if matches!(mine.operands.first(), Some(Operand::Undecoded(_))) {
            unread += 1;
            by_feature
                .entry(feature.clone())
                .or_default()
                .push(format!("{mnemonic}({opcode:#010x})"));
        }
    }

    println!(
        "\n--- definitions with a general-purpose operand this decoder leaves unread: {unread} ---"
    );
    for (feature, mut rows) in by_feature {
        rows.sort();
        rows.dedup();
        println!("\n  {feature}  ({} definitions)", rows.len());
        for chunk in rows.chunks(6) {
            println!("    {}", chunk.join("  "));
        }
    }

    // The other direction, which is the one the rows above cannot reach: they compare
    // *definitions*, so they find a family nobody decoded and never a field nobody constrained.
    let words: u64 = over.values().map(|(count, _)| count).sum();
    println!(
        "\n--- words this decoder shapes that the generated table refuses: {words} \
         ({:.1}% of the encoding space), {} mnemonics ---",
        words as f64 / f64::from(u32::MAX) * 100.0,
        over.len()
    );
    for (mnemonic, (count, example)) in &over {
        println!("  {mnemonic:<12} {count:>12}  e.g. {example:#010x}");
    }
}

/// Every definition the generated table reaches, from one stripe of the encoding space.
///
/// The stripe is `lane`, `lane + 8`, `lane + 16` and so on, so eight threads cover the whole of it
/// without sharing anything. What is recorded per definition is whether any of its operands is a
/// general-purpose register, and which feature introduced it.
fn collect(lane: u32) -> (Definitions, OverAccepted) {
    let mut seen = Definitions::new();
    let mut over = OverAccepted::new();
    let mut word = lane;
    loop {
        match disarm64::decoder::decode(word) {
            Some(theirs) => {
                let definition = theirs.definition();
                seen.entry((definition.mnemonic.to_string(), definition.opcode))
                    .or_insert_with(|| {
                        let general = definition
                            .operands
                            .iter()
                            .any(|operand| format!("{:?}", operand.class) == "INT_REG");
                        (general, format!("{:?}", definition.feature_set))
                    });
            }
            // A word the generated table does not allocate. If this crate shapes it anyway, it is
            // claiming an instruction that does not exist -- which is what a caller walking data
            // through `decode_range` is handed instead of the `Undecoded` marker.
            None => {
                let mine = decode_instruction(&word.to_be_bytes(), 0x1000, InstructionSet::Arm64);
                let undecoded = mine
                    .operands
                    .iter()
                    .any(|operand| matches!(operand, Operand::Undecoded(_)));
                if !undecoded && !mine.mnemonic.is_empty() {
                    let entry = over.entry(mine.mnemonic.clone()).or_insert((0, word));
                    entry.0 += 1;
                }
            }
        }
        match word.checked_add(8) {
            Some(next) => word = next,
            None => break (seen, over),
        }
    }
}
