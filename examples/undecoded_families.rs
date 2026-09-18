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
//! `disarm64`, whose tables are generated from the architecture — and reports the definitions the
//! generated table holds that this one returns [`Operand::Undecoded`] for. Fifty-one seconds on
//! eight threads, and no debugger, target or dump.
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

fn main() {
    let threads: Vec<_> = (0..8u32)
        .map(|lane| std::thread::spawn(move || collect(lane)))
        .collect();
    let mut all = Definitions::new();
    for thread in threads {
        all.extend(thread.join().expect("a sweep thread panicked"));
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
}

/// Every definition the generated table reaches, from one stripe of the encoding space.
///
/// The stripe is `lane`, `lane + 8`, `lane + 16` and so on, so eight threads cover the whole of it
/// without sharing anything. What is recorded per definition is whether any of its operands is a
/// general-purpose register, and which feature introduced it.
fn collect(lane: u32) -> Definitions {
    let mut seen = Definitions::new();
    let mut word = lane;
    loop {
        if let Some(theirs) = disarm64::decoder::decode(word) {
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
        match word.checked_add(8) {
            Some(next) => word = next,
            None => break seen,
        }
    }
}
