//! ARM64 (A64) control flow, decoded from the encoding.
//!
//! This is deliberately **not** a disassembler. The engine already renders every instruction, and
//! [`crate::dbgeng::Instruction::text`] carries that rendering verbatim; what no engine call
//! answers is where control goes, which is the one thing a caller following a call graph cannot
//! recover from a rendering without parsing symbols out of it. So this decodes
//! [`Flow`](crate::dbgeng::Flow) and nothing else: no operands, no registers, no privilege. The
//! honest tell for "operands were not read here" is
//! [`InstructionSet::operands_are_read`](crate::dbgeng::InstructionSet::operands_are_read), which
//! answers `false` for ARM64 and will keep doing so until somebody decodes them.
//!
//! # Why the flow half is small enough to write by hand
//!
//! A64 is fixed-width and regular. Every transfer of control in the Armv8 baseline is one of six
//! encoding classes, all discriminated by a mask on the top bits of a 32-bit word — and there is
//! no seventh *there*, because A64 has no instruction that writes the program counter as a general
//! register. So `Flow::Fallthrough` is much closer to a decoded answer here than on the x86 side,
//! where the default has to be [`Flow::Unknown`](crate::dbgeng::Flow::Unknown) because a
//! variable-length encoding this decoder does not know may be anything at all.
//!
//! **It is not decoded, though, and an earlier draft of this paragraph said it was.** "No
//! instruction writes the PC" rules out a *seventh shape*; it does not rule out a seventh
//! **class**, and a later architecture can add one — Armv9.6's FEAT_CMPBR does, with a
//! register-to-register compare-and-branch at `0111010` where the Armv8 conditional branch is
//! `0101010`. This decodes six classes and reads anything else as a fall-through, so on a target
//! with such an instruction it is **incomplete rather than wrong**: a conditional branch read as a
//! fall-through keeps the edge that is really there and loses the taken one. That costs a
//! [`Flow::Branch`](crate::dbgeng::Flow::Branch)'s second edge, which weakens a NOT REACHABLE — a
//! best-effort verdict by contract — and never underwrites a REACHABLE, which is the one that has
//! to be sound.
//!
//! FEAT_CMPBR is not decoded because no target here has it: adding masks for an encoding nothing
//! can render would put a *computed branch destination* behind a recollection of a table, and a
//! wrong destination is the one failure this whole module is arranged to avoid. Reopen it with a
//! target that renders one.
//!
//! # The word, and which end of it is first
//!
//! **The two ways into this module disagree about byte order, and both are right.** The engine's
//! rendered byte column prints the instruction *word*, most significant digit first — measured on
//! a 26100 ARM64 kernel dump, `nt!KeBugCheckEx+4` renders as `a9bf7bfd  stp fp,lr,[sp,#-0x10]!`,
//! and `stp x29,x30,[sp,#-16]!` encodes as `0xa9bf7bfd`. The same four bytes read out of memory
//! come back `fd 7b bf a9`, A64 being little-endian. So a caller decoding the *rendering* assembles
//! the word with [`u32::from_be_bytes`] and one decoding *memory* with [`u32::from_le_bytes`], and
//! this module takes the word rather than the bytes so that the choice is made where the bytes came
//! from and cannot be made twice.

use crate::dbgeng::Flow;

/// The width of an A64 instruction. Fixed, which is the property the rest of this module rests on:
/// a fall-through is the next word, and a branch displacement is in units of this.
pub(crate) const INSTRUCTION_BYTES: usize = 4;

/// What one A64 word does to control flow.
///
/// `address` is where the word is, which every relative form is computed against — A64 measures a
/// branch from the branch itself rather than from its end, so there is no instruction length in
/// this arithmetic. The result is a full 64-bit address in the same space the instruction came
/// from, so the canonicalisation the x86 path needs (`canonical_target`, for a narrow effective
/// machine over a wide address) has nothing to do here: A64 exists only at 64-bit, and the
/// displacement is added to the whole address rather than to a truncated one. `test_a_branch_target_keeps_the_instruction_s_address_space` pins that rather than leaving it assumed.
pub(crate) fn flow(word: u32, address: u64) -> Flow {
    // Unconditional branch (immediate): `op 00101 imm26`, where `op` is bit 31 and picks `bl` from
    // `b`. Masked without bit 31 so the two share one arm — they differ only in whether control
    // comes back, which is exactly the difference between `Call` and `Jmp`.
    if word & 0x7c00_0000 == 0x1400_0000 {
        let target = relative(address, word & 0x03ff_ffff, 26);
        return match word & 0x8000_0000 == 0 {
            true => Flow::Jmp(Some(target)),
            false => Flow::Call(Some(target)),
        };
    }
    // Conditional branch (immediate): `0101010 o1 imm19 o0 cond`. `o0` picks `bc.cond` (FEAT_HBC)
    // from `b.cond`, and both are conditional, so it is not read. `o1` is the third class with
    // unallocated space, and it gets the same treatment as the two below: only `0` is allocated,
    // so `1` is UNDEFINED and stops rather than falling through.
    //
    // **`al` and `nv` are unconditional and are reported as such.** A64 gives condition `1110` and
    // `1111` the meaning "always", so `b.al` never falls through. Calling it `Branch` would hand a
    // reachability walk a fall-through edge that the processor does not have — and an edge that is
    // not there is exactly what a sound `REACHABLE` verdict must never rest on. No compiler emits
    // the form; that is a reason to expect the arm to be cold, not a reason to get it wrong.
    if word & 0xfe00_0000 == 0x5400_0000 {
        if word & 0x0100_0000 != 0 {
            return Flow::Trap;
        }
        let target = relative(address, (word >> 5) & 0x0007_ffff, 19);
        return match word & 0xe == 0xe {
            true => Flow::Jmp(Some(target)),
            false => Flow::Branch(Some(target)),
        };
    }
    // Compare and branch (immediate): `sf 011010 op imm19 Rt` — `cbz`/`cbnz`. Conditional on a
    // register rather than on the flags, which is a difference this type does not carry: both
    // edges are live either way.
    if word & 0x7e00_0000 == 0x3400_0000 {
        return Flow::Branch(Some(relative(address, (word >> 5) & 0x0007_ffff, 19)));
    }
    // Test and branch (immediate): `b5 011011 op b40 imm14 Rt` — `tbz`/`tbnz`. Fourteen bits of
    // displacement rather than nineteen, which is the only thing that separates it from the arm
    // above and the reason the two are not folded together.
    if word & 0x7e00_0000 == 0x3600_0000 {
        return Flow::Branch(Some(relative(address, (word >> 5) & 0x0000_3fff, 14)));
    }
    // Unconditional branch (register): `1101011 opc op2 op3 Rn op4`. The destination is in a
    // register, so every one of these is `None` — the encoding does not carry it, and a caller
    // reading `None` as "no edge" stays sound.
    //
    // **The fixed fields are checked first, and only the two that are fixed the same way for every
    // allocated form.** `op2` is `11111` and `op3` is one of three values throughout the table, so
    // requiring them cannot exclude a real branch — while `0xd6200000`, which has `op2` zero, is
    // unallocated and would otherwise read as a `blr` and fall through. `Rn` and `op4` vary *per
    // form* (`retaa` pins `Rn`, `braa` uses `op4` as a second register), and a mistake there costs
    // a truncated walk at every indirect call on the architecture, which is a worse failure than
    // the one this is closing. So they are left unchecked deliberately rather than overlooked.
    //
    // `opc` then separates the forms, pointer authentication included: `braa`/`brab` are `1000` to
    // `br`'s `0000`, `blraa`/`blrab` are `1001` to `blr`'s `0001`, and `retaa`/`retab` share
    // `ret`'s `0010`.
    if word & 0xfe00_0000 == 0xd600_0000 {
        let (op2, op3) = ((word >> 16) & 0x1f, (word >> 10) & 0x3f);
        if op2 != 0b11111 || !matches!(op3, 0b000000 | 0b000010 | 0b000011) {
            return Flow::Trap;
        }
        return match (word >> 21) & 0xf {
            // `br`, `braaz`, `brabz`, `braa`, `brab`.
            0b0000 | 0b1000 => Flow::Jmp(None),
            // `blr` and its authenticating forms.
            0b0001 | 0b1001 => Flow::Call(None),
            // `ret`/`retaa`/`retab`, then `eret` and `drps`. The last two are an exception return
            // and a debug-state restore: neither continues at the next instruction, which is the
            // only property `Return` claims here.
            0b0010 | 0b0100 | 0b0101 => Flow::Return,
            // Unallocated, and UNDEFINED is an exception rather than a no-op: control does not
            // reach the next word. Same rule as the class below, and see it for why the default
            // inside a class is the opposite of this function's own.
            _ => Flow::Trap,
        };
    }
    // Exception generation: `11010100 opc imm16 op2 LL`. **Only the system-call family continues
    // at the next instruction**, and that is the rule rather than a list of the ones that do not.
    //
    // `svc`, `hvc` and `smc` call into a higher exception level and return to the following word,
    // so stopping there would discard everything after a system call. They are the three `LL`
    // values under `opc` `000` with `op2` zero, and all three fields are matched: `opc` alone lets
    // `0xd4000000` (reserved `LL`) and `0xd4000004` (nonzero `op2`) through, and both are
    // unallocated.
    //
    // Everything else here raises an exception that resumes somewhere else or not at all — `brk`
    // and `hlt` (`001`, `010`), which MSVC emits as `brk #0xf000` behind an unreachable tail, this
    // architecture's `__fastfail`; `tcancel` (`011`), which unwinds to the continuation its
    // `tstart` named and is UNDEFINED outside a transaction, so it has no fall-through under
    // either reading; the `dcps` family (`101`), which enters debug state rather than continuing;
    // and every unallocated encoding among them, UNDEFINED being an exception too.
    //
    // **The default inside a class is the opposite of this function's**, deliberately, and it is
    // why this class, the register branches above and the conditional branch above them all end
    // in `Trap` for what they do not allocate. Outside them a word
    // nothing matched is almost always an ordinary instruction from an extension this does not
    // enumerate, so falling through is the accurate answer; inside them the encoding space is
    // fully spoken for and what is left over is UNDEFINED. Where the two readings of a rare
    // encoding differ, stopping costs a `NOT REACHABLE` that is best-effort by contract while
    // continuing costs a `REACHABLE` that is meant to be sound.
    if word & 0xff00_0000 == 0xd400_0000 {
        let (opc, op2, ll) = ((word >> 21) & 0x7, (word >> 2) & 0x7, word & 0x3);
        return match (opc, op2, ll) {
            (0b000, 0b000, 0b01 | 0b10 | 0b11) => Flow::Fallthrough,
            _ => Flow::Trap,
        };
    }
    // A64's **Reserved** top-level space, `op0` (bits 28..25) zero. Its one defined member is
    // `udf #imm16` (`0000000000000000 imm16`), which is what a zero word is, and a zero word is
    // what sits between functions: the engine renders those `???` even though it read them
    // perfectly well, which is a different fact from the `??` it prints for bytes it could not
    // read at all. Trapping stops a walk at the end of a function; falling through would run it
    // into whatever the linker put next.
    //
    // **The whole space rather than the `udf` pattern**, because the rest of it is unallocated and
    // UNDEFINED is an exception either way — the same rule the two classes above apply inside
    // themselves, and the reason `0x00010000` is not a fall-through. It is one mask and needs no
    // per-form knowledge, which is what makes it worth doing; the classes are disjoint from it, so
    // it reads last without that being load-bearing.
    //
    // **`op0` `0001` and `0011` are left falling through**, and that is the line rather than an
    // omission. This space is *Reserved* — permanently undefined by construction, which is what
    // `udf` means — while those two are merely *unallocated today*, and ARM allocates into them.
    // A decoder that trapped there would truncate a walk the first time an extension landed, on
    // instructions that carry no control flow at all.
    if (word >> 25) & 0xf == 0 {
        return Flow::Trap;
    }
    // Not a class this decodes. On the Armv8 baseline that is an ordinary instruction and the
    // answer is right; on a later architecture it may be a branch class that did not exist when
    // these masks were written, and the module header says which one and why it is not here.
    Flow::Fallthrough
}

/// A branch destination: `address` plus a sign-extended displacement in instruction-width units.
fn relative(address: u64, immediate: u32, bits: u32) -> u64 {
    let shift = u32::BITS - bits;
    let displacement = ((immediate << shift) as i32 >> shift) as i64;
    address.wrapping_add((displacement * INSTRUCTION_BYTES as i64) as u64)
}

/// What the second word of an ARM64 `RUNTIME_FUNCTION` is, which its low two bits decide.
///
/// The x64 record is three RVAs of which the second is an end address; this one is **two** words,
/// and the second is either unwind data packed into it or an RVA pointing at the unwind data. Both
/// carry the function's length, which is all a region bound needs — so neither path is a full
/// unwind decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnwindRecord {
    /// The unwind data is packed into the word itself, and the function's length in **bytes** is
    /// this. `Flag` is 1 or 2 — the two differ in whether the prologue is folded into the epilogue,
    /// which changes nothing about the length.
    PackedLength(u64),
    /// The word is an RVA into `.xdata`, whose first word carries the length. Read it and hand it
    /// to [`xdata_length`].
    XdataAt(u32),
    /// `Flag` is 3, which is reserved. Nothing is claimed.
    Reserved,
}

/// Which of the three shapes above the second word is.
///
/// Measured on a 26100 ARM64 kernel image (`nt`), where both live forms occur in the same
/// `.pdata`: `nt!EtwpDestructIptData` is `[0x007773d8, 0x01420079]` — `Flag` 1, and
/// `(0x01420079 >> 2) & 0x7ff` is `0x1e`, so `0x78` bytes, which is what `.fnent` prints as
/// `FuncLen=78`. `nt!KeBugCheckEx` is `[0x0025df60, 0x0005f218]` — `Flag` 0, so an `.xdata` RVA.
pub(crate) fn unwind_record(second_word: u32) -> UnwindRecord {
    match second_word & 0x3 {
        0 => UnwindRecord::XdataAt(second_word),
        3 => UnwindRecord::Reserved,
        // `FunctionLength` is eleven bits at bit 2, in four-byte units — so a packed record caps a
        // function at 8188 bytes, and anything longer gets an `.xdata` record instead.
        _ => UnwindRecord::PackedLength((((second_word >> 2) & 0x7ff) as u64) * 4),
    }
}

/// The function's length in bytes, from the first word of its `.xdata` header.
///
/// `FunctionLength` is eighteen bits at bit 0, again in four-byte units. The header has a second
/// word in some shapes (`CodeWords` and `EpilogCount` both zero means an extension word follows),
/// and it does not matter here: the length is in the first word in every version of the layout.
///
/// `None` when `Vers` is not zero, which is a header shape this has not seen. Two bits at bit 18,
/// and every version but 0 is reserved today — so this is the same rule as everywhere else in the
/// crate, decode what has been measured and refuse the rest by name, rather than reading an unknown
/// layout's bits as if they were this one's.
///
/// Measured on the same image: `nt!KeBugCheckEx`'s `.xdata` word is `0x08000006`, so six
/// instructions — `0x25df60..0x25df78`, which is exactly where the engine's own listing ends.
/// `nt!KiSystemStartup`'s is `0x1800007f`, so `0x1fc` bytes, ending at the `brk` the routine
/// finishes on.
pub(crate) fn xdata_length(header: u32) -> Option<u64> {
    ((header >> 18) & 0x3 == 0).then(|| ((header & 0x0003_ffff) as u64) * 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every encoding below is one the engine rendered on the 26100 ARM64 kernel dump in
    /// `windbg-mcp`'s `docs/samples`, at the address given, so the expected target is the one the
    /// debugger itself printed rather than one computed the same way twice.
    const KE_BUG_CHECK_EX: u64 = 0xfffff802_e9e5df60;

    #[test]
    fn test_a_direct_call_carries_its_destination() {
        // `fffff802e9e5df70  97fffcc4  bl nt!KeBugCheck2 (fffff802e9e5d280)` — a backwards
        // displacement, which is what pins the sign extension.
        assert_eq!(
            flow(0x97ff_fcc4, KE_BUG_CHECK_EX + 0x10),
            Flow::Call(Some(0xfffff802_e9e5d280))
        );
    }

    #[test]
    fn test_a_direct_branch_is_a_jump_and_not_a_call() {
        // `b .+0x10`: the same encoding class as the `bl` above with bit 31 clear.
        assert_eq!(flow(0x1400_0004, 0x1000), Flow::Jmp(Some(0x1010)));
        assert_eq!(flow(0x9400_0004, 0x1000), Flow::Call(Some(0x1010)));
    }

    #[test]
    fn test_a_conditional_branch_takes_both_edges() {
        // `fffff802ea69dc1c  540002c1  bne nt!KiSystemStartup+0xb4 (fffff802ea69dc74)`.
        assert_eq!(
            flow(0x5400_02c1, 0xfffff802_ea69dc1c),
            Flow::Branch(Some(0xfffff802_ea69dc74))
        );
    }

    #[test]
    fn test_an_always_condition_does_not_fall_through() {
        // `b.al` and `b.nv` are conditions 1110 and 1111, and A64 gives both the meaning "always".
        // Reported as a jump, so a walk does not inherit a fall-through edge the processor has not
        // got. The `eq` form beside them is the control: same displacement, two live edges.
        assert_eq!(flow(0x5400_002e, 0x1000), Flow::Jmp(Some(0x1004)));
        assert_eq!(flow(0x5400_002f, 0x1000), Flow::Jmp(Some(0x1004)));
        assert_eq!(flow(0x5400_0020, 0x1000), Flow::Branch(Some(0x1004)));
    }

    #[test]
    fn test_compare_and_branch_is_conditional() {
        // `fffff802ea3773f0  b4000293  cbz x19,nt!EtwpDestructIptData+0x68 (fffff802ea377440)`.
        assert_eq!(
            flow(0xb400_0293, 0xfffff802_ea3773f0),
            Flow::Branch(Some(0xfffff802_ea377440))
        );
        // `fffff802ea69dc80  35000128  cbnz w8,nt!KiSystemStartup+0xe4 (fffff802ea69dca4)`.
        assert_eq!(
            flow(0x3500_0128, 0xfffff802_ea69dc80),
            Flow::Branch(Some(0xfffff802_ea69dca4))
        );
    }

    #[test]
    fn test_test_and_branch_reads_a_shorter_displacement() {
        // `fffff802ea69dc34  36800208  tbz w8,#0x10,nt!KiSystemStartup+0xb4 (fffff802ea69dc74)`.
        // Fourteen bits, not nineteen: reading it as nineteen would take in the bit-position field
        // above it and land somewhere else entirely, which is the whole reason this is its own arm.
        assert_eq!(
            flow(0x3680_0208, 0xfffff802_ea69dc34),
            Flow::Branch(Some(0xfffff802_ea69dc74))
        );
        // `fffff802ea69dc78  36100168  tbz w8,#2,nt!KiSystemStartup+0xe4 (fffff802ea69dca4)`.
        assert_eq!(
            flow(0x3610_0168, 0xfffff802_ea69dc78),
            Flow::Branch(Some(0xfffff802_ea69dca4))
        );
    }

    #[test]
    fn test_an_indirect_transfer_names_no_destination() {
        // `fffff802ea377420  d63f01e0  blr x15` and `fffff802ea37744c  d65f03c0  ret`, both from
        // `uf nt!EtwpDestructIptData`.
        assert_eq!(flow(0xd63f_01e0, 0x1000), Flow::Call(None));
        assert_eq!(flow(0xd65f_03c0, 0x1000), Flow::Return);
        // `br x16`, `retab`, `eret`.
        assert_eq!(flow(0xd61f_0200, 0x1000), Flow::Jmp(None));
        assert_eq!(flow(0xd65f_0fff, 0x1000), Flow::Return);
        assert_eq!(flow(0xd69f_03e0, 0x1000), Flow::Return);
    }

    #[test]
    fn test_a_trap_stops_a_walk_and_a_system_call_does_not() {
        // `fffff802e9e5df74  d43e0000  brk #0xF000`.
        assert_eq!(flow(0xd43e_0000, 0x1000), Flow::Trap);
        // `hlt #0`.
        assert_eq!(flow(0xd440_0000, 0x1000), Flow::Trap);
        // The system-call family, all three of it: `svc #0`, `hvc #0`, `smc #0`. A walk that
        // stopped at one would lose the rest of every routine that makes a system call.
        assert_eq!(flow(0xd400_0001, 0x1000), Flow::Fallthrough);
        assert_eq!(flow(0xd400_0002, 0x1000), Flow::Fallthrough);
        assert_eq!(flow(0xd400_0003, 0x1000), Flow::Fallthrough);
    }

    /// An encoding a class does not allocate is UNDEFINED, and UNDEFINED does not fall through.
    ///
    /// Both classes whose whole encoding space is spoken for end in `Trap`, and the fields that
    /// decide it are the ones a mask on the top bits does not reach. `0xd6200000` has `opc` `0001`
    /// and would read as a `blr` — it has `op2` zero, so it is not one; `0xd4000000` has `opc`
    /// `000` and would read as a system call — its `LL` is the reserved value; `0xd4000004` has a
    /// nonzero `op2`. Each of the three falls through if only `opc` is read, which is a sequential
    /// edge the processor has not got.
    ///
    /// The controls beside them are the real instructions nearest each: getting the guard wrong in
    /// the other direction would turn every indirect call on the architecture into a dead end.
    #[test]
    fn test_an_unallocated_encoding_in_an_allocated_class_stops() {
        // `op2` must be `11111` and `op3` one of three values, for every form in the table.
        assert_eq!(flow(0xd620_0000, 0x1000), Flow::Trap);
        assert_eq!(flow(0xd63f_0400, 0x1000), Flow::Trap);
        // And the four real ones those two are a bit away from.
        assert_eq!(flow(0xd63f_0000, 0x1000), Flow::Call(None));
        assert_eq!(flow(0xd61f_0000, 0x1000), Flow::Jmp(None));
        assert_eq!(flow(0xd65f_0bff, 0x1000), Flow::Return);
        assert_eq!(flow(0xd63f_0800, 0x1000), Flow::Call(None));
        // An unallocated `opc` inside the class, which used to fall through.
        assert_eq!(flow(0xd67f_0000, 0x1000), Flow::Trap);

        // The conditional-branch class has the same hole, and it is not one review found: `o1` is
        // bit 24 and only `0` is allocated, so `0x55000000` is in the class and is not a branch.
        assert_eq!(flow(0x5500_0020, 0x1000), Flow::Trap);
        assert_eq!(flow(0x5400_0020, 0x1000), Flow::Branch(Some(0x1004)));

        // The system-call family is `opc` `000`, `op2` `000`, and one of three `LL` values.
        assert_eq!(flow(0xd400_0000, 0x1000), Flow::Trap);
        assert_eq!(flow(0xd400_0004, 0x1000), Flow::Trap);
        assert_eq!(flow(0xd400_0005, 0x1000), Flow::Trap);
    }

    /// Everything in the exception-generation class but the system-call family stops.
    ///
    /// The point is the **default**, not the individual encodings: this class is where a word
    /// nothing matched must not be read as falling through, and the two that make that concrete
    /// are `tcancel` and `dcps`. `tcancel` unwinds to the continuation its `tstart` named and is
    /// UNDEFINED outside a transaction, so it has no fall-through under either reading — and it is
    /// the one a catch-all gets wrong quietly, since it would report the post-cancel code as
    /// reachable by an edge the processor has not got.
    #[test]
    fn test_nothing_else_in_the_exception_class_falls_through() {
        // `tcancel #1`, `opc` 011.
        assert_eq!(flow(0xd460_0020, 0x1000), Flow::Trap);
        // `dcps1`, `dcps2`, `dcps3` — `opc` 101, `LL` 01/10/11.
        assert_eq!(flow(0xd4a0_0001, 0x1000), Flow::Trap);
        assert_eq!(flow(0xd4a0_0002, 0x1000), Flow::Trap);
        assert_eq!(flow(0xd4a0_0003, 0x1000), Flow::Trap);
        // An unallocated `opc` in the class. UNDEFINED is an exception, so it does not continue
        // either, and this is the arm the reasoning above is actually about.
        assert_eq!(flow(0xd480_0000, 0x1000), Flow::Trap);
        // The neighbouring class is untouched: `1101 011` is the register branches, not this.
        assert_eq!(flow(0xd65f_03c0, 0x1000), Flow::Return);
    }

    #[test]
    fn test_the_reserved_top_level_space_is_the_undefined_instruction() {
        // `udf`, of which the zero word is the one that matters: inter-function padding, which the
        // engine renders `???` while still reporting the four zero bytes it read. Falling through
        // it walks into the next function.
        assert_eq!(flow(0x0000_0000, 0x1000), Flow::Trap);
        assert_eq!(flow(0x0000_ffff, 0x1000), Flow::Trap);
        // And the rest of the Reserved space, which is not the `udf` pattern and is undefined all
        // the same. `op0` is bits 28..25 and this is every word with it zero.
        assert_eq!(flow(0x0001_0000, 0x1000), Flow::Trap);
        assert_eq!(flow(0x01ff_ffff, 0x1000), Flow::Trap);
        assert_eq!(flow(0xe1ff_ffff, 0x1000), Flow::Trap);
        // The neighbouring top-level spaces are **not** trapped: unallocated today is not reserved
        // for ever, and they carry no control flow to get wrong either way.
        assert_eq!(flow(0x0200_0000, 0x1000), Flow::Fallthrough);
        assert_eq!(flow(0x0600_0000, 0x1000), Flow::Fallthrough);
    }

    /// A branch class this does not decode reads as a fall-through, and that is a **documented**
    /// limit rather than an undiscovered one.
    ///
    /// The word is Armv9.6 FEAT_CMPBR's `cbbne w1,w2,+8` as review reported it, and it is
    /// *unverified here* — no target on this bench renders one, which is the whole reason the
    /// class is not decoded. So what this pins is the behaviour and not the encoding: a word in
    /// that space is read as continuing, which loses the taken edge and keeps the real one.
    ///
    /// It is deliberately a test that **fails when somebody decodes CMPBR**, at which point the
    /// module header's paragraph about it is the thing to update rather than this assertion to
    /// relax.
    #[test]
    fn test_a_branch_class_this_does_not_decode_reads_as_a_fall_through() {
        assert_eq!(flow(0x74e2_8041, 0x1000), Flow::Fallthrough);
    }

    #[test]
    fn test_an_ordinary_instruction_falls_through() {
        // `pacibsp`, `stp fp,lr,[sp,#-0x10]!`, `mov fp,sp`, `adrp x8,..`, `ldr x19,[x20,#0x438]`,
        // `cmp w8,#0` — the first six words of two real prologues. Nothing here transfers control,
        // and on a fixed-width encoding that is a decoded answer rather than a default.
        for word in [
            0xd503_237f_u32,
            0xa9bf_7bfd,
            0x9100_03fd,
            0x9000_1b68,
            0xf942_1e93,
            0x7100_011f,
        ] {
            assert_eq!(flow(word, 0x1000), Flow::Fallthrough, "{word:#010x}");
        }
    }

    #[test]
    fn test_a_branch_target_keeps_the_instruction_s_address_space() {
        // A64 is 64-bit only and the displacement is added to the whole address, so a branch near
        // the top of the kernel half stays there and one that crosses a 4 GB boundary is not
        // dragged back into it. Both are the failure the x86 path's `canonical_target` exists for,
        // and neither is reachable here.
        assert_eq!(
            flow(0x1400_0001, 0xffff_ffff_ffff_fffc),
            Flow::Jmp(Some(0x0000_0000_0000_0000))
        );
        assert_eq!(
            flow(0x1400_0001, 0x0000_0000_ffff_fffc),
            Flow::Jmp(Some(0x0000_0001_0000_0000))
        );
        // The largest backward displacement a `b` can carry: 2^25 words.
        assert_eq!(
            flow(0x1600_0000, 0x0000_0001_0000_0000),
            Flow::Jmp(Some(0x0000_0000_f800_0000))
        );
    }

    #[test]
    fn test_the_packed_unwind_record_carries_a_length() {
        // `nt!EtwpDestructIptData`: `.fnent` prints `Flag=1 FuncLen=78`.
        assert_eq!(unwind_record(0x0142_0079), UnwindRecord::PackedLength(0x78));
        // `nt!EtwpUpdateLastBranchTracingConfiguration`: `Flag=1 FuncLen=D4`.
        assert_eq!(unwind_record(0x01c3_00d5), UnwindRecord::PackedLength(0xd4));
        // Flag 2 is the other packed form and reads the same field.
        assert_eq!(unwind_record(0x0000_000a), UnwindRecord::PackedLength(8));
        // Eleven bits, so the cap is 8188 bytes rather than the 8192 an even count would give.
        assert_eq!(unwind_record(0xffff_fffd), UnwindRecord::PackedLength(8188));
    }

    #[test]
    fn test_a_zero_flag_is_an_xdata_pointer_and_not_a_length() {
        // `nt!KeBugCheckEx`'s second word. Read as a packed length it would be
        // `((0x5f218 >> 2) & 0x7ff) * 4`, which is a plausible-looking 0x1860 bytes for a routine
        // that is 24 — the wrong answer that looks right, and the reason the flag is read first.
        assert_eq!(
            unwind_record(0x0005_f218),
            UnwindRecord::XdataAt(0x0005_f218)
        );
        assert_eq!(unwind_record(0x0000_0003), UnwindRecord::Reserved);
    }

    #[test]
    fn test_the_xdata_header_carries_a_length_and_a_version() {
        // `nt!KeBugCheckEx`: six instructions.
        assert_eq!(xdata_length(0x0800_0006), Some(24));
        // `nt!KiSystemStartup`: 0x7f instructions.
        assert_eq!(xdata_length(0x1800_007f), Some(0x1fc));
        // `nt!KeQueryPerformanceCounter`: `.fnent` prints `FuncLen=330`.
        assert_eq!(xdata_length(0x1840_00cc), Some(0x330));
        // A version this has not seen is refused rather than read with these bits' meanings.
        assert_eq!(xdata_length(0x0004_0006), None);
    }
}
