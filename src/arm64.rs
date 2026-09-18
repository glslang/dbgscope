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
//! A64 is fixed-width and regular. Every transfer of control is one of six encoding classes, all
//! discriminated by a mask on the top bits of a 32-bit word, and there is no seventh: A64 has no
//! instruction that writes the program counter as a general register, so a word outside those
//! classes falls through by construction. That is what makes `Flow::Fallthrough` the default here
//! a *decoded* answer rather than a guess — the opposite of the x86 side, where the default has to
//! be [`Flow::Unknown`](crate::dbgeng::Flow::Unknown) because a variable-length encoding this
//! decoder does not know may be anything at all.
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
    // Conditional branch (immediate): `0101010 o1 imm19 o0 cond`. `o1` must be zero; `o0` picks
    // `bc.cond` (FEAT_HBC) from `b.cond`, and both are conditional, so it is not read.
    //
    // **`al` and `nv` are unconditional and are reported as such.** A64 gives condition `1110` and
    // `1111` the meaning "always", so `b.al` never falls through. Calling it `Branch` would hand a
    // reachability walk a fall-through edge that the processor does not have — and an edge that is
    // not there is exactly what a sound `REACHABLE` verdict must never rest on. No compiler emits
    // the form; that is a reason to expect the arm to be cold, not a reason to get it wrong.
    if word & 0xff00_0000 == 0x5400_0000 {
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
    // `opc` alone separates them, including the pointer-authentication forms: `braa`/`brab` are
    // `1000` to `br`'s `0000`, `blraa`/`blrab` are `1001` to `blr`'s `0001`, and `retaa`/`retab`
    // share `ret`'s `0010`. So the low three bits of `opc` would be enough for the first two and
    // the whole nibble is matched anyway, because `0101` (`drps`) is not `0001`.
    if word & 0xfe00_0000 == 0xd600_0000 {
        return match (word >> 21) & 0xf {
            // `br`, `braaz`, `brabz`, `braa`, `brab`.
            0b0000 | 0b1000 => Flow::Jmp(None),
            // `blr` and its authenticating forms.
            0b0001 | 0b1001 => Flow::Call(None),
            // `ret`/`retaa`/`retab`, then `eret` and `drps`. The last two are an exception return
            // and a debug-state restore: neither continues at the next instruction, which is the
            // only property `Return` claims here.
            0b0010 | 0b0100 | 0b0101 => Flow::Return,
            // Unallocated. Fall through rather than stop: this decodes control flow, and a word it
            // does not recognise has not been shown to transfer any.
            _ => Flow::Fallthrough,
        };
    }
    // Exception generation: `11010100 opc imm16 op2 LL`.
    if word & 0xff00_0000 == 0xd400_0000 {
        return match (word >> 21) & 0x7 {
            // `brk` and `hlt`. Both trap to the debugger or the host with no architectural return
            // path, and MSVC emits `brk #0xf000` as the padding behind an unreachable tail — the
            // `__fastfail` of this architecture, and the reason a walk must not fall through one.
            0b001 | 0b010 => Flow::Trap,
            // `svc`, `hvc`, `smc` (`opc` `000`), and the `dcps` family (`101`), which exists only
            // in debug state. All of them resume at the next instruction, so stopping here would
            // discard everything after a system call.
            _ => Flow::Fallthrough,
        };
    }
    // `udf #imm16` — the permanently undefined encoding, `0000000000000000 imm16`. It is what a
    // zero word is, and a zero word is what sits between functions: the engine renders those `???`
    // even though it read them perfectly well, which is a different fact from the `??` it prints
    // for bytes it could not read at all. Trapping stops a walk at the end of a function; falling
    // through would run it into whatever the linker put next.
    if word >> 16 == 0 {
        return Flow::Trap;
    }
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
        // `svc #0` returns, and a walk that stopped there would lose the rest of every routine
        // that makes a system call.
        assert_eq!(flow(0xd400_0001, 0x1000), Flow::Fallthrough);
    }

    #[test]
    fn test_a_zero_word_is_the_undefined_instruction() {
        // Inter-function padding, which the engine renders `???` while still reporting the four
        // zero bytes it read. Falling through it walks into the next function.
        assert_eq!(flow(0x0000_0000, 0x1000), Flow::Trap);
        assert_eq!(flow(0x0000_ffff, 0x1000), Flow::Trap);
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
