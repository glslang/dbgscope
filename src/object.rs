//! The kernel **object namespace**, walked by name.
//!
//! `\Device\MountPointManager` is not an address, and nothing in [`crate::dbgeng`] could turn it
//! into one: a symbol names code and data the linker placed, while an object is created at run
//! time and filed under a name in a tree the object manager keeps. The debugger's own answer to
//! this is `!object`, which is an extension command printing text; this is the same walk answering
//! in values.
//!
//! # What the walk is
//!
//! `nt!ObpRootDirectoryObject` points at the root [`_OBJECT_DIRECTORY`]. A directory is an array
//! of hash buckets, each a chain of `_OBJECT_DIRECTORY_ENTRY`, each pointing at an object **body**.
//! The name of a body is not in the body: it is in an `_OBJECT_HEADER_NAME_INFO` that sits *before*
//! the `_OBJECT_HEADER`, present only when the header's `InfoMask` says so, at a distance the
//! kernel looks up in `nt!ObpInfoMaskToOffset`. So resolving one path component means enumerating
//! a directory and reading a name out from under every object in it.
//!
//! **Every bucket is walked rather than the one the name hashes to.** The hash is the object
//! manager's own, over a case-folded name using the kernel's upcase table, and a wrong reimplementation
//! of it does not fail — it looks in the wrong bucket and reports that the object does not exist,
//! which is the answer a caller would act on. A directory holds tens of entries, so walking all of
//! them costs nothing worth having that risk for.
//!
//! # What it refuses
//!
//! Every list is capped, and a cap is an **error rather than a short list**. A namespace is data
//! this crate did not write: a corrupt chain is a cycle, and a directory reported shorter than it
//! is answers "which symbolic links point here" wrongly, which is the one thing a security question
//! must not do.
//!
//! Names are folded the way `nt!ObpLookupDirectoryEntry` folds them -- through **the target's
//! own** upcase table, walked as the 8-4-4 trie `RtlUpcaseUnicodeChar` walks it, with this host's
//! copy of that routine standing in where the target will not say where its table is. See
//! [`Upcase`]. Reproducing the fold instead of performing it was measurably wrong for 326 of the
//! 65,536 code units, and wrong *confidently* for 224 of them; performing it against the host's
//! table was right for all 65,536 on one bench and had nothing to say about a target of another
//! vintage, which is what reading the target's own closes.
//!
//! # Where it works
//!
//! A live kernel, and a kernel dump complete enough to carry `nt`'s data pages. It does **not**
//! work on a kernel minidump: measured against `docs/samples/081226-2187-01.dmp` in the consumer,
//! `nt!ObpRootDirectoryObject` itself reads `????????`, so the walk stops at its first read and
//! says so rather than reporting an empty namespace.

use std::cell::RefCell;
use std::collections::BTreeMap;

use thiserror::Error;

use crate::dbgeng::{DbgEngError, DebugEngine};

/// The most entries one directory may hold before the walk refuses it.
///
/// `\GLOBAL??` on a busy machine holds a few thousand; this is well above that and far below a
/// chain that has looped. It bounds the whole directory rather than one bucket, because a cycle
/// can be spread across buckets as easily as kept inside one.
// The looping-chain unit tests exhaust this bound. At 65,536 entries their byte-addressed
// fixtures take hours under Miri; 32 exercises the same refusal with far fewer interpreted reads.
// Keep the full bound in production and normal tests, including non-test builds under Miri.
const MAX_ENTRIES: usize = if cfg!(all(test, miri)) { 32 } else { 65_536 };

/// The most path components a name may have. `\Device\HarddiskVolume1` is two.
const MAX_COMPONENTS: usize = 32;

/// The longest object **name** this reads, in bytes of UTF-16.
///
/// `_UNICODE_STRING::Length` is a `USHORT`, so the structure's own limit is 64 KiB; a name that
/// long is not one the object manager made. A name is one component and not a path -- the longest
/// in `\\Device` on an ordinary machine is a few dozen bytes.
const MAX_NAME_BYTES: usize = 1024;

/// The longest **link target**, which is a different quantity and needs a bound of its own.
///
/// A target is a whole path where a name is one component of one, so holding it to the name bound
/// refuses a link that is perfectly ordinary, with a message about object names. This is the
/// structure's own limit rounded down to something a path can reach: `UNICODE_STRING` counts bytes
/// in a `USHORT`, and `MAX_PATH` twice over in UTF-16 is well inside it.
const MAX_TARGET_BYTES: usize = 32_768;

/// The most any structure this walk reads may be, in bytes.
///
/// Every one of them is tens of bytes: `_OBJECT_HEADER` is 0x30, a name header 0x20, a
/// `UNICODE_STRING` 0x10. A bound on the *relation* between offsets is not a bound on their size --
/// a buffer offset of nearly four gigabytes satisfies every ordering this checks and then asks the
/// target for a read that large, which is an allocation failure rather than a refusal. So the
/// magnitudes are bounded too, and every sum that reaches this is checked.
const MAX_STRUCTURE: usize = 4096;

/// The most hash buckets a directory may claim.
///
/// Windows uses 37 and has for a long time. This is far above that and far below a count that
/// would have the walk read for minutes off a [`Layout`] nobody checked.
const MAX_BUCKETS: usize = 1024;

/// What the object manager calls a directory's type, and the one type name this walk acts on.
const DIRECTORY: &str = "Directory";

/// The bit in `_OBJECT_SYMBOLIC_LINK::Flags` that says the object's callback arm is live.
///
/// **Read out of the kernel rather than out of a document.** `nt!ObpParseSymbolicLinkEx` on
/// 26100 x64 loads `Flags`, tests `10h`, and on that branch calls through the pointer at `+0x08`
/// with the context at `+0x10`; with the bit clear it takes `+0x08` as the `_UNICODE_STRING` it
/// is in the other arm. The neighbouring bits are all something else -- `2h` asks whether the
/// token is sandboxed, `8h` masks an access mask, `1h` is a silo check -- which is why this was
/// measured rather than guessed: the first bit anyone would have tried is the sandbox one.
const SYMBOLIC_LINK_CALLBACK: u32 = 0x10;

/// The globals a walk names when it has to say which one is missing.
const ROOT_SYMBOL: &str = "nt!ObpRootDirectoryObject";
const OFFSETS_SYMBOL: &str = "nt!ObpInfoMaskToOffset";

/// Why a namespace walk could not answer.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ObjectError {
    /// Target memory that would not read. On a kernel minidump this is the first thing that
    /// happens, and it names the address so that the answer is "this target has no namespace"
    /// rather than "this namespace is empty".
    #[error("could not read {len} bytes of the object namespace at {at:#x}")]
    Unreadable { at: u64, len: usize },
    /// A structure whose fields contradict themselves.
    #[error("the object namespace is malformed: {reason}")]
    Malformed { reason: &'static str },
    /// A path that is not one the object manager could have filed anything under.
    #[error("{path:?} is not an object path: {reason}")]
    BadPath { path: String, reason: &'static str },
    /// Every component before this one resolved, and this one is not in its directory.
    #[error("{component:?} is not in {directory:?}")]
    NotFound {
        directory: String,
        component: String,
    },
    /// A component resolved to something that is not a directory, with path left to walk.
    #[error("{component:?} is not a directory, so {rest:?} cannot be under it")]
    NotADirectory { component: String, rest: String },
    /// A component could not be **typed**, so this walk will not treat it as a directory.
    ///
    /// Distinct from [`Self::NotADirectory`], and the distinction is the whole reason this variant
    /// exists: that one says an object *is* something else, which for a directory this could not
    /// name would be a lie. The walk still refuses, because a guard that passes on doubt passes on
    /// exactly the case it is for -- but it refuses saying it could not tell.
    #[error("{component:?} could not be typed, so this walk will not descend through it")]
    Untyped { component: String },
    /// A global this operation needs is not one the target resolves.
    ///
    /// Per operation rather than per walk: reading a symbolic link needs none of the namespace's
    /// globals, and taking it away because the root pointer was renamed would refuse something this
    /// target can perfectly well answer.
    #[error("this target does not resolve {what}, which this operation reads")]
    Unavailable { what: &'static str },
    /// A cap was reached, so what this could answer with is a **short** list.
    #[error("{what} exceeded its bound of {bound}, so this list would be shorter than the truth")]
    TooMany { what: &'static str, bound: usize },
    /// The walk was stopped before it could answer -- a caller's deadline, or an interrupt.
    ///
    /// **Not [`Self::NotFound`] and not [`Self::TooMany`]**: the first says the target does not
    /// hold it and the second that this walk refuses to answer about it, while this says nobody
    /// asked long enough. A caller retries it with more time; the other two never succeed.
    #[error("the namespace walk was stopped before it reached {what}")]
    Halted { what: String },
    /// It is not among the entries of its directory that could be named, and some could not be.
    ///
    /// **Distinct from [`Self::NotFound`], and the distinction is the whole reason this exists.**
    /// That one says the directory was read in full and this name is not in it, which is a fact
    /// about the target. This one cannot say that: an entry whose name could not be read is an
    /// object that is *there* and was not named, so it may be the very one being asked for.
    ///
    /// **And it carries both counts rather than their sum**, for the reason [`Listing`] keeps them
    /// apart: a page that was out will be back, and an entry the object manager cannot have
    /// written will not. One figure, under a message saying the entries could not be *read*, would
    /// report structural corruption as transient paging and send a reader away to retry it.
    ///
    /// **The fold is not a third way to fall short here**, and it was one for a day.
    /// [`same_object_name`] performs the object manager's own fold rather than reproducing it, so
    /// every name either matches or does not; there is no comparison it declines to make, and so
    /// nothing to count.
    #[error(
        "{component:?} is not among the entries of {directory:?} that could be named \
         ({unreadable} would not read, {malformed} contradict themselves) -- so this cannot say \
         it is absent"
    )]
    NotFoundInPart {
        directory: String,
        component: String,
        unreadable: usize,
        malformed: usize,
    },
}

/// Whether two object **names** are the one name the object manager would file an object under,
/// folded through **this host's** upcase table.
///
/// The object manager is case-insensitive -- `nt!ObpCaseInsensitive` is 1 on 26100 -- so `Device`
/// and `DEVICE` are one name. It is not insensitive the way ASCII is, and it is **not insensitive
/// the way Unicode is either**, which is the whole difficulty: it folds through the system's own
/// upcase table, and that table is not Unicode's simple case mapping.
///
/// So this does not reproduce the fold, it **performs** it -- against the table of whichever
/// machine this runs on. [`Upcase::of_host`] is what that means and where the limit is written
/// down; [`Namespace::upcase`] is the same fold against the **target's** table, which is what the
/// walk itself uses and what a caller holding a target should use too. This is for a caller that
/// has two names and no target, and gives the answer both agree on wherever the two machines' NLS
/// data agrees.
///
/// **This compares one name, not a path.** A caller holding a whole path may pass it: the fold is
/// per code unit, so a separator folds to itself and comparing `\Device\Foo` against `\DEVICE\FOO`
/// gives the same answer as comparing the components pairwise. What it does not do is anything
/// about *prefixes* -- `\Device\HarddiskVolume1\dir` is not `\Device\HarddiskVolume1`, and a caller
/// wanting that has to ask it -- or about a trailing separator, which is a caller's habit rather
/// than part of a name and a caller's to trim.
pub fn same_object_name(one: &str, other: &str) -> bool {
    Upcase::of_host().same_name(one, other)
}

/// Where a target keeps the upcase table the object manager folds names through.
///
/// Three coordinates rather than one address, because the table is reached through two structures
/// and neither offset is a constant: `_ESERVERSILO_GLOBALS` grows between builds and
/// `_RTL_NLS_STATE` sits inside it. Resolved from the target's own symbols and type information by
/// [`DebugEngine::object_globals`], the way [`Layout`] is and for the same reason -- a table of
/// literals here would decode a different build confidently and wrongly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpcaseTable {
    /// `nt!PspHostSiloGlobals` -- the structure itself, not a pointer to it.
    ///
    /// **The host silo's globals, which is a limit rather than an oversight.** The fold the object
    /// manager performs reads `PsGetCurrentServerSiloGlobals()`, which -- measured by
    /// disassembling it on 26100 x64 -- returns `&PspHostSiloGlobals` unless the *calling thread*
    /// is in a server silo, and that silo's globals when it is. A debugger walking a namespace has
    /// no calling thread in it, so there is no current silo to ask for, and the host silo is both
    /// the answer for every thread outside a container and the only one a symbol reaches. A server
    /// silo with its own NLS data would fold its own names differently and nothing here would
    /// know.
    pub silo_globals: u64,
    /// `_ESERVERSILO_GLOBALS::RtlNlsState` -- `0x408` on 26100 x64.
    pub nls_state: u32,
    /// `_RTL_NLS_STATE::UnicodeUpcaseTable844` -- `0xa8` on 26100 x64, which puts the pointer at
    /// silo globals `+0x4b0` on that build, the same distance measured on 26100 ARM64.
    pub upcase_table: u32,
}

/// Which machine's table a fold answered from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpcaseFrom {
    /// The target's own, at this address, for every code unit folded so far.
    Target(u64),
    /// The target's table is at this address **and did not answer for every unit**: at least one
    /// read into the trie did not come back, and that unit was folded on this host instead.
    ///
    /// **A fold of two machines' NLS data, which is the thing this type exists to make visible.**
    /// A partial dump is the ordinary way to get here -- the pointer's page is present and a page
    /// of the table is not -- and without this case that fold reported as [`Self::Target`], which
    /// is the provenance claim being wrong in the one direction that matters. It is not an error:
    /// every comparison still answers, because a table that will not *read* says nothing about how
    /// the target folds. It is a caller's cue that some of the answer came from here.
    Mixed { at: u64 },
    /// **This host's**, because the target's could not be reached at all -- no [`Globals::upcase`]
    /// to reach it by, or a table pointer whose read did not come back. The answer is then this
    /// machine's NLS data standing in for the target's, which is right wherever the two agree and
    /// says nothing about where they do not.
    Host,
}

/// The fold `nt!ObpLookupDirectoryEntry` performs on a name, over whichever table this can reach.
///
/// # The table is the target's, and the host's is what is left
///
/// `RtlUpcaseUnicodeChar` reads **the machine it runs on**. Calling the host's copy to fold a
/// *target's* names is right exactly as far as the two machines' NLS data agrees, which on the
/// bench this was settled on was all 65,536 code units -- both being 26100-era Windows, which is
/// the easy case rather than the general one. Between vintages nothing guarantees it: Windows'
/// table declines mappings Unicode makes and predates the `U+A7xx` additions, so it moves when
/// Windows adopts them, and a fold that disagreed with the target would report two objects as one
/// or one as two, silently and with nothing to detect it. So the table is read from the target
/// when the target says where it is, and the host's call is what is left when it does not.
///
/// # The walk
///
/// Transcribed from `RtlUpcaseUnicodeChar` itself rather than from a description of it -- the
/// disassembly is in [`Self::from_table`]. Three bands, of which the first two read no table at
/// all, which is why an ASCII name costs no target read: `U+0061`..`U+007A` has `0x20` subtracted,
/// anything else below `U+00C0` comes back unchanged, and the rest indexes an 8-4-4 trie.
///
/// **A surrogate is passed through, and that is the kernel's answer too.** A per-`WCHAR` fold is
/// handed half a character at a time and cannot fold a non-BMP letter, so two spellings of one
/// Deseret name are genuinely two objects. `RtlUpcaseUnicodeChar` moves no unit in `D800..DFFF` --
/// measured across the range -- so the band needs no exception and has none; the trie's own leaves
/// are zero there.
///
/// # What it costs
///
/// Three target reads per *distinct* code unit at or above `U+00C0`, once, and none after that --
/// they are remembered, because one path component is compared against every entry in a directory
/// and a directory holds tens of them. A name that is entirely ASCII -- which is nearly every name
/// in the namespace -- reads nothing and remembers nothing.
pub struct Upcase<'a> {
    /// The target's table and what it takes to read it, or [`None`] for the host's fold.
    target: Option<TargetTable<'a>>,
    /// What has been resolved so far. Behind a [`RefCell`] because folding happens through `&self`
    /// -- the walk holds one of these and compares names from inside an iterator.
    known: RefCell<Known>,
}

/// A target's table: where it is, how to read it, and how wide a pointer is on the way.
#[derive(Clone, Copy)]
struct TargetTable<'a> {
    memory: &'a dyn Memory,
    table: UpcaseTable,
    /// A pointer's width on **this target**, which is [`Layout::pointer`]'s figure and is derived
    /// from the target's own structures rather than assumed from the host.
    ///
    /// Carried here because the table is reached through a pointer, and a 32-bit kernel debugged
    /// from a 64-bit host keeps its pointers at four. Reading eight there takes four bytes of
    /// table pointer and four of whatever follows it -- see [`Upcase::base`] for what that
    /// produced before this field existed.
    pointer: usize,
}

/// The table's address once it has been asked for, and the units folded through it.
#[derive(Debug, Default)]
struct Known {
    /// [`None`] is "not asked yet"; `Some(None)` is "asked, and this target would not say", which
    /// is remembered so a target whose globals do not read is not re-read once per code unit.
    base: Option<Option<u64>>,
    units: BTreeMap<u16, u16>,
    /// Whether any unit was folded on **this host** after the target's table was located -- the
    /// one fallback [`UpcaseFrom`] could not otherwise be told about, because the base is
    /// populated and every later `source()` would have claimed the target answered.
    host_folded: bool,
}

impl<'a> Upcase<'a> {
    /// The fold performed against **the target's** table, falling back to this host's.
    /// `pointer` is a pointer's width on the target, in bytes -- [`Layout::pointer`], which
    /// derives it from the target's own structures. Any width but 4 or 8 folds on the host, since
    /// a table this cannot read a pointer to is a table it cannot reach.
    pub fn of_target(memory: &'a dyn Memory, table: UpcaseTable, pointer: usize) -> Self {
        Self {
            target: Some(TargetTable {
                memory,
                table,
                pointer,
            }),
            known: RefCell::default(),
        }
    }

    /// The fold performed against **this host's** table, for a caller that has names and no
    /// target.
    ///
    /// Sound wherever the host's NLS data matches the target's, which is not a thing this can
    /// check -- see [`Upcase`] for what moves between builds. A caller holding a target should
    /// fold through [`Namespace::upcase`] instead.
    pub fn of_host() -> Self {
        Self {
            target: None,
            known: RefCell::default(),
        }
    }

    /// Which table this answers from -- **resolving it if that has not happened yet**, which for a
    /// target costs the one read that finds the table.
    ///
    /// What lets a caller say which machine's NLS data an answer came from, rather than leaving a
    /// fallback to look like a measurement.
    ///
    /// **It describes the folds performed so far, not the target**, and it has to: the table is
    /// read lazily, so whether a page of it answers is not known until a unit needs that page.
    /// Before anything non-ASCII is folded this reports [`UpcaseFrom::Target`] as soon as the
    /// pointer reads, and a later unit whose page is absent moves it to [`UpcaseFrom::Mixed`].
    /// A caller reporting provenance should therefore ask **after** the comparisons it is
    /// reporting on.
    pub fn source(&self) -> UpcaseFrom {
        // `base()` first and on its own: it may read and record, and holding a borrow across it
        // would be a second one on the same `RefCell`.
        let base = self.base();
        match (base, self.known.borrow().host_folded) {
            (Some(at), true) => UpcaseFrom::Mixed { at },
            (Some(at), false) => UpcaseFrom::Target(at),
            (None, _) => UpcaseFrom::Host,
        }
    }

    /// Whether two object **names** are the one name the object manager would file an object
    /// under. See [`same_object_name`] for what counts as a name here, and what a path does not.
    pub fn same_name(&self, one: &str, other: &str) -> bool {
        self.fold(one) == self.fold(other)
    }

    /// A name folded the way the object manager folds one: **one UTF-16 code unit in, one out.**
    fn fold(&self, name: &str) -> Vec<u16> {
        name.encode_utf16().map(|unit| self.unit(unit)).collect()
    }

    /// One code unit, in the three bands the lookup folds in.
    fn unit(&self, unit: u16) -> u16 {
        match unit {
            // The comparison's own fast path, written the way it writes it -- and the reason the
            // table is not simply read for every unit: these two bands consult no table, so they
            // are the same answer on any machine, and keeping them here is what lets the walk's
            // tests run against a target carrying no NLS data at all.
            0x61..=0x7a => unit - 0x20,
            // Below the floor the lookup reaches for no table, so neither does this.
            0..=0xbf => unit,
            _ => {
                if let Some(remembered) = self.known.borrow().units.get(&unit) {
                    return *remembered;
                }
                let folded = self.uncached(unit);
                self.known.borrow_mut().units.insert(unit, folded);
                folded
            }
        }
    }

    /// One code unit at or above `U+00C0`, from whichever table answers.
    fn uncached(&self, unit: u16) -> u16 {
        let (Some(target), Some(base)) = (self.target, self.base()) else {
            return Self::on_host(unit);
        };
        // **The routine's own null check, and the one place a miss is not a fallback.**
        // `RtlUpcaseUnicodeChar` tests the table pointer before it indexes anything and returns
        // the code unit unchanged when it is zero -- so a target whose pointer reads as null folds
        // by the two ASCII bands and by nothing else, and that is its answer rather than a gap in
        // this one. Standing the host's table in here would fold where the target does not, which
        // is the exact shape of the bug that stopped this crate reproducing the table at all.
        if base == 0 {
            return unit;
        }
        match Self::from_table(target.memory, base, unit) {
            Some(folded) => folded,
            // **A table that would not read is not a target that does not fold.** The reads above
            // are of a structure this located by symbol, so a miss is a page that was out or an
            // offset that is not this build's -- neither of which says anything about how the
            // target folds. The host's table is the same stand-in it was before any of this.
            //
            // **And it is recorded, because the base is already resolved and nothing else would
            // say.** Without the flag, `source()` reads the populated base and answers
            // [`UpcaseFrom::Target`] for a fold that was partly this host's -- a provenance claim
            // that is wrong in exactly the direction this whole change exists to fix. It is not
            // cleared: one unit folded on the wrong machine is enough to make the comparison this
            // walk performs a comparison of two tables.
            None => {
                self.known.borrow_mut().host_folded = true;
                Self::on_host(unit)
            }
        }
    }

    /// The table's address, read once and remembered, or [`None`] for "fold on the host".
    ///
    /// **A null is resolved, not rejected.** A pointer that reads as zero is a table this target
    /// does not have, which is an answer -- see [`Self::uncached`], which is where the routine's
    /// own null check lives. What [`None`] means here is narrower: the read itself did not come
    /// back, so nothing is known about the target's table and the host's stands in.
    fn base(&self) -> Option<u64> {
        if let Some(asked) = self.known.borrow().base {
            return asked;
        }
        let target = self.target?;
        let at = target
            .table
            .silo_globals
            .wrapping_add(u64::from(target.table.nls_state))
            .wrapping_add(u64::from(target.table.upcase_table));
        // **At the target's pointer width, not this host's**, and it is the one read here that
        // could not be got right by degrading. This used to take eight bytes unconditionally, on
        // the reasoning that a 32-bit kernel would then yield an address that does not read and
        // fall back to the host -- which was a guess about the four bytes that follow the pointer,
        // written as though it were a fact. When they happen to read, the eight-byte value is a
        // plausible address assembled from two unrelated halves; the trie walk then succeeds
        // against whatever is there and returns folds that are simply wrong, with nothing having
        // failed and `source()` reporting `Target`. A silently wrong fold presented as the
        // target's own answer is the exact failure this whole change exists to prevent, so the
        // width is carried rather than assumed.
        let base = match target.pointer {
            4 => target.memory.read(at, 4).and_then(|bytes| {
                bytes
                    .first_chunk::<4>()
                    .map(|four| u64::from(u32::from_le_bytes(*four)))
            }),
            8 => target.memory.read(at, 8).and_then(|bytes| {
                bytes
                    .first_chunk::<8>()
                    .map(|eight| u64::from_le_bytes(*eight))
            }),
            // [`Layout::check`] refuses any other width before a [`Namespace`] is built, so this
            // is reachable only through [`Self::of_target`] directly. A width this cannot read a
            // pointer at is a table it cannot reach, which is what [`UpcaseFrom::Host`] says.
            _ => None,
        };
        self.known.borrow_mut().base = Some(base);
        base
    }

    /// One code unit through the target's 8-4-4 trie.
    ///
    /// Transcribed instruction for instruction from `ntdll!RtlUpcaseUnicodeChar` on 26200 x64,
    /// which is the same routine `nt!ObpLookupDirectoryEntry` inlines against the kernel's copy of
    /// the table:
    ///
    /// ```text
    ///     movzx r8d,cx                    ; the code unit
    ///     movzx eax,cx
    ///     shr   rax,8                     ; high byte
    ///     movzx edx,word ptr [r9+rax*2]   ; level one: an element index
    ///     mov   eax,r8d
    ///     shr   eax,4
    ///     and   r8d,0Fh                   ; low nibble
    ///     and   eax,0Fh                   ; middle nibble
    ///     add   edx,eax
    ///     movzx edx,word ptr [r9+rdx*2]   ; level two: another element index
    ///     add   edx,r8d
    ///     add   cx,word ptr [r9+rdx*2]    ; level three: a delta, added
    /// ```
    ///
    /// Three things in that are worth keeping. Every index is an index of `u16` **elements from
    /// the same base** -- not a byte offset, and not relative to its own level. The leaf is a
    /// **delta added** to the code unit rather than the folded unit itself, so a leaf of zero
    /// means "this unit does not fold", which is most of the table. And the add is 16-bit, so it
    /// wraps; nothing in a real table does, and reproducing the wrap costs a `wrapping_add` rather
    /// than a decision about what to do instead.
    ///
    /// **The reads are bounded by the arithmetic rather than by a check.** A level's value is a
    /// `u16` and a nibble is at most 15, so no index exceeds `0x1000e` and no read lands more than
    /// 128 KiB past the base, whatever the table holds. A corrupt table therefore reads the wrong
    /// element *of itself*; it cannot be made to read an address of its own choosing.
    fn from_table(memory: &dyn Memory, base: u64, unit: u16) -> Option<u16> {
        let element = |index: u32| -> Option<u16> {
            let bytes = memory.read(base.wrapping_add(u64::from(index) * 2), 2)?;
            bytes
                .first_chunk::<2>()
                .map(|pair| u16::from_le_bytes(*pair))
        };
        let level1 = u32::from(element(u32::from(unit >> 8))?);
        let level2 = u32::from(element(level1 + u32::from((unit >> 4) & 0xf))?);
        let delta = element(level2 + u32::from(unit & 0xf))?;
        Some(unit.wrapping_add(delta))
    }

    /// One code unit through **this host's** table.
    ///
    /// Miri cannot call a foreign function, and the walk's tests are worth running under it: they
    /// are the pointer arithmetic this module is, over a fake target. Every name they use is
    /// ASCII, which the bands above answer identically, so the shim costs those tests nothing --
    /// and the trie walk itself is reads through [`Memory`] and nothing else, so the tests that
    /// are about *that* run under Miri unshimmed. The tests that are about this call say so and
    /// are ignored there.
    fn on_host(unit: u16) -> u16 {
        match cfg!(miri) {
            true => unit,
            false => unsafe { windows::Wdk::System::SystemServices::RtlUpcaseUnicodeChar(unit) },
        }
    }
}

/// What a directory holds, and how much of it could not be read.
///
/// **A count beside the objects rather than a marker among them.** An entry whose name is paged
/// out is an object that is there and cannot be presented under a name, so it is left out of
/// [`Self::objects`] -- and without this a listing short by one is indistinguishable from a
/// directory holding one fewer object, which is the reading this walk exists not to produce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    /// Everything the directory holds that could be read and named, in bucket order.
    pub objects: Vec<KernelObject>,
    /// Entries whose memory would not read -- a name paged out, which is the ordinary case on a
    /// live kernel and says nothing about the target beyond what was resident.
    pub unreadable: usize,
    /// Entries whose structure contradicts itself: a name longer than its own maximum, an
    /// optional-header distance shorter than the header it locates.
    ///
    /// **Counted apart from [`Self::unreadable`] because the two mean opposite things about the
    /// target.** One is a page that was out and will be back; the other is a directory entry that
    /// cannot have been written by the object manager, which on a directory anybody cares about
    /// is a finding rather than a wrinkle. A walk that reported "1 unreadable" for both would
    /// hand a reader the benign reading of the alarming case.
    pub malformed: usize,
    /// True when the walk was stopped before the directory ran out.
    ///
    /// **The list is then a prefix of the directory rather than the directory**, and the counts
    /// beside it describe only what was reached. Separate from them because it is not an entry
    /// this could not read -- it is entries it never looked at, and there is no saying how many.
    pub halted: bool,
}

impl Listing {
    /// Entries this **reached** and could not present, however they failed.
    ///
    /// **Not a completeness test**, and the distinction is why [`Self::is_complete`] exists
    /// beside it: a walk stopped by [`Namespace::halting`] never reaches the rest of the
    /// directory, so this returns zero for a listing that is missing an unknown number of
    /// entries. A caller branching on `skipped() == 0` would read that as the whole directory,
    /// which is the one reading these counts exist to prevent.
    pub fn skipped(&self) -> usize {
        self.unreadable + self.malformed
    }

    /// Whether this is the whole directory: every entry reached, and every one of them presented.
    ///
    /// What a caller should branch on before treating an absence as a fact. An empty list is
    /// "nothing is filed here" under this and nothing at all otherwise.
    pub fn is_complete(&self) -> bool {
        !self.halted && self.skipped() == 0
    }
}

/// One object, as much of it as the namespace says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelObject {
    /// The object **body** — what a handle resolves to, and what `!devobj` and friends take.
    pub address: u64,
    /// Its name in the directory that holds it, not a path.
    pub name: String,
    /// Whether [`Self::name`] **is** that name, or only shows it.
    ///
    /// A name is a counted run of UTF-16 units, which an unpaired surrogate makes legal as a name
    /// and illegal as text. Such a name is rendered with replacements so the object still lists,
    /// and this says the rendering is not an identity: [`Namespace::object_at`] will not resolve to
    /// an object whose name it cannot reproduce exactly, because two such names render alike and a
    /// caller would get whichever came first.
    pub exact_name: bool,
    /// The object type's name (`Device`, `SymbolicLink`, `Directory`), when the type table could
    /// be read. `None` is "this walk could not say", never "untyped".
    pub type_name: Option<String>,
    /// `_OBJECT_HEADER::SecurityDescriptor`, with the fast-reference count masked out of it.
    /// `None` where the object carries none.
    pub security_descriptor: Option<u64>,
}

/// Where the fields this walk reads live, taken from the **target's own type information**.
///
/// Not one literal offset, and that is the point: `_OBJECT_HEADER` has moved between Windows
/// versions and `_OBJECT_DIRECTORY`'s bucket count is a build's choice. A table of constants here
/// would decode a different build confidently and wrongly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    /// A pointer's width on this target, **derived** from the distance between the two pointer
    /// fields of a directory entry rather than assumed from the host.
    pub pointer: usize,
    /// How many hash buckets a directory has, derived the same way: the span from the array to the
    /// field after it, over a pointer.
    pub buckets: usize,
    /// `_OBJECT_DIRECTORY::HashBuckets`.
    pub hash_buckets: u32,
    /// `_OBJECT_DIRECTORY_ENTRY::ChainLink` and `::Object`.
    pub entry_chain: u32,
    pub entry_object: u32,
    /// `_OBJECT_HEADER::Body`, which is how far *back* a body's header is.
    pub header_body: u32,
    pub header_type_index: u32,
    pub header_info_mask: u32,
    pub header_security: u32,
    /// `_OBJECT_HEADER_NAME_INFO::Name`, and the structure's size.
    pub name_info_name: u32,
    pub name_info_size: u32,
    /// `_UNICODE_STRING::Length` and `::Buffer`.
    pub unicode_length: u32,
    pub unicode_buffer: u32,
    /// `_OBJECT_SYMBOLIC_LINK::LinkTarget`, and the `Flags` that say whether it is live.
    pub link_target: u32,
    pub link_flags: u32,
    /// `_OBJECT_TYPE::Name`.
    pub type_name: u32,
}

impl Layout {
    /// Whether this describes a target's structures, or merely has the right field names.
    ///
    /// Two kinds of check, and the second is the one worth naming. A **width** and a **count** are
    /// what the walk sizes reads and loops from, so a wrong one panics or runs away. An **offset**
    /// into a structure the walk reads whole has to be inside what it reads, or the read succeeds
    /// and the field is taken from past its end. Offsets that are only added to an address are not
    /// checked: a wrong one reads somewhere else, which comes back as [`ObjectError::Unreadable`]
    /// naming the address, and there is nothing this could compare it against anyway.
    fn check(&self) -> Result<(), ObjectError> {
        let bad = |reason| Err(ObjectError::Malformed { reason });
        if !matches!(self.pointer, 4 | 8) {
            return bad("a pointer on this target is neither four bytes nor eight");
        }
        if self.buckets == 0 || self.buckets > MAX_BUCKETS {
            return bad("a directory's bucket count is not one a directory has");
        }
        // **Every offset is small before any of them is added to another.** These describe
        // structures of tens of bytes, so anything near a `u32`'s range is not one of them -- and
        // checking that first is what stops a sum overflowing on a 32-bit host and what stops a
        // read being asked for in gigabytes.
        let fields = [
            self.hash_buckets,
            self.entry_chain,
            self.entry_object,
            self.header_body,
            self.header_type_index,
            self.header_info_mask,
            self.header_security,
            self.name_info_name,
            self.name_info_size,
            self.unicode_length,
            self.unicode_buffer,
            self.link_target,
            self.link_flags,
            self.type_name,
        ];
        if fields.iter().any(|offset| *offset as usize > MAX_STRUCTURE) {
            return bad("a field sits further into its structure than any of these reach");
        }
        // A `UNICODE_STRING` is read whole: its two lengths, then its buffer.
        let unicode = (self.unicode_buffer as usize) + self.pointer;
        if (self.unicode_length as usize) + 4 > unicode {
            return bad("a UNICODE_STRING's lengths sit outside the structure");
        }
        // And the name header is read as far as the string inside it.
        if (self.name_info_name as usize) + unicode > self.name_info_size as usize {
            return bad("a name header's string sits outside the name header");
        }
        Ok(())
    }
}

/// The globals the walk starts from, resolved by symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Globals {
    /// `nt!ObpRootDirectoryObject` — a pointer to the root directory, not the directory.
    pub root: Option<u64>,
    /// `nt!ObpInfoMaskToOffset` — a byte per `InfoMask` combination, saying how far before the
    /// header the optional headers sit.
    pub info_mask_to_offset: Option<u64>,
    /// `nt!ObHeaderCookie` and `nt!ObTypeIndexTable`, which together turn a header's obfuscated
    /// `TypeIndex` into a type object. Optional: a build without them still resolves names, and a
    /// `type_name` of `None` is the honest answer there.
    pub header_cookie: Option<u64>,
    pub type_index_table: Option<u64>,
    /// Where this target keeps the upcase table, for folding names the way it folds them.
    ///
    /// **Optional, and its absence is a degraded answer rather than a refused one.** Every other
    /// global here is a thing the walk reads *or does not run*; this one has a fallback, because
    /// [`Upcase`] can still fold on the host. A target that resolves no `nt!PspHostSiloGlobals`
    /// therefore walks its namespace exactly as it did before this field existed -- see
    /// [`UpcaseFrom::Host`] for what that is worth and what it is not.
    ///
    /// **It is here rather than in [`Layout`], although two of its three coordinates come from
    /// type information.** What decides that is not where the numbers come from but what an
    /// absence means: a `Layout` this cannot resolve stops the walk, every field in it being one
    /// the walk reads, whereas this structure going missing costs only the target's own table.
    /// Putting it there would let one missing type on an unusual build refuse a walk that has
    /// nothing to do with folding.
    pub upcase: Option<UpcaseTable>,
}

/// Which optional header is wanted, as the bit the kernel's own lookup is keyed on.
const INFO_MASK_NAME: u8 = 0x02;

/// Reads a walk's worth of target memory. A trait so the walk is testable against bytes, which is
/// the only way to test it at all: the namespace it walks lives in a running kernel.
pub trait Memory {
    /// Answers `None` for anything that would not read, at any length.
    fn read(&self, address: u64, len: usize) -> Option<Vec<u8>>;
}

impl<F> Memory for F
where
    F: Fn(u64, usize) -> Option<Vec<u8>>,
{
    fn read(&self, address: u64, len: usize) -> Option<Vec<u8>> {
        self(address, len)
    }
}

/// The namespace, over some memory and a layout.
pub struct Namespace<'a> {
    memory: &'a dyn Memory,
    layout: Layout,
    globals: Globals,
    halt: Option<&'a dyn Fn() -> bool>,
    upcase: Upcase<'a>,
}

impl<'a> Namespace<'a> {
    /// A walk over some memory, once the layout has been checked.
    ///
    /// **The check is here and not in each read**, which is the third answer this seam has had and
    /// the one that ends it. [`Layout`] is public, so its fields are a caller's to fill in, and
    /// every one of them is either an index into bytes this walk read or a count it loops on -- a
    /// width of two had two bytes read and eight taken, a field past the end of its structure was
    /// the same fault by another route, a bucket count of zero made an empty directory out of a
    /// full one, and `usize::MAX` overflowed the size arithmetic before any of the guards those
    /// produced could run. Defending each read found one more of these every round. Checking the
    /// layout once means the walk below can rely on it, and there is no next one.
    pub fn new(
        memory: &'a dyn Memory,
        layout: Layout,
        globals: Globals,
    ) -> Result<Self, ObjectError> {
        layout.check()?;
        // **Built here and not read here.** `Upcase` resolves the table on the first code unit
        // that needs one, which for a namespace of ASCII names is never -- and `link_target` folds
        // nothing at all, so a walk that only follows a symbolic link makes no NLS read whatever
        // this target resolved. That is the same rule `needs` states for the other globals: an
        // operation pays for what it reads.
        let upcase = match globals.upcase {
            Some(table) => Upcase::of_target(memory, table, layout.pointer),
            None => Upcase::of_host(),
        };
        Ok(Self {
            memory,
            layout,
            globals,
            halt: None,
            upcase,
        })
    }

    /// The fold this walk compares names with -- **the target's own table** where it resolved one.
    ///
    /// Exposed because a caller comparing a name this walk *returned* against one of its own is
    /// asking the same question the walk asks, and answering it with [`same_object_name`] would
    /// answer it on a different machine's table. A link target measured against a device's path is
    /// the case this exists for.
    pub fn upcase(&self) -> &Upcase<'a> {
        &self.upcase
    }

    /// The same walk, stoppable.
    ///
    /// **A directory is an unbounded amount of work behind one call**, which is the whole reason
    /// this exists: `\GLOBAL??` on an ordinary Windows guest holds a couple of hundred entries and
    /// each costs several reads of target memory, so over a kernel debugging wire the enumeration
    /// alone can outlast a caller's patience. Without this the caller's only bound is a timeout on
    /// *waiting*, which abandons the waiter and not the walk -- so the work carries on holding the
    /// session it runs on, which is the one thing a deadline is supposed to prevent.
    ///
    /// `halt` is polled per directory entry and per link of a bucket's chain, which is where the
    /// reads are. What it stops is reported rather than raised wherever there is a partial answer
    /// to give: [`Listing::halted`] on an enumeration, and [`ObjectError::Halted`] on a lookup,
    /// which has no partial answer.
    #[must_use]
    pub fn halting(mut self, halt: &'a dyn Fn() -> bool) -> Self {
        self.halt = Some(halt);
        self
    }

    /// Whether the caller has asked this to stop.
    fn stopped(&self) -> bool {
        self.halt.is_some_and(|halt| halt())
    }

    /// One global this operation cannot do without.
    ///
    /// **Asked for where it is used rather than where the set is built**, because the operations
    /// here need different subsets and a walk that resolved the union of them would take reading a
    /// symbolic link away from a target that merely renamed the root pointer. The layout is not
    /// treated this way and deliberately: every type in it comes out of one PDB, so a partial
    /// answer there is not a thing a real target produces.
    fn needs(&self, global: Option<u64>, what: &'static str) -> Result<u64, ObjectError> {
        global.ok_or(ObjectError::Unavailable { what })
    }

    fn read(&self, at: u64, len: usize) -> Result<Vec<u8>, ObjectError> {
        match self.memory.read(at, len) {
            Some(bytes) if bytes.len() >= len => Ok(bytes),
            _ => Err(ObjectError::Unreadable { at, len }),
        }
    }

    /// A pointer, at whichever of the two widths this target uses.
    ///
    /// **Any other width is refused rather than treated as eight.** [`Layout`] is public and its
    /// fields are a caller's to fill in, so a width of two would have this read two bytes and then
    /// take eight of them — a panic, inside calls whose whole contract is that they return an
    /// error. Nothing here trusts a layout to be one this crate built.
    fn pointer_at(&self, at: u64) -> Result<u64, ObjectError> {
        let bytes = self.read(at, self.layout.pointer)?;
        match self.layout.pointer {
            4 => Ok(u64::from(u32::from_le_bytes(
                bytes[..4].try_into().unwrap_or_default(),
            ))),
            8 => Ok(u64::from_le_bytes(
                bytes[..8].try_into().unwrap_or_default(),
            )),
            _ => Err(ObjectError::Malformed {
                reason: "a pointer on this target is neither four bytes nor eight",
            }),
        }
    }

    /// Two bytes out of a structure this walk read, at an offset a [`Layout`] gave it.
    ///
    /// Bounds-checked for the same reason as the widths above: the offsets are public fields, and
    /// one past the end of what was read is a panic where this owes an error.
    fn field_at(bytes: &[u8], offset: u32) -> Result<u16, ObjectError> {
        bytes
            .get(offset as usize..)
            .and_then(|rest| rest.first_chunk::<2>())
            .map(|pair| u16::from_le_bytes(*pair))
            .ok_or(ObjectError::Malformed {
                reason: "a field sits outside the structure this layout describes",
            })
    }

    /// The object body every entry of a directory points at.
    fn entries_of(&self, directory: u64) -> Result<(Vec<u64>, bool), ObjectError> {
        let mut out = Vec::new();
        let mut followed = 0usize;
        for bucket in 0..self.layout.buckets {
            // **Polled before the bucket is read, not only while a chain is followed.** An empty
            // bucket never enters the loop below, so a directory that is empty -- or merely has a
            // long run of empty buckets -- was unstoppable: `halting(&|| true)` still paid one
            // target read per bucket, up to the thousand a layout may declare, and answered
            // `halted: false` having done all of it.
            if self.stopped() {
                return Ok((out, true));
            }
            let at = directory
                .wrapping_add(u64::from(self.layout.hash_buckets))
                .wrapping_add((bucket * self.layout.pointer) as u64);
            let mut entry = self.pointer_at(at)?;
            // A chain is bounded by the whole directory's bound rather than one of its own: a
            // cycle inside a bucket and a cycle across buckets are the same corruption.
            //
            // **The bound counts links followed, not objects found.** Counting what came out of
            // the walk leaves a chain of entries whose `Object` is null unbounded -- one of them
            // pointing at itself is a loop this never leaves, which on a live kernel is a
            // debugger that stops answering rather than a walk that refuses.
            while entry != 0 {
                // Polled per link rather than per bucket: a chain is where a long directory's
                // work is, and a bound checked only between buckets leaves a thirty-entry chain
                // unstoppable.
                if self.stopped() {
                    return Ok((out, true));
                }
                followed += 1;
                if followed > MAX_ENTRIES {
                    return Err(ObjectError::TooMany {
                        what: "a directory's entries",
                        bound: MAX_ENTRIES,
                    });
                }
                let object =
                    self.pointer_at(entry.wrapping_add(u64::from(self.layout.entry_object)))?;
                if object != 0 {
                    out.push(object);
                }
                entry = self.pointer_at(entry.wrapping_add(u64::from(self.layout.entry_chain)))?;
            }
        }
        Ok((out, false))
    }

    /// The header that belongs to an object body.
    fn header_of(&self, body: u64) -> u64 {
        body.wrapping_sub(u64::from(self.layout.header_body))
    }

    /// One `_UNICODE_STRING`, read from wherever it sits.
    fn unicode_at(
        &self,
        at: u64,
        bound: usize,
        what: &'static str,
    ) -> Result<(String, bool), ObjectError> {
        let size = (self.layout.unicode_buffer as usize) + self.layout.pointer;
        let bytes = self.read(at, size)?;
        let length = Self::field_at(&bytes, self.layout.unicode_length)? as usize;
        // **A string that is longer than its own buffer is torn**, and reading `Length` alone
        // takes whatever follows into a name the walk then matches paths against -- which
        // resolves some other object, rather than failing to resolve this one.
        if length > Self::field_at(&bytes, self.layout.unicode_length + 2)? as usize {
            return Err(ObjectError::Malformed {
                reason: "a UNICODE_STRING is longer than its own maximum",
            });
        }
        let buffer = self.pointer_at(at.wrapping_add(u64::from(self.layout.unicode_buffer)))?;
        if length == 0 {
            return Ok((String::new(), true));
        }
        // **A length with no buffer is not an empty string**, it is a structure contradicting
        // itself -- and an empty string is what a caller would publish as a symbolic link's
        // target, which is worse than saying nothing.
        if buffer == 0 {
            return Err(ObjectError::Malformed {
                reason: "a UNICODE_STRING has a length and no buffer",
            });
        }
        if !length.is_multiple_of(2) {
            return Err(ObjectError::Malformed {
                reason: "a UNICODE_STRING's length is not a whole number of UTF-16 units",
            });
        }
        if length > bound {
            return Err(ObjectError::TooMany { what, bound });
        }
        let raw = self.read(buffer, length)?;
        Ok(utf16(&raw[..length]))
    }

    /// An object's own name, which lives in an optional header before its header.
    ///
    /// `Ok(None)` is an object filed under no name at all, which is ordinary — most objects are
    /// reached by handle and never named.
    fn name_of(&self, body: u64) -> Result<Option<(String, bool)>, ObjectError> {
        let header = self.header_of(body);
        let mask = self.read(
            header.wrapping_add(u64::from(self.layout.header_info_mask)),
            1,
        )?[0];
        if mask & INFO_MASK_NAME == 0 {
            return Ok(None);
        }
        // The kernel's own lookup: the offsets of every optional header present *up to and
        // including* the one wanted, which is what the bit and every bit below it select.
        let index = mask & (INFO_MASK_NAME | (INFO_MASK_NAME - 1));
        let distance = self.read(
            self.needs(self.globals.info_mask_to_offset, OFFSETS_SYMBOL)?
                .wrapping_add(u64::from(index)),
            1,
        )?[0];
        if u32::from(distance) < self.layout.name_info_size {
            return Err(ObjectError::Malformed {
                reason: "the name header's distance is shorter than the name header",
            });
        }
        let name_info = header.wrapping_sub(u64::from(distance));
        Ok(Some(self.unicode_at(
            name_info.wrapping_add(u64::from(self.layout.name_info_name)),
            MAX_NAME_BYTES,
            "an object name",
        )?))
    }

    /// The security descriptor an object carries, with the reference count cleared out of it.
    ///
    /// **The field is an `_EX_FAST_REF`, not a pointer**: the object manager keeps a count of
    /// outstanding fast references in the bits an aligned address leaves spare, and that is
    /// **four** bits on a 64-bit kernel — measured, `nt!_EX_FAST_REF::RefCnt` is `Pos 0, 4 Bits`
    /// on 26100 x64. Clearing three of them leaves the fourth set on any object with eight or more
    /// live references, and the address handed back is then eight bytes into the descriptor: what
    /// gets decoded is a DACL read from the middle of a header, which is a wrong answer about who
    /// may open a device rather than a failure to answer.
    ///
    /// So the mask is derived from the pointer width the layout already derived — the count fills
    /// what the descriptor's alignment leaves, which is one bit more than the pointer's own.
    fn security_of(&self, body: u64) -> Result<Option<u64>, ObjectError> {
        let at = self
            .header_of(body)
            .wrapping_add(u64::from(self.layout.header_security));
        let counted = (2 * self.layout.pointer as u64) - 1;
        let descriptor = self.pointer_at(at)? & !counted;
        Ok((descriptor != 0).then_some(descriptor))
    }

    /// The name of an object's type, when the type table can be read.
    ///
    /// The index in the header is obfuscated — exclusive-ored with a per-boot cookie and with a
    /// byte of the header's own address — so a build whose cookie this cannot find gets `None`
    /// rather than a type read out of the wrong table slot.
    fn type_of(&self, body: u64) -> Option<String> {
        let (cookie, table) = (self.globals.header_cookie?, self.globals.type_index_table?);
        let header = self.header_of(body);
        let raw = self
            .read(
                header.wrapping_add(u64::from(self.layout.header_type_index)),
                1,
            )
            .ok()?[0];
        let cookie = self.read(cookie, 1).ok()?[0];
        let index = raw ^ cookie ^ ((header >> 8) as u8);
        let entry = self
            .pointer_at(table.wrapping_add((usize::from(index) * self.layout.pointer) as u64))
            .ok()?;
        if entry == 0 {
            return None;
        }
        let (name, _) = self
            .unicode_at(
                entry.wrapping_add(u64::from(self.layout.type_name)),
                MAX_NAME_BYTES,
                "a type name",
            )
            .ok()?;
        (!name.is_empty()).then_some(name)
    }

    /// Everything one directory holds, named.
    fn named_in(&self, directory: u64) -> Result<Listing, ObjectError> {
        let mut objects = Vec::new();
        let mut unreadable = 0usize;
        let mut malformed = 0usize;
        let (bodies, mut halted) = self.entries_of(directory)?;
        for body in bodies {
            // **A halt this was already told about is not asked about again, because asking can
            // consume the answer.** `DebugEngine::interrupted` is `GetInterrupt`, which clears
            // the pending request on its first poll -- measured in this crate rather than
            // assumed, by `test_get_interrupt_drain_semantics`, whose asserted vector is
            // `[true, false, false, false, false]`. So a Ctrl+C caught while the buckets were
            // walked came back here as `halted`, this loop re-polled, the second answer was
            // false because the first poll had taken it, and every entry the walk had gathered
            // was named regardless: thousands of reads on a remote target after the stop, and
            // `object_at` returning a found object as though the lookup had finished, since it
            // consults `halted` only when the name is *not* in the listing.
            if halted {
                break;
            }
            // And again per entry, because naming one is several reads of its own -- the header,
            // the offset table, the name, the security field and the type.
            if self.stopped() {
                halted = true;
                break;
            }
            // **An entry this cannot read is skipped and counted, not propagated**, and that is
            // the difference between one paged-out name and a directory nobody can list.
            // Measured on a live Windows Server 26100 guest 2026-09-13: `\GLOBAL??` holds some
            // two hundred links and one whose `Name.Buffer` is paged out, which the debugger's
            // own `!object` prints as `(*** Name not accessible ***)` and walks past. Failing on
            // it took away the entire directory -- and, since `object_at` resolves each component
            // through here, every lookup whose path crossed that directory as well.
            //
            // **Only the two errors that are about the entry.** `Unavailable` says this *target*
            // does not resolve `nt!ObpInfoMaskToOffset`, which is equally true of every entry
            // there will ever be: skipping that would answer with an empty directory for a build
            // this walk cannot decode at all, which is the failure the whole module is against.
            let named = match self.name_of(body) {
                Ok(named) => named,
                Err(ObjectError::Unreadable { .. }) => {
                    unreadable += 1;
                    continue;
                }
                Err(ObjectError::Malformed { .. }) => {
                    malformed += 1;
                    continue;
                }
                Err(fatal) => return Err(fatal),
            };
            let Some((name, exact_name)) = named else {
                continue;
            };
            // The same treatment, for the same reason. This reads a field of the header
            // `name_of` has just read a byte of, so a target that answers one and not the other
            // is barely a real case -- and the last thing here that was barely a real case is
            // the paragraph above. An object dropped for it is counted like any other, rather
            // than listed with a `None` that would read as "carries no descriptor".
            let security_descriptor = match self.security_of(body) {
                Ok(found) => found,
                Err(ObjectError::Unreadable { .. }) => {
                    unreadable += 1;
                    continue;
                }
                Err(ObjectError::Malformed { .. }) => {
                    malformed += 1;
                    continue;
                }
                Err(fatal) => return Err(fatal),
            };
            objects.push(KernelObject {
                address: body,
                name,
                exact_name,
                type_name: self.type_of(body),
                security_descriptor,
            });
        }
        Ok(Listing {
            objects,
            unreadable,
            malformed,
            halted,
        })
    }

    /// Resolves a path to the object filed under it.
    pub fn object_at(&self, path: &str) -> Result<KernelObject, ObjectError> {
        let components = components_of(path)?;
        // The root is a directory rather than an object in one, so there is nothing here to
        // resolve. `objects_in` is the call that answers about it.
        if components.is_empty() {
            return Err(ObjectError::BadPath {
                path: path.to_string(),
                reason: "it names the root directory rather than an object in it",
            });
        }
        let mut directory = self.pointer_at(self.needs(self.globals.root, ROOT_SYMBOL)?)?;
        if directory == 0 {
            return Err(ObjectError::Malformed {
                reason: "the root directory pointer is null",
            });
        }
        let mut walked = String::from("\\");
        let last = components.len() - 1;
        for (at, component) in components.iter().enumerate() {
            let listing = self.named_in(directory)?;
            let skipped = (listing.unreadable, listing.malformed);
            // **A stop is the answer whatever the prefix happened to contain**, and this used to
            // be asked only when the component was *missing* -- so a walk stopped after naming it
            // handed it back, and for a path with another component behind it descended into that
            // directory with the interrupt already spent, doing the rest of the lookup's remote
            // reads after the Ctrl+C meant to end them. A name is not less found for the walk
            // having been stopped; it is that the caller asked for no more work, and the prefix a
            // one-shot predicate leaves behind is exactly where that reads as success.
            if listing.halted {
                return Err(ObjectError::Halted {
                    what: component.clone(),
                });
            }
            // **Absent, or absent from what could be read.** A directory with an entry this could
            // not name may hold the very object being asked for, so "not found" is a thing this is
            // only entitled to say when the directory read in full.
            //
            // A name that is not text is neither absent nor uncertain: it is rendered with
            // replacements, and a rendering cannot equal a component of a `&str` path -- an
            // unpaired surrogate is the only thing that makes `exact_name` false and no `&str`
            // contains one. Skipping those loses nothing this could have found, which is why they
            // are not a third count.
            let found = listing
                .objects
                .into_iter()
                .find(|object| object.exact_name && self.upcase.same_name(&object.name, component))
                .ok_or_else(|| match skipped {
                    (0, 0) => ObjectError::NotFound {
                        directory: walked.clone(),
                        component: component.clone(),
                    },
                    (unreadable, malformed) => ObjectError::NotFoundInPart {
                        directory: walked.clone(),
                        component: component.clone(),
                        unreadable,
                        malformed,
                    },
                })?;
            if at == last {
                return Ok(found);
            }
            // Anything with a directory under it has to *be* one, and the type is how that is
            // known. **Fail closed**: an object whose type could not be read is not one to walk
            // through on the chance that it is a directory, because what that reads is a device's
            // own fields as bucket pointers.
            match found.type_name.as_deref() {
                Some(DIRECTORY) => {}
                Some(_) => {
                    return Err(ObjectError::NotADirectory {
                        component: component.clone(),
                        rest: components[at + 1..].join("\\"),
                    });
                }
                None => {
                    return Err(ObjectError::Untyped {
                        component: component.clone(),
                    });
                }
            }
            directory = found.address;
            if walked.len() > 1 {
                walked.push('\\');
            }
            walked.push_str(component);
        }
        unreachable!("a path with no components is refused above")
    }

    /// Everything a directory holds.
    ///
    /// **A path that resolves to a leaf is refused rather than enumerated.** `object_at` guards
    /// walking *through* a device on the way to something else; this is the same guard at the end
    /// of the path, and without it `\Device\MountPointManager` has a driver's own fields read as
    /// thirty-seven bucket pointers and whatever they hold followed as chains.
    pub fn objects_in(&self, path: &str) -> Result<Listing, ObjectError> {
        // **The same parser `object_at` uses**, which is the point rather than a tidy-up: this
        // had its own, and the two disagreed twice -- an empty argument listed the root, and so
        // did a path of nothing but separators, both of which `object_at` refused. One question
        // with two answers depending on which door it came through.
        let directory = match components_of(path)?.is_empty() {
            true => self.pointer_at(self.needs(self.globals.root, ROOT_SYMBOL)?)?,
            false => {
                let found = self.object_at(path)?;
                match found.type_name.as_deref() {
                    Some(DIRECTORY) => {}
                    Some(_) => {
                        return Err(ObjectError::NotADirectory {
                            component: found.name,
                            rest: String::new(),
                        });
                    }
                    None => {
                        return Err(ObjectError::Untyped {
                            component: found.name,
                        });
                    }
                }
                found.address
            }
        };
        self.named_in(directory)
    }

    /// What a symbolic link points at.
    ///
    /// **`LinkTarget` shares its storage with a callback pointer**, and the type does not tell
    /// the two apart: a callback-backed link is a `SymbolicLink` like any other. `Callback` lands
    /// exactly on `Length` and `MaximumLength`, `CallbackContext` lands on `Buffer`, so decoding
    /// without looking reads a name out of whatever a context pointer happens to address.
    ///
    /// What remains after the flag is **structural** and nothing more: a whole number of UTF-16
    /// units, within its own maximum, addressing a buffer that reads. A target is deliberately not
    /// held to looking like an object path, and the shape of that mistake is worth recording --
    /// this did require one to begin with a backslash, which refuses `\\KnownDlls\\KnownDllPath`,
    /// whose target is the DOS path `C:\\Windows\\System32`. The kernel does test a leading
    /// backslash two blocks earlier in that routine, and it is testing the **remaining name** being
    /// parsed rather than the target; reading one as the other is how a real link came to be
    /// refused.
    ///
    /// **And the discriminator is read first**, because the checks above are evidence and the flag
    /// is the answer: [`SYMBOLIC_LINK_CALLBACK`] is the bit the object manager itself branches on,
    /// taken out of `nt!ObpParseSymbolicLinkEx` rather than out of a document. A link whose
    /// callback arm is live has no target to read, and saying so is not the same as failing to
    /// decode one.
    pub fn link_target(&self, link: u64) -> Result<String, ObjectError> {
        let flags = self.read(
            link.wrapping_add(u64::from(self.layout.link_flags)),
            size_of::<u32>(),
        )?;
        let flags = u32::from_le_bytes(flags[..4].try_into().unwrap_or_default());
        if flags & SYMBOLIC_LINK_CALLBACK != 0 {
            return Err(ObjectError::Malformed {
                reason: "this link resolves through a callback, so it has no target to read",
            });
        }
        let at = link.wrapping_add(u64::from(self.layout.link_target));
        let size = (self.layout.unicode_buffer as usize) + self.layout.pointer;
        let bytes = self.read(at, size)?;
        let length = Self::field_at(&bytes, self.layout.unicode_length)?;
        let maximum = Self::field_at(&bytes, self.layout.unicode_length + 2)?;
        if length == 0 || !length.is_multiple_of(2) || length > maximum {
            return Err(ObjectError::Malformed {
                reason: "the link target is not a string this can vouch for",
            });
        }
        let (target, exact) = self.unicode_at(at, MAX_TARGET_BYTES, "a link target")?;
        if !exact {
            return Err(ObjectError::Malformed {
                reason: "the link target is not text, so it is not a path to follow",
            });
        }
        Ok(target)
    }
}

/// Splits an object path into the components a walk descends through.
fn components_of(path: &str) -> Result<Vec<String>, ObjectError> {
    let bad = |reason| ObjectError::BadPath {
        path: path.to_string(),
        reason,
    };
    if !path.starts_with('\\') {
        return Err(bad("an object path begins at the root, with a backslash"));
    }
    // The root, which is the one path with no components in it.
    if path == "\\" {
        return Ok(Vec::new());
    }
    // One trailing separator is a caller's convenience and is dropped. **An empty component
    // anywhere else is refused rather than dropped**, which is where the leniency here used to
    // be: filtering them turned `\\Device\\\\X` into `\\Device\\X` and `\\\\` into the root, so a path
    // that is not one quietly became a path that is -- and a listing answered about a directory
    // nobody named.
    let body = path.strip_suffix('\\').unwrap_or(path);
    let parts: Vec<String> = body[1..].split('\\').map(str::to_string).collect();
    if parts.iter().any(String::is_empty) {
        return Err(bad("it has a component with no name in it"));
    }
    if parts.len() > MAX_COMPONENTS {
        return Err(bad("it has more components than the namespace is deep"));
    }
    Ok(parts)
}

/// UTF-16 little-endian, and whether what came back **is** the name or only shows it.
///
/// A name the object manager holds is a counted run of UTF-16 units, which is not the same thing
/// as text: an unpaired surrogate is a legal name and not a legal `String`. Replacing one keeps the
/// object listable, and the flag is what stops that rendering being used as an identity -- two
/// different names with a lone surrogate each render alike, so a walk matching on the rendering
/// resolves whichever came first, and a caller asking for the replacement character resolves an
/// object whose name has no such character in it. For a security question that is a device
/// answering under a name that is not its own.
fn utf16(bytes: &[u8]) -> (String, bool) {
    let (pairs, _) = bytes.as_chunks::<2>();
    let units: Vec<u16> = pairs.iter().copied().map(u16::from_le_bytes).collect();
    match String::from_utf16(&units) {
        Ok(exact) => (exact, true),
        Err(_) => (String::from_utf16_lossy(&units), false),
    }
}

impl DebugEngine {
    /// Where the object namespace's structures are on **this** target.
    ///
    /// Read once per call rather than cached: the walk that follows makes tens of memory reads, so
    /// a dozen type lookups beside them are not what costs, and a cache keyed on the wrong thing
    /// is how a second build gets decoded with the first one's offsets.
    pub fn object_layout(&self) -> Result<Layout, DbgEngError> {
        // Every type below is the kernel's, so the module is the kernel's base -- asked of the
        // engine rather than inferred from a symbol's address, which is inside a section and not
        // the base a type lookup is scoped by.
        let module = self.kernel_base()?;
        let of = |type_name: &str, field: &str| -> Result<u32, DbgEngError> {
            let id = self.type_id(module, type_name)?;
            self.field_offset(module, id, field)
        };

        let entry_chain = of("_OBJECT_DIRECTORY_ENTRY", "ChainLink")?;
        let entry_object = of("_OBJECT_DIRECTORY_ENTRY", "Object")?;
        // **A pointer's width is the target's, and it is derived rather than assumed.** These two
        // fields are adjacent and the first is one pointer, so their distance is that width -- on
        // a 32-bit kernel read from a 64-bit host, which is a supported target, the host's answer
        // would be wrong by a factor of two and every read after it off the end of something.
        let pointer = entry_object
            .checked_sub(entry_chain)
            .filter(|width| matches!(width, 4 | 8))
            .ok_or(DbgEngError::InvalidCommand)? as usize;

        let hash_buckets = of("_OBJECT_DIRECTORY", "HashBuckets")?;
        // And the bucket count is the array's span over that width, for the same reason: 37 is
        // this build's number rather than the structure's.
        let buckets = (of("_OBJECT_DIRECTORY", "Lock")?.saturating_sub(hash_buckets) as usize)
            .checked_div(pointer)
            .filter(|count| *count > 0)
            .ok_or(DbgEngError::InvalidCommand)?;

        let name_info = self.type_id(module, "_OBJECT_HEADER_NAME_INFO")?;
        Ok(Layout {
            pointer,
            buckets,
            hash_buckets,
            entry_chain,
            entry_object,
            header_body: of("_OBJECT_HEADER", "Body")?,
            header_type_index: of("_OBJECT_HEADER", "TypeIndex")?,
            header_info_mask: of("_OBJECT_HEADER", "InfoMask")?,
            header_security: of("_OBJECT_HEADER", "SecurityDescriptor")?,
            name_info_name: self.field_offset(module, name_info, "Name")?,
            name_info_size: self.type_size(module, name_info)?,
            unicode_length: of("_UNICODE_STRING", "Length")?,
            unicode_buffer: of("_UNICODE_STRING", "Buffer")?,
            link_target: of("_OBJECT_SYMBOLIC_LINK", "LinkTarget")?,
            link_flags: of("_OBJECT_SYMBOLIC_LINK", "Flags")?,
            type_name: of("_OBJECT_TYPE", "Name")?,
        })
    }

    /// The globals the walk starts from.
    ///
    /// The two the walk cannot do without are errors; the two that only name a *type* are options,
    /// because a build that renamed or inlined them still resolves paths.
    pub fn object_globals(&self) -> Result<Globals, DbgEngError> {
        Ok(Globals {
            root: self.symbol_offset("nt!ObpRootDirectoryObject").ok(),
            info_mask_to_offset: self.symbol_offset("nt!ObpInfoMaskToOffset").ok(),
            header_cookie: self.symbol_offset("nt!ObHeaderCookie").ok(),
            type_index_table: self.symbol_offset("nt!ObTypeIndexTable").ok(),
            upcase: self.object_upcase_table(),
        })
    }

    /// Where this target keeps the upcase table, if it says.
    ///
    /// **Three lookups that have to agree, and any one of them failing gives up the whole thing**
    /// rather than half of it: a silo-globals address with no offset to add is not a table, and an
    /// offset with no base is not either. There is a good answer for giving up -- [`Upcase`] folds
    /// on the host instead -- so this returns [`None`] where [`Self::object_layout`] would raise.
    ///
    /// Not an error for the same reason it is not in [`Layout`]: `_ESERVERSILO_GLOBALS` is not a
    /// type every target carries type information for, and refusing to walk a namespace over an
    /// absent NLS coordinate would take a whole capability away to protect a fold that has a
    /// fallback.
    fn object_upcase_table(&self) -> Option<UpcaseTable> {
        let module = self.kernel_base().ok()?;
        let of = |type_name: &str, field: &str| -> Option<u32> {
            let id = self.type_id(module, type_name).ok()?;
            self.field_offset(module, id, field).ok()
        };
        Some(UpcaseTable {
            silo_globals: self.symbol_offset("nt!PspHostSiloGlobals").ok()?,
            nls_state: of("_ESERVERSILO_GLOBALS", "RtlNlsState")?,
            upcase_table: of("_RTL_NLS_STATE", "UnicodeUpcaseTable844")?,
        })
    }

    /// The object filed under a path, as `!object` would find it.
    pub fn object_at(&self, path: &str) -> Result<KernelObject, ObjectError> {
        self.with_namespace(|namespace| namespace.object_at(path))
    }

    /// Everything a directory holds.
    pub fn objects_in(&self, path: &str) -> Result<Listing, ObjectError> {
        self.with_namespace(|namespace| namespace.objects_in(path))
    }

    /// What a symbolic link object points at.
    pub fn symbolic_link_target(&self, link: u64) -> Result<String, ObjectError> {
        self.with_namespace(|namespace| namespace.link_target(link))
    }

    fn with_namespace<T>(
        &self,
        answer: impl FnOnce(&Namespace<'_>) -> Result<T, ObjectError>,
    ) -> Result<T, ObjectError> {
        // A layout or a global this cannot resolve is reported as the read it would have been:
        // both mean the same thing to a caller — this target does not carry a namespace to walk —
        // and the symbol that failed is in the engine's own error rather than lost here.
        let layout = self.object_layout().map_err(|_| ObjectError::Malformed {
            reason: "this target has no type information for the object manager's structures",
        })?;
        let globals = self.object_globals().map_err(|_| ObjectError::Malformed {
            reason: "this target does not resolve the object manager's globals",
        })?;
        let read = |at: u64, len: usize| self.read_memory(at, len).ok();
        answer(&Namespace::new(&read, layout, globals)?)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    /// The offsets measured on Windows 26100 x64, which is what the fixtures below are laid out to.
    ///
    /// Written out rather than derived from the builder that places the bytes: a fixture sharing
    /// its arithmetic with the code under test agrees with it about a wrong offset, which is the
    /// one thing a layout test cannot afford.
    fn layout() -> Layout {
        Layout {
            pointer: 8,
            buckets: 37,
            hash_buckets: 0x00,
            entry_chain: 0x00,
            entry_object: 0x08,
            header_body: 0x30,
            header_type_index: 0x18,
            header_info_mask: 0x1a,
            header_security: 0x28,
            name_info_name: 0x08,
            name_info_size: 0x20,
            unicode_length: 0x00,
            unicode_buffer: 0x08,
            link_target: 0x08,
            link_flags: 0x1c,
            type_name: 0x10,
        }
    }

    const ROOT_POINTER: u64 = 0xffff_f800_0000_1000;
    const INFO_OFFSETS: u64 = 0xffff_f800_0000_2000;
    const COOKIE: u64 = 0xffff_f800_0000_3000;
    const TYPE_TABLE: u64 = 0xffff_f800_0000_4000;
    /// The cookie this fixture's kernel booted with.
    const COOKIE_VALUE: u8 = 0x5a;

    fn globals() -> Globals {
        Globals {
            root: Some(ROOT_POINTER),
            info_mask_to_offset: Some(INFO_OFFSETS),
            header_cookie: Some(COOKIE),
            type_index_table: Some(TYPE_TABLE),
            // **No NLS coordinate, so these walk on the host's fold.** Every name in this module's
            // fixtures is ASCII, which both tables answer identically and neither is read for, so
            // the walk's own tests stay about the walk. The tests that are about the fold build a
            // target table of their own, and one of them uses a table that *disagrees* with this
            // host on purpose -- because a fixture where the two agree cannot tell which one
            // answered.
            upcase: None,
        }
    }

    /// A byte-addressed target, which is all the walk needs to be a walk.
    #[derive(Default)]
    struct Fake {
        bytes: BTreeMap<u64, u8>,
    }

    impl Memory for Fake {
        fn read(&self, address: u64, len: usize) -> Option<Vec<u8>> {
            (0..len)
                .map(|step| self.bytes.get(&(address + step as u64)).copied())
                .collect()
        }
    }

    impl Fake {
        fn put(&mut self, at: u64, bytes: &[u8]) {
            for (step, byte) in bytes.iter().enumerate() {
                self.bytes.insert(at + step as u64, *byte);
            }
        }

        fn pointer(&mut self, at: u64, value: u64) {
            self.put(at, &value.to_le_bytes());
        }

        /// A `_UNICODE_STRING` at `at`, with its characters at `buffer`.
        fn string(&mut self, at: u64, buffer: u64, text: &str) {
            let units: Vec<u8> = text
                .encode_utf16()
                .flat_map(|unit| unit.to_le_bytes())
                .collect();
            let length = units.len() as u16;
            // The whole structure, padding included: the walk reads it in one go, and a fixture
            // that writes only the fields it cares about leaves a hole that reads as unmapped.
            self.put(at, &[0u8; 16]);
            self.put(at, &length.to_le_bytes());
            self.put(at + 2, &length.to_le_bytes());
            self.pointer(at + 8, buffer);
            self.put(buffer, &units);
        }

        /// An object body with a header, a name, a type and a descriptor.
        #[allow(clippy::too_many_arguments)]
        fn object(&mut self, body: u64, name: &str, type_index: u8, security: u64) {
            let header = body - 0x30;
            // Name info sits `distance` before the header, and the table says how far.
            self.put(header + 0x18, &[type_index]);
            self.put(header + 0x1a, &[0x02]);
            self.pointer(header + 0x28, security);
            self.put(INFO_OFFSETS + u64::from(0x02u8 & 0x03), &[0x20]);
            let name_info = header - 0x20;
            self.string(name_info + 0x08, name_info + 0x1000, name);
        }

        /// A directory holding these objects, one per bucket so the chains stay short.
        fn directory(&mut self, at: u64, objects: &[u64]) {
            for bucket in 0..37u64 {
                self.pointer(at + bucket * 8, 0);
            }
            for (index, object) in objects.iter().enumerate() {
                let entry = at + 0x2000 + (index as u64) * 0x20;
                let bucket = (index as u64) % 37;
                // Push onto the front of the bucket's chain.
                let was =
                    u64::from_le_bytes(self.read(at + bucket * 8, 8).unwrap().try_into().unwrap());
                self.pointer(entry, was);
                self.pointer(entry + 0x08, *object);
                self.pointer(at + bucket * 8, entry);
            }
        }

        /// An object whose name is written as raw UTF-16 units rather than as text, which is
        /// what the object manager actually holds.
        fn units_named(&mut self, body: u64, units: &[u16], type_index: u8) {
            let header = body - 0x30;
            self.put(header + 0x18, &[type_index]);
            self.put(header + 0x1a, &[0x02]);
            self.pointer(header + 0x28, 0);
            self.put(INFO_OFFSETS + u64::from(0x02u8 & 0x03), &[0x20]);
            let name_info = header - 0x20;
            let bytes: Vec<u8> = units.iter().flat_map(|unit| unit.to_le_bytes()).collect();
            let length = bytes.len() as u16;
            self.put(name_info + 0x08, &[0u8; 16]);
            self.put(name_info + 0x08, &length.to_le_bytes());
            self.put(name_info + 0x0a, &length.to_le_bytes());
            self.pointer(name_info + 0x10, name_info + 0x1000);
            self.put(name_info + 0x1000, &bytes);
        }

        /// The flags a symbolic link carries, which say which arm of its union is live.
        fn flags(&mut self, link: u64, flags: u32) {
            self.put(link + 0x1c, &flags.to_le_bytes());
        }

        /// A type object whose index the header will be obfuscated against.
        fn kind(&mut self, index: u8, at: u64, name: &str) {
            self.pointer(TYPE_TABLE + u64::from(index) * 8, at);
            self.string(at + 0x10, at + 0x1000, name);
        }
    }

    /// The index a header must carry for its object to read as `kind`.
    fn obfuscated(kind: u8, body: u64) -> u8 {
        let header = body - 0x30;
        kind ^ COOKIE_VALUE ^ ((header >> 8) as u8)
    }

    const ROOT: u64 = 0xffff_a000_0000_0000;
    const DEVICE_DIR: u64 = 0xffff_a000_0010_0000;
    const DEVICE: u64 = 0xffff_a000_0020_0000;

    fn namespace() -> Fake {
        let mut fake = Fake::default();
        fake.put(COOKIE, &[COOKIE_VALUE]);
        fake.pointer(ROOT_POINTER, ROOT);
        fake.kind(3, 0xffff_a000_0030_0000, "Directory");
        fake.kind(4, 0xffff_a000_0031_0000, "Device");
        fake.kind(5, 0xffff_a000_0032_0000, "SymbolicLink");

        fake.object(DEVICE_DIR, "Device", obfuscated(3, DEVICE_DIR), 0);
        fake.directory(ROOT, &[DEVICE_DIR]);

        fake.object(
            DEVICE,
            "MountPointManager",
            obfuscated(4, DEVICE),
            0xffff_b000_0000_000f,
        );
        fake.directory(DEVICE_DIR, &[DEVICE]);
        fake
    }

    /// A path resolves to the object filed under it, with its type and its descriptor.
    ///
    /// The descriptor is stored with the object manager's own flag bits set, which is how a real
    /// one is stored: taking the field as an address reads a security descriptor three bytes into
    /// its own header and reports a DACL that is not there.
    #[test]
    fn a_path_resolves_to_the_object_filed_under_it() {
        let fake = namespace();
        let namespace = Namespace::new(&fake, layout(), globals())
            .expect("the fixture layout is one this crate builds");

        let found = namespace
            .object_at("\\Device\\MountPointManager")
            .expect("the device is in the namespace");
        assert_eq!(
            (
                found.address,
                found.name.as_str(),
                found.type_name.as_deref(),
                found.security_descriptor
            ),
            (
                DEVICE,
                "MountPointManager",
                Some("Device"),
                Some(0xffff_b000_0000_0000)
            ),
            "the descriptor field is a fast reference, and the count in its low bits is not \
             part of the address"
        );
    }

    /// A name is matched without regard to ASCII case, as the object manager matches it.
    #[test]
    fn a_name_is_matched_without_regard_to_case() {
        let fake = namespace();
        let namespace = Namespace::new(&fake, layout(), globals())
            .expect("the fixture layout is one this crate builds");
        assert_eq!(
            namespace
                .object_at("\\device\\MOUNTPOINTMANAGER")
                .map(|found| found.address),
            Ok(DEVICE)
        );
    }

    /// **The fold is the object manager's, and it is performed rather than reproduced.**
    ///
    /// Every expectation here was read off a **live 26100 kernel's own**
    /// `RtlNlsState.UnicodeUpcaseTable844`, dumped over KD and walked as an 8-4-4 trie, and the
    /// host's `RtlUpcaseUnicodeChar` agreed with it on all 65,536 code units. So these are the
    /// object manager's answers, not Unicode's -- which is the distinction the whole function
    /// turns on, and the four below are where the two part company.
    #[cfg_attr(miri, ignore = "folds through ntdll; see `Upcase::on_host`")]
    #[test]
    fn a_name_is_folded_by_the_object_managers_own_table_and_not_by_unicodes() {
        // The two bands that read no table, which this crate still answers itself.
        assert!(same_object_name("MountPointManager", "MOUNTPOINTMANAGER"));
        // `U+00B5` is below the `U+00C0` floor, so no table is consulted and it stays put --
        // where Unicode would fold it to a Greek capital mu, changing its script on the way.
        assert!(!same_object_name("\u{00b5}", "\u{039c}"));

        // The band the old `eq_ignore_ascii_case` got wrong: one object to the table, two to
        // twenty-six letters of ASCII.
        assert!(same_object_name("K\u{e4}se", "K\u{c4}SE"));

        // **The 224 the reproduction was confidently wrong about**, of which this is the
        // cleanest. `U+0131`'s Unicode simple uppercase is `I`; the system's table leaves it
        // alone, because folding it would break Turkish round-tripping. Two objects.
        assert!(
            !same_object_name("\u{0131}", "I"),
            "dotless i is not I here"
        );
        assert!(!same_object_name("\u{017f}", "S"), "long s is not S here");
        assert!(
            !same_object_name("\u{01c5}", "\u{01c4}"),
            "a titlecase digraph is not its uppercase here"
        );

        // **The 102 it had no answer for at all**, because Rust exposes only the full mapping.
        // The table has a one-unit answer for both of these, and they are opposite answers --
        // which is exactly why declining was the only honest thing to do without it.
        assert!(
            same_object_name("\u{1f80}", "\u{1f88}"),
            "the table maps U+1F80 to U+1F88, one unit"
        );
        assert!(
            !same_object_name("\u{00df}", "SS"),
            "and leaves U+00DF alone, so it is not SS"
        );

        // Context and expansion, the two ways `to_lowercase` was wrong in opposite directions.
        // Both still hold, now for the table's reasons rather than for Unicode's.
        assert!(
            same_object_name("\u{0391}\u{03A3}", "\u{0391}\u{03C3}"),
            "one object spelt with either sigma is still one object"
        );
        assert!(
            !same_object_name("\u{0130}", "i\u{0307}"),
            "a fold that expands would make one object out of two"
        );

        // A surrogate pair is not a letter to a per-`WCHAR` fold, and the table moves no unit in
        // `D800..DFFF` -- measured across the range.
        assert!(!same_object_name("\u{10400}", "\u{10428}"));
    }

    /// Where a fixture's silo globals sit, and the two offsets that reach the table pointer from
    /// them. The offsets are 26100 x64's, read off `dt nt!_ESERVERSILO_GLOBALS` and
    /// `dt nt!_RTL_NLS_STATE` -- written out rather than taken from the resolver, because a
    /// fixture that asks the code under test where a field is agrees with it about a wrong answer.
    const SILO_GLOBALS: u64 = 0xffff_f800_0005_0000;
    const NLS_STATE: u32 = 0x408;
    const UPCASE_TABLE: u32 = 0xa8;
    /// Where these fixtures lay the table itself out.
    const TABLE: u64 = 0xffff_f800_0006_0000;

    fn upcase_globals() -> UpcaseTable {
        UpcaseTable {
            silo_globals: SILO_GLOBALS,
            nls_state: NLS_STATE,
            upcase_table: UPCASE_TABLE,
        }
    }

    impl Fake {
        /// The table pointer, at the distance the two offsets put it.
        fn nls_pointer(&mut self, table: u64) {
            self.pointer(
                SILO_GLOBALS + u64::from(NLS_STATE) + u64::from(UPCASE_TABLE),
                table,
            );
        }

        /// A `u16` element of a table at `base`, addressed the way the routine addresses one: an
        /// index of **elements from the base**, scaled by two.
        fn element(&mut self, base: u64, index: u32, value: u16) {
            self.put(base + u64::from(index) * 2, &value.to_le_bytes());
        }
    }

    /// An 8-4-4 trie that folds exactly one code unit, laid out by hand.
    ///
    /// **Every index here is a literal**, which is the point of it: the walk's whole contract is
    /// that a level's value is an element index from the *base* rather than a byte offset or a
    /// level-relative one, and a fixture that computed its indices the way [`Upcase::from_table`]
    /// computes them could not tell those three apart. The layout is
    ///
    /// ```text
    ///   0x000..0x0ff   level one, one entry per high byte
    ///   0x100..0x10f   a level-two block whose every nibble reaches the zero leaves
    ///   0x110..0x11f   sixteen zero leaves -- "this unit does not fold"
    ///   0x120..0x12f   the level-two block for high byte 0x00
    ///   0x130..0x13f   the leaves for U+00Ex
    /// ```
    ///
    /// and the one unit that moves is `U+00E9`, by `delta`.
    fn one_fold_table(delta: u16) -> Fake {
        one_fold_table_at(TABLE, delta)
    }

    /// The same table, laid out at an arbitrary base -- which is what a 32-bit target needs, its
    /// table living at an address a four-byte pointer can hold.
    fn one_fold_table_at(base: u64, delta: u16) -> Fake {
        let mut fake = Fake::default();
        fake.nls_pointer(base);
        // Level one: every high byte but 0x00 reaches the block that folds nothing.
        for high in 0..=0xffu32 {
            fake.element(base, high, 0x100);
        }
        fake.element(base, 0x00, 0x120);
        // The shared level-two block, and the leaves it reaches.
        for nibble in 0..0x10u32 {
            fake.element(base, 0x100 + nibble, 0x110);
            fake.element(base, 0x110 + nibble, 0);
            // High byte 0x00's own level two, which differs in one nibble.
            fake.element(base, 0x120 + nibble, 0x110);
            fake.element(base, 0x130 + nibble, 0);
        }
        fake.element(base, 0x120 + 0xe, 0x130);
        fake.element(base, 0x130 + 0x9, delta);
        fake
    }

    /// The trie is walked the way the routine walks it -- from the base, and as a delta.
    ///
    /// Three mistakes this pins, each of which reads the same on a table where the levels happen
    /// to sit where a wrong rule would put them: a level-relative index, a byte offset in place of
    /// an element index, and a leaf taken as the folded unit rather than added to it. The leaf
    /// here is `0xffe0` and the answer is `U+00C9`, which is only true of the addition.
    #[test]
    fn the_trie_is_walked_from_the_base_and_its_leaf_is_a_delta() {
        let fake = one_fold_table(0xffe0);
        let upcase = Upcase::of_target(&fake, upcase_globals(), layout().pointer);

        assert_eq!(upcase.source(), UpcaseFrom::Target(TABLE));
        assert_eq!(
            upcase.unit(0x00e9),
            0x00c9,
            "the leaf is added to the unit, not substituted for it"
        );
        assert_eq!(
            upcase.unit(0x00ea),
            0x00ea,
            "a zero leaf is a unit that does not fold"
        );
        assert_eq!(
            upcase.unit(0x01e9),
            0x01e9,
            "another high byte reaches the block that folds nothing"
        );
    }

    /// **The target's table answers, and this host's does not.**
    ///
    /// The fixture folds `U+00E9` to `U+00EA` -- which no Windows table does, and this host's
    /// certainly does not, where the two fold to `U+00C9` and `U+00CA` and are two names. So the
    /// assertion below can only pass by reading the target, which is the whole of what item 77
    /// was about: a fixture whose table *agrees* with the host cannot say which one answered.
    #[test]
    fn the_targets_own_table_answers_and_not_this_hosts() {
        let fake = one_fold_table(0x0001);
        let upcase = Upcase::of_target(&fake, upcase_globals(), layout().pointer);

        assert_eq!(upcase.unit(0x00e9), 0x00ea);
        assert!(
            upcase.same_name("\u{00e9}", "\u{00ea}"),
            "on this target's table they are one name"
        );
    }

    /// And the walk itself folds through it, rather than through the host.
    ///
    /// The same discriminating table, reached the way a real walk reaches it -- through
    /// [`Globals::upcase`] -- so this fails if the component match goes back to
    /// [`same_object_name`], which is the edit it is here to catch.
    #[test]
    fn the_walk_matches_a_component_through_the_targets_table() {
        let mut fake = namespace();
        const ODD: u64 = 0xffff_a000_0060_0000;
        // `\Device\<U+00E9>`, which this target's table folds to `<U+00EA>` and no other machine
        // does.
        fake.object(ODD, "\u{00e9}", obfuscated(4, ODD), 0);
        fake.directory(DEVICE_DIR, &[DEVICE, ODD]);
        for (index, value) in one_fold_table(0x0001).bytes {
            fake.bytes.insert(index, value);
        }
        let globals = Globals {
            upcase: Some(upcase_globals()),
            ..globals()
        };
        let namespace = Namespace::new(&fake, layout(), globals)
            .expect("the fixture layout is one this crate builds");

        assert_eq!(
            namespace.upcase().source(),
            UpcaseFrom::Target(TABLE),
            "the walk folds on the target's table"
        );
        assert_eq!(
            namespace
                .object_at("\\Device\\\u{00ea}")
                .map(|found| found.address),
            Ok(ODD),
            "which is the only table that makes these one name"
        );
    }

    /// A table pointer that reads as **null** folds the ASCII bands and nothing else.
    ///
    /// `RtlUpcaseUnicodeChar`'s own `test r9,r9` answer, and the one miss that is not a fallback:
    /// a target with no table does not fold `U+00E9`, so neither does this. Standing the host's
    /// table in would report two objects as one, which is the failure the whole fold exists to
    /// avoid.
    #[test]
    fn a_null_table_pointer_folds_no_further_than_ascii() {
        let mut fake = Fake::default();
        fake.nls_pointer(0);
        let upcase = Upcase::of_target(&fake, upcase_globals(), layout().pointer);

        assert_eq!(upcase.source(), UpcaseFrom::Target(0));
        assert_eq!(upcase.unit(0x00e9), 0x00e9, "no table, so no fold");
        assert_eq!(upcase.unit(0x0061), 0x0041, "the ASCII band still folds");
    }

    /// A target that will not say where its table is falls back to the host, and **says so**.
    ///
    /// Two ways to fall short and one answer: no [`Globals::upcase`] at all, and coordinates whose
    /// read does not come back. Neither is a fact about how the target folds, which is why both
    /// stand the host's table in rather than passing the unit through.
    #[cfg_attr(
        miri,
        ignore = "the fallback folds through ntdll; see `Upcase::on_host`"
    )]
    #[test]
    fn a_table_that_cannot_be_reached_falls_back_to_the_host_and_reports_it() {
        let empty = Fake::default();
        let unreadable = Upcase::of_target(&empty, upcase_globals(), layout().pointer);
        assert_eq!(unreadable.source(), UpcaseFrom::Host);
        assert_eq!(
            unreadable.unit(0x00e9),
            Upcase::of_host().unit(0x00e9),
            "the host's table stands in"
        );

        assert_eq!(Upcase::of_host().source(), UpcaseFrom::Host);
    }

    /// A table located but not readable is **not** reported as the target having answered.
    ///
    /// The partial-dump shape, and the ordinary way to reach it: the page holding the table
    /// pointer is present, so the base resolves, and a page of the table itself is not. Every unit
    /// still folds -- a table that will not read says nothing about how the target folds, so the
    /// host stands in -- but the provenance has to say so, because a caller asking
    /// [`Upcase::source`] would otherwise be told the target answered for a fold that was this
    /// host's. That is the provenance claim wrong in the one direction this whole change exists
    /// to fix, so it is pinned rather than argued.
    #[cfg_attr(
        miri,
        ignore = "the fallback folds through ntdll; see `Upcase::on_host`"
    )]
    #[test]
    fn a_table_located_but_unreadable_reports_a_fold_of_both_machines() {
        let mut fake = Fake::default();
        // The pointer reads; nothing it points at does.
        fake.nls_pointer(TABLE);
        let upcase = Upcase::of_target(&fake, upcase_globals(), layout().pointer);

        assert_eq!(
            upcase.source(),
            UpcaseFrom::Target(TABLE),
            "before anything needs a page of it, the table is simply where it says"
        );

        assert_eq!(
            upcase.unit(0x00e9),
            Upcase::of_host().unit(0x00e9),
            "the unit still folds, on the host"
        );
        assert_eq!(
            upcase.source(),
            UpcaseFrom::Mixed { at: TABLE },
            "and the answer now carries both machines, which is what a caller has to be able to see"
        );

        // An ASCII name reads no table, so it cannot move the provenance back.
        assert!(upcase.same_name("Device", "DEVICE"));
        assert_eq!(
            upcase.source(),
            UpcaseFrom::Mixed { at: TABLE },
            "one unit folded on the wrong machine is not undone by a later one that needed no table"
        );
    }

    /// A 32-bit target's table pointer is read at **four** bytes, not eight.
    ///
    /// **The construction is the whole point, and it is the one an eight-byte read survives.** A
    /// fixture that left the four bytes after the pointer unmapped would pass either way: the
    /// eight-byte read would fail, the fold would fall back to the host, and the test could not
    /// tell a width bug from a missing page. So those four bytes are present and non-zero here,
    /// which is what a real 32-bit kernel has -- the pointer is followed by the next field, not by
    /// a hole. An eight-byte read then *succeeds* and yields an address assembled from two
    /// unrelated halves, and nothing about that failure announces itself.
    ///
    /// Read at four, the base is the table, the fold is the target's, and `source()` says so.
    #[test]
    fn a_32_bit_targets_table_pointer_is_read_at_its_own_width() {
        // A table where a 32-bit kernel would keep one, so a four-byte pointer can name it.
        const TABLE32: u64 = 0x8006_0000;
        let mut fake = one_fold_table_at(TABLE32, 0x0001);
        let at = SILO_GLOBALS + u64::from(NLS_STATE) + u64::from(UPCASE_TABLE);
        // Four bytes of pointer, then four bytes of the field that follows it -- `nls_pointer`
        // wrote eight, and on a 32-bit target only the first four are the pointer.
        fake.put(at, &(TABLE32 as u32).to_le_bytes());
        fake.put(at + 4, &0xdead_beefu32.to_le_bytes());

        let upcase = Upcase::of_target(&fake, upcase_globals(), 4);
        assert_eq!(
            upcase.source(),
            UpcaseFrom::Target(TABLE32),
            "the pointer is four bytes wide on this target"
        );
        assert_eq!(
            upcase.unit(0x00e9),
            0x00ea,
            "and the fold is the one this target's table performs"
        );

        // The same bytes read at eight: a plausible address out of two unrelated halves, reached
        // without anything failing. That is what carrying the width prevents.
        let eight = Upcase::of_target(&fake, upcase_globals(), 8);
        assert_eq!(
            eight.source(),
            UpcaseFrom::Target(0xdead_beef_8006_0000),
            "which is not where any table is"
        );

        // And a width this cannot read a pointer at reaches no table at all.
        let odd = Upcase::of_target(&fake, upcase_globals(), 2);
        assert_eq!(odd.source(), UpcaseFrom::Host);
    }

    /// And the **walk** hands the fold the width it derived, rather than a constant.
    ///
    /// **A separate test from the one above, because they pin different lines.** That one drives
    /// [`Upcase::of_target`] with explicit widths, which pins the callee and is silent about every
    /// caller -- mutating [`Namespace::new`] to pass a literal `8` leaves it green, because it
    /// never calls it. The width reaching the fold from [`Layout::pointer`] is a property of that
    /// one line, and this is the test that fails when it is wrong.
    ///
    /// `Layout::pointer` is derived from the target's own structures precisely so a 32-bit kernel
    /// debugged from a 64-bit host is not read at the host's width; a fold that did not take it
    /// would undo that for the one pointer it reads.
    #[test]
    fn the_walk_folds_at_the_pointer_width_its_layout_derived() {
        const TABLE32: u64 = 0x8006_0000;
        let mut fake = one_fold_table_at(TABLE32, 0x0001);
        let at = SILO_GLOBALS + u64::from(NLS_STATE) + u64::from(UPCASE_TABLE);
        fake.put(at, &(TABLE32 as u32).to_le_bytes());
        fake.put(at + 4, &0xdead_beefu32.to_le_bytes());

        let narrow = Layout {
            pointer: 4,
            ..layout()
        };
        let globals = Globals {
            upcase: Some(upcase_globals()),
            ..globals()
        };
        let namespace = Namespace::new(&fake, narrow, globals)
            .expect("a four-byte pointer is a width this crate builds");

        assert_eq!(
            namespace.upcase().source(),
            UpcaseFrom::Target(TABLE32),
            "the walk read the table pointer at its own target's width"
        );
    }

    /// Counts what a fold reads, so a claim about its cost is measured rather than asserted.
    struct Counting<'a> {
        inner: &'a dyn Memory,
        reads: RefCell<usize>,
    }

    impl Memory for Counting<'_> {
        fn read(&self, address: u64, len: usize) -> Option<Vec<u8>> {
            *self.reads.borrow_mut() += 1;
            self.inner.read(address, len)
        }
    }

    /// An ASCII name reads no target memory at all, and a folded unit is read once.
    ///
    /// The first half is what makes reading the table affordable: nearly every name in the
    /// namespace is ASCII, and the two bands that answer those consult no table, so the ordinary
    /// walk pays nothing for this. The second is the cache -- one component is compared against
    /// every entry in a directory, so a unit re-read per comparison would turn a directory of tens
    /// of entries into hundreds of round trips over a KD wire.
    #[test]
    fn an_ascii_name_costs_no_target_read_and_a_folded_unit_costs_one_walk() {
        let table = one_fold_table(0xffe0);
        let counting = Counting {
            inner: &table,
            reads: RefCell::new(0),
        };
        let upcase = Upcase::of_target(&counting, upcase_globals(), layout().pointer);

        assert!(upcase.same_name("MountPointManager", "MOUNTPOINTMANAGER"));
        assert_eq!(
            *counting.reads.borrow(),
            0,
            "an ASCII name never asks where the table is"
        );

        assert!(upcase.same_name("\u{00e9}", "\u{00c9}"));
        // One read finds the table, three walk the trie for `U+00E9`; `U+00C9` is a fourth level
        // one, a fifth level two and a sixth leaf.
        let first = *counting.reads.borrow();
        assert_eq!(
            first, 7,
            "the pointer, then three levels for each of two units"
        );

        assert!(upcase.same_name("\u{00e9}", "\u{00c9}"));
        assert_eq!(
            *counting.reads.borrow(),
            first,
            "folding the same units again reads nothing"
        );
    }

    /// Lays out an 8-4-4 trie that encodes `fold`, allocating blocks as it goes.
    ///
    /// **The inverse of [`Upcase::from_table`] and deliberately not a caller of it.** This decides
    /// where a block goes and writes the index that reaches it; the walk reads an index and
    /// follows it. Sharing so much as an arithmetic helper between the two would let them agree
    /// about a wrong rule, which is the one thing a table fixture cannot afford.
    fn trie_encoding(fold: impl Fn(u16) -> u16) -> Fake {
        let mut elements: Vec<u16> = vec![0; 0x100];
        let mut leaves: BTreeMap<Vec<u16>, u16> = BTreeMap::new();
        let mut level_twos: BTreeMap<Vec<u16>, u16> = BTreeMap::new();

        for high in 0..=0xffu32 {
            let mut block = Vec::new();
            for middle in 0..0x10u32 {
                let deltas: Vec<u16> = (0..0x10u32)
                    .map(|low| {
                        let unit = ((high << 8) | (middle << 4) | low) as u16;
                        fold(unit).wrapping_sub(unit)
                    })
                    .collect();
                let at = match leaves.get(&deltas) {
                    Some(at) => *at,
                    None => {
                        let at = elements.len() as u16;
                        elements.extend_from_slice(&deltas);
                        leaves.insert(deltas, at);
                        at
                    }
                };
                block.push(at);
            }
            let at = match level_twos.get(&block) {
                Some(at) => *at,
                None => {
                    let at = elements.len() as u16;
                    elements.extend_from_slice(&block);
                    level_twos.insert(block, at);
                    at
                }
            };
            elements[high as usize] = at;
        }

        let mut fake = Fake::default();
        fake.nls_pointer(TABLE);
        for (index, value) in elements.iter().enumerate() {
            fake.put(TABLE + (index as u64) * 2, &value.to_le_bytes());
        }
        fake
    }

    /// The walk reproduces `RtlUpcaseUnicodeChar` on **all 65,536 code units**.
    ///
    /// The strongest thing that can be said about the trie walk without a target in the room: a
    /// table is built that encodes this host's own fold, laid out by the routine's rules and by an
    /// encoder that shares no code with the walk, and the walk is asked for every code unit there
    /// is. A rule the walk got wrong -- an index read as a byte offset, a level read relative to
    /// itself, a leaf substituted rather than added -- cannot survive 65,536 units of a real
    /// Windows table, where 973 of them move and the rest must not.
    ///
    /// **What it does not establish** is the *target* half: that `nt!PspHostSiloGlobals` plus
    /// those two offsets is where a live kernel keeps this. That is a symbol and two type lookups,
    /// and [`DebugEngine::object_upcase_table`] is where they are read.
    #[cfg_attr(miri, ignore = "builds from ntdll's fold; see `Upcase::on_host`")]
    #[test]
    fn the_trie_walk_reproduces_the_routine_across_every_code_unit() {
        let host = Upcase::of_host();
        let fake = trie_encoding(|unit| host.unit(unit));
        let upcase = Upcase::of_target(&fake, upcase_globals(), layout().pointer);

        // **A floor rather than the figure, and the difference is what the figure is a property
        // of.** A fixture whose table moved nothing would pass whatever the walk did, so the count
        // has to be checked -- but what it counts is what *this machine's* NLS data does, which is
        // the very thing this change exists because it varies. It is 973 on 26200 x64 and on both
        // CI runner images today; pinning that would fail on the first runner whose Windows adopts
        // another `U+A7xx` block, and would fail saying nothing about the walk.
        let moved = (0..=0xffffu32)
            .filter(|unit| host.unit(*unit as u16) != *unit as u16)
            .count();
        assert!(
            moved > 900,
            "this host's table moves {moved} code units, too few to be a real upcase table -- and \
             a fixture where none moved would pass whatever the walk did"
        );

        let wrong: Vec<u16> = (0..=0xffffu32)
            .map(|unit| unit as u16)
            .filter(|unit| upcase.unit(*unit) != host.unit(*unit))
            .collect();
        assert!(
            wrong.is_empty(),
            "the walk disagrees with the routine on {} code units, first {:04x?}",
            wrong.len(),
            &wrong[..wrong.len().min(8)]
        );
    }

    /// A name differing outside ASCII resolves, which is the defect this fold replaced.
    ///
    /// `eq_ignore_ascii_case` folds twenty-six letters and the object manager folds through its
    /// own table, so `K\u{e4}se` and `K\u{c4}SE` are one object there and were two here --
    /// reported as [`ObjectError::NotFound`], which is the answer a caller acts on.
    #[cfg_attr(miri, ignore = "folds through ntdll; see `Upcase::on_host`")]
    #[test]
    fn a_name_is_matched_through_the_object_managers_fold_and_not_through_ascii() {
        let mut fake = namespace();
        const ACCENTED: u64 = 0xffff_a000_0070_0000;
        fake.object(ACCENTED, "K\u{e4}se", obfuscated(4, ACCENTED), 0);
        fake.directory(DEVICE_DIR, &[DEVICE, ACCENTED]);
        let namespace = Namespace::new(&fake, layout(), globals())
            .expect("the fixture layout is one this crate builds");

        assert_eq!(
            namespace
                .object_at("\\Device\\K\u{c4}SE")
                .map(|found| found.address),
            Ok(ACCENTED),
            "the object manager files these under one name, so this resolves to one object"
        );
    }

    /// And a name the table does **not** fold together stays two objects through the walk.
    ///
    /// The mirror of the test above, and the one that would have caught the 224: a reproduction
    /// that folds where the system does not resolves a lookup to an object the object manager
    /// would not have found, which is worse than failing to find one.
    #[cfg_attr(miri, ignore = "folds through ntdll; see `Upcase::on_host`")]
    #[test]
    fn a_name_the_table_does_not_fold_together_is_two_objects() {
        let mut fake = namespace();
        const DOTLESS: u64 = 0xffff_a000_0071_0000;
        fake.object(DOTLESS, "\u{0131}", obfuscated(4, DOTLESS), 0);
        fake.directory(DEVICE_DIR, &[DEVICE, DOTLESS]);
        let namespace = Namespace::new(&fake, layout(), globals())
            .expect("the fixture layout is one this crate builds");

        assert_eq!(
            namespace
                .object_at("\\Device\\\u{0131}")
                .map(|found| found.address),
            Ok(DOTLESS),
            "its own name still resolves"
        );
        assert_eq!(
            namespace.object_at("\\Device\\I"),
            Err(ObjectError::NotFound {
                directory: "\\Device".to_string(),
                component: "I".to_string(),
            }),
            "and `I` is a different object, which Unicode's simple mapping would have merged"
        );
    }

    /// A component that is not there is **not found**, naming what was being looked in — and not
    /// an empty answer, which reads as a namespace with nothing in it.
    #[test]
    fn a_missing_component_names_the_directory_it_was_not_in() {
        let fake = namespace();
        let namespace = Namespace::new(&fake, layout(), globals())
            .expect("the fixture layout is one this crate builds");
        assert_eq!(
            namespace.object_at("\\Device\\Nothing"),
            Err(ObjectError::NotFound {
                directory: "\\Device".to_string(),
                component: "Nothing".to_string(),
            })
        );
    }

    /// Walking *through* something that is not a directory is refused rather than followed.
    ///
    /// A device's body is not a directory, and reading one as a directory reads 37 pointers out of
    /// a driver's own fields and follows whatever they hold.
    #[test]
    fn a_leaf_is_not_walked_through() {
        let fake = namespace();
        let namespace = Namespace::new(&fake, layout(), globals())
            .expect("the fixture layout is one this crate builds");
        assert_eq!(
            namespace.object_at("\\Device\\MountPointManager\\Deeper"),
            Err(ObjectError::NotADirectory {
                component: "MountPointManager".to_string(),
                rest: "Deeper".to_string(),
            })
        );
    }

    /// A directory lists what it holds, named.
    #[test]
    fn a_directory_lists_what_it_holds() {
        let fake = namespace();
        let namespace = Namespace::new(&fake, layout(), globals())
            .expect("the fixture layout is one this crate builds");
        assert_eq!(
            namespace.objects_in("\\Device").map(|found| found
                .objects
                .into_iter()
                .map(|one| one.name)
                .collect::<Vec<_>>()),
            Ok(vec!["MountPointManager".to_string()])
        );
    }

    /// A target whose namespace will not read says **which read failed**, rather than answering
    /// with an empty namespace.
    ///
    /// This is a kernel minidump, where `nt`'s data pages are not in the file at all: measured on
    /// `docs/samples/081226-2187-01.dmp`, `ObpRootDirectoryObject` itself reads `????????`.
    #[test]
    fn a_target_with_no_namespace_says_so_rather_than_answering_empty() {
        let fake = Fake::default();
        let namespace = Namespace::new(&fake, layout(), globals())
            .expect("the fixture layout is one this crate builds");
        assert_eq!(
            namespace.object_at("\\Device"),
            Err(ObjectError::Unreadable {
                at: ROOT_POINTER,
                len: 8
            })
        );
    }

    /// A **null-object** chain is bounded too, and that is a different counter from the one that
    /// bounds what comes out.
    ///
    /// An entry whose `Object` is null contributes nothing to the list, so a bound counting the
    /// list never reaches it — and one of those pointing at itself is a loop this never leaves. On
    /// a live kernel that is a debugger that stops answering, which is the failure a bound exists
    /// to turn into a refusal.
    #[test]
    fn a_chain_of_entries_that_name_nothing_is_bounded_as_well() {
        let mut fake = namespace();
        const EMPTY: u64 = DEVICE_DIR + 0x8000;
        fake.pointer(DEVICE_DIR, EMPTY);
        fake.pointer(EMPTY, EMPTY);
        fake.pointer(EMPTY + 0x08, 0);
        let namespace = Namespace::new(&fake, layout(), globals())
            .expect("the fixture layout is one this crate builds");
        assert_eq!(
            namespace.objects_in("\\Device"),
            Err(ObjectError::TooMany {
                what: "a directory's entries",
                bound: MAX_ENTRIES
            })
        );
    }

    /// Listing a **leaf** is refused rather than answered.
    ///
    /// `object_at` guards walking *through* a device on the way to something else; this is the
    /// same guard at the end of a path. Without it a driver's own fields are read as thirty-seven
    /// bucket pointers and whatever they hold is followed as chains.
    #[test]
    fn a_leaf_is_not_listed_as_a_directory() {
        let fake = namespace();
        let namespace = Namespace::new(&fake, layout(), globals())
            .expect("the fixture layout is one this crate builds");
        assert_eq!(
            namespace.objects_in("\\Device\\MountPointManager"),
            Err(ObjectError::NotADirectory {
                component: "MountPointManager".to_string(),
                rest: String::new(),
            })
        );
    }

    /// A string with a length and **no buffer** is malformed, not empty.
    ///
    /// Answered as an empty string it becomes a symbolic link whose target is `""`, which a
    /// caller publishes as a device reachable under no name at all.
    #[test]
    fn a_length_with_no_buffer_is_malformed_rather_than_empty() {
        let mut fake = namespace();
        const LINK: u64 = 0xffff_a000_0042_0000;
        fake.flags(LINK, 0);
        fake.string(LINK + 0x08, LINK + 0x1000, "\\Device\\X");
        // Everything the link check looks at still holds; only the buffer is gone.
        fake.pointer(LINK + 0x10, 0);
        let namespace = Namespace::new(&fake, layout(), globals())
            .expect("the fixture layout is one this crate builds");
        assert_eq!(
            namespace.link_target(LINK),
            Err(ObjectError::Malformed {
                reason: "a UNICODE_STRING has a length and no buffer"
            })
        );
    }

    /// A chain that points at itself is refused, rather than walked until the process dies.
    #[test]
    fn a_looping_chain_is_refused_rather_than_walked() {
        let mut fake = namespace();
        // The first bucket's entry chains to itself.
        let entry = DEVICE_DIR + 0x2000;
        fake.pointer(DEVICE_DIR, entry);
        fake.pointer(entry, entry);
        let namespace = Namespace::new(&fake, layout(), globals())
            .expect("the fixture layout is one this crate builds");
        assert_eq!(
            namespace.objects_in("\\Device"),
            Err(ObjectError::TooMany {
                what: "a directory's entries",
                bound: MAX_ENTRIES
            })
        );
    }

    /// A link target is read as a string, and something that is not one is refused.
    ///
    /// The field shares storage with a callback pointer, so a link this walk cannot vouch for is
    /// an error rather than a string decoded out of a function address.
    #[test]
    fn a_link_target_is_checked_before_it_is_decoded() {
        let mut fake = namespace();
        const LINK: u64 = 0xffff_a000_0040_0000;
        fake.flags(LINK, 0);
        fake.string(LINK + 0x08, LINK + 0x1000, "\\Device\\MountPointManager");
        let namespace = Namespace::new(&fake, layout(), globals())
            .expect("the fixture layout is one this crate builds");
        assert_eq!(
            namespace.link_target(LINK).as_deref(),
            Ok("\\Device\\MountPointManager")
        );

        // The union's **other** arm, laid out as it really is: a callback address where the two
        // lengths are, a context pointer where the buffer is, and all sixteen bytes mapped -- so
        // what refuses this is the check rather than a read that happened to fail.
        const CALLBACK: u64 = 0xffff_a000_0041_0000;
        fake.flags(CALLBACK, 0);
        fake.pointer(CALLBACK + 0x08, 0xffff_f805_cb41_2341);
        fake.pointer(CALLBACK + 0x10, 0xffff_a000_0050_0000);
        let namespace = Namespace::new(&fake, layout(), globals())
            .expect("the fixture layout is one this crate builds");
        assert_eq!(
            namespace.link_target(CALLBACK),
            Err(ObjectError::Malformed {
                reason: "the link target is not a string this can vouch for"
            }),
            "a code address is not a whole number of UTF-16 units"
        );

        // **A target that is not an object path at all**, which is ordinary rather than
        // suspicious: `\\KnownDlls\\KnownDllPath` points at a DOS path. This walk used to require a
        // leading backslash and refused exactly that link -- a content rule standing in for the
        // flag, and wrong as soon as there was a flag to ask.
        const DOS: u64 = 0xffff_a000_0043_0000;
        fake.flags(DOS, 0);
        fake.string(DOS + 0x08, DOS + 0x1000, "C:\\Windows\\System32");
        let namespace = Namespace::new(&fake, layout(), globals())
            .expect("the fixture layout is one this crate builds");
        assert_eq!(
            namespace.link_target(DOS).as_deref(),
            Ok("C:\\Windows\\System32"),
            "the flag said this is a target, so what it holds is the answer"
        );
    }

    /// A link whose **callback** arm is live has no target, and says so.
    ///
    /// This is the case the content checks cannot reach: the lengths are a string's, the buffer
    /// reads, and what it holds is a path. Only the flag the object manager itself branches on
    /// separates the two arms, which is why it is read first.
    #[test]
    fn a_callback_link_has_no_target_to_read() {
        let mut fake = namespace();
        const LINK: u64 = 0xffff_a000_0044_0000;
        // A target that would decode perfectly well, and a flag saying it is not the live arm.
        fake.string(LINK + 0x08, LINK + 0x1000, "\\Device\\X");
        fake.flags(LINK, 0);
        let namespace = Namespace::new(&fake, layout(), globals())
            .expect("the fixture layout is one this crate builds");
        assert_eq!(
            namespace.link_target(LINK).as_deref(),
            Ok("\\Device\\X"),
            "with the bit clear the union holds the target"
        );

        fake.flags(LINK, SYMBOLIC_LINK_CALLBACK);
        let namespace = Namespace::new(&fake, layout(), globals())
            .expect("the fixture layout is one this crate builds");
        assert_eq!(
            namespace.link_target(LINK),
            Err(ObjectError::Malformed {
                reason: "this link resolves through a callback, so it has no target to read"
            }),
            "and with it set the same bytes are a callback and a context"
        );
    }

    /// An object whose **type could not be read** is not walked through or listed.
    ///
    /// The guard is what stops a device's own fields being read as bucket pointers, and a guard
    /// that passes when it cannot tell is not one. Here the type table slot is empty, which is
    /// every way that read can fail rolled into one.
    #[test]
    fn an_object_of_unknown_type_is_not_treated_as_a_directory() {
        let mut fake = namespace();
        // The slot the Device directory's own type index selects, emptied.
        fake.pointer(TYPE_TABLE + 3 * 8, 0);
        let namespace = Namespace::new(&fake, layout(), globals())
            .expect("the fixture layout is one this crate builds");
        assert_eq!(
            namespace.object_at("\\Device\\MountPointManager"),
            Err(ObjectError::Untyped {
                component: "Device".to_string(),
            }),
            "it refuses, and says it could not tell rather than that this is something else"
        );
        assert!(
            matches!(
                namespace.objects_in("\\Device"),
                Err(ObjectError::Untyped { .. })
            ),
            "and listing it is the same refusal"
        );
    }

    /// A name longer than its own maximum is **torn**, and taking its length would read past the
    /// buffer into whatever follows -- which the walk would then match a path against, resolving
    /// some other object rather than failing to resolve this one.
    ///
    /// **It is dropped from the listing and counted, rather than refused.** That was the first
    /// answer here and it protected the right thing in the wrong place: the danger is a torn name
    /// *resolving*, and an entry that is not in the listing resolves to nothing at all, so
    /// skipping it is exactly as safe and leaves the rest of the directory answerable. What is
    /// asserted below is both halves of that -- the torn entry is gone and its neighbour is not.
    ///
    /// **Counted as `malformed` and not as `unreadable`**, because the two say opposite things
    /// about a target: a page that was out will be back, while a directory entry the object
    /// manager cannot have written is a finding.
    #[test]
    fn a_name_longer_than_its_own_maximum_is_dropped_rather_than_taken_or_refused() {
        let mut fake = namespace();
        let header = DEVICE - 0x30;
        let name_info = header - 0x20;
        // Length past MaximumLength, with the buffer left as it was.
        fake.put(name_info + 0x08, &200u16.to_le_bytes());
        let namespace = Namespace::new(&fake, layout(), globals())
            .expect("the fixture layout is one this crate builds");

        let listed = namespace
            .objects_in("\\Device")
            .expect("the directory still lists");
        assert_eq!(
            (listed.objects.len(), listed.unreadable, listed.malformed),
            (0, 0, 1),
            "the torn entry is dropped, and counted as the structural fault it is"
        );
        assert_eq!(listed.skipped(), 1);

        // And it resolves to nothing rather than to whatever follows its buffer -- said about
        // **this** name, since a path is matched against what the listing holds.
        assert!(
            matches!(
                namespace.object_at("\\Device\\MountPointManager"),
                Err(ObjectError::NotFoundInPart {
                    unreadable: 0,
                    malformed: 1,
                    ..
                })
            ),
            "and a lookup says it cannot call this absent, rather than that it is -- naming \
             the structural fault rather than a page that was out"
        );
    }

    /// **A global this target does not resolve is still fatal, and skipping an entry must not
    /// have quietly made it survivable.**
    ///
    /// The two live side by side and pull opposite ways: an entry that will not read is skipped,
    /// and a missing `nt!ObpInfoMaskToOffset` makes *every* entry fail to read. Catch both in one
    /// arm and a build this walk cannot decode at all answers with an empty directory -- which
    /// says "nothing is filed here", the one reading this module exists to never produce.
    ///
    /// Written because the obvious mutation -- widening the `Err(fatal)` arm to a catch-all --
    /// left the whole suite green. The neighbouring test that looked like it covered this hands
    /// the walk an **empty** target, so it fails on the root pointer long before an entry is
    /// reached, and could not have caught it.
    #[test]
    fn a_global_the_target_lacks_is_not_swallowed_by_the_skip() {
        let fake = namespace();
        let nameless = Globals {
            info_mask_to_offset: None,
            ..globals()
        };
        let namespace = Namespace::new(&fake, layout(), nameless)
            .expect("the fixture layout is one this crate builds");
        assert_eq!(
            namespace.objects_in("\\"),
            Err(ObjectError::Unavailable {
                what: "nt!ObpInfoMaskToOffset"
            }),
            "a directory whose every entry is unnameable for want of a global is refused, not \
             answered as empty"
        );
        assert_eq!(
            namespace.object_at("\\Device"),
            Err(ObjectError::Unavailable {
                what: "nt!ObpInfoMaskToOffset"
            }),
            "and so is a lookup, rather than reporting the name absent"
        );
    }

    /// **A component already named does not override the stop that arrived after it.**
    ///
    /// The sibling below fixed the walk; this is the lookup built on it, and the hole it left. A
    /// one-shot predicate that fires *between* two namings leaves a listing that holds the first
    /// name **and** says it was halted -- and `object_at` consulted `halted` only down the
    /// not-found path, so it took the name, descended into it, and finished the lookup with the
    /// interrupt already spent. A multi-component path is what shows it: with one component the
    /// answer is merely returned early, with two the walk carries on reading.
    #[test]
    fn a_lookup_stopped_after_naming_a_component_does_not_go_on_through_it() {
        let mut two = namespace();
        const SECOND: u64 = ROOT + 0x4_0000;
        two.object(SECOND, "Second", obfuscated(3, SECOND), 0);
        two.directory(ROOT, &[DEVICE_DIR, SECOND]);

        // Fires on the second entry poll: a bucket each, a chain link each, then one per entry.
        // So `Device` is named and the stop lands before `Second` is -- the prefix case.
        let polls = std::cell::Cell::new(0usize);
        let between_namings = || {
            polls.set(polls.get() + 1);
            polls.get() == layout().buckets + 2 + 2
        };
        let looking = Namespace::new(&two, layout(), globals())
            .expect("the fixture layout is one this crate builds")
            .halting(&between_namings);
        assert!(
            matches!(
                looking.object_at("\\Device\\MountPointManager"),
                Err(ObjectError::Halted { .. })
            ),
            "the lookup was stopped holding `Device`, and must not walk on into it"
        );

        // And the component the stop names is the one it was reached at, not the one asked for,
        // so a caller can see how far the path got.
        let polls = std::cell::Cell::new(0usize);
        let between_namings = || {
            polls.set(polls.get() + 1);
            polls.get() == layout().buckets + 2 + 2
        };
        let looking = Namespace::new(&two, layout(), globals())
            .expect("the fixture layout is one this crate builds")
            .halting(&between_namings);
        assert!(
            matches!(
                looking.object_at("\\Device\\MountPointManager"),
                Err(ObjectError::Halted { what }) if what == "Device"
            ),
            "the halt names the component the walk was stopped at"
        );
    }

    /// **A halt already reported is not polled for a second time, because polling consumes it.**
    ///
    /// `DebugEngine::interrupted` is `GetInterrupt`, which clears the pending request on its first
    /// poll -- `test_get_interrupt_drain_semantics` in this crate asserts the vector
    /// `[true, false, false, false, false]`. A predicate like that is **one-shot**, and every
    /// other construction here uses one that stays true or counts up, so not one of them can see
    /// this: `entries_of` returned `halted`, `named_in` asked again, the answer was false because
    /// the first ask had taken it, and the gathered entries were named anyway.
    #[test]
    fn a_halt_the_walk_already_reported_is_not_polled_for_a_second_time() {
        let fake = namespace();

        // Fires exactly once, on the poll after the root's only entry has been gathered: bucket
        // zero's poll, then its chain's -- which is where the body is pushed -- then bucket one's.
        // So `entries_of` comes back holding a body *and* saying it was stopped, which is the
        // shape this needs: a halt at bucket zero gathers nothing and would hide the bug.
        let polls = std::cell::Cell::new(0usize);
        let once = || {
            polls.set(polls.get() + 1);
            polls.get() == 3
        };
        let walk = Namespace::new(&fake, layout(), globals())
            .expect("the fixture layout is one this crate builds")
            .halting(&once);
        let listed = walk
            .objects_in("\\")
            .expect("a stopped enumeration still answers");
        assert_eq!(
            (listed.objects.len(), listed.halted),
            (0, true),
            "the entry was gathered before the stop and must not be named after it: {listed:?}"
        );
        assert_eq!(
            polls.get(),
            3,
            "and nothing asked again once the halt came back, which is what consumes it"
        );

        // And the lookup built on it says it was stopped rather than answering. Without the break
        // the entry above is in the listing, so this finds it and reports a completed lookup --
        // `object_at` reaches its `halted` arm only when the name is *not* there.
        // Its own counter: `once` above is spent, and a one-shot that has already fired is not
        // one-shot any more -- reusing it here walked to the end and proved nothing.
        let again = std::cell::Cell::new(0usize);
        let once_more = || {
            again.set(again.get() + 1);
            again.get() == 3
        };
        let looking = Namespace::new(&fake, layout(), globals())
            .expect("the fixture layout is one this crate builds")
            .halting(&once_more);
        assert!(
            matches!(
                looking.object_at("\\Device"),
                Err(ObjectError::Halted { .. })
            ),
            "a stopped lookup does not answer with the object it had already gathered"
        );
    }

    /// **A caller's clock reaches inside the enumeration, not only around it.**
    ///
    /// A directory is an unbounded amount of work behind one call, and a timeout on *waiting* for
    /// that call abandons the waiter rather than the walk -- so the work carries on holding
    /// whatever it runs on, which is the one thing a deadline exists to prevent.
    ///
    /// **Three assertions, because there are two polls and they hid each other.** Removing either
    /// one left this green while the other still stopped the walk, so each is checked on a
    /// construction the other cannot reach.
    #[test]
    fn a_walk_stops_where_its_caller_asks_and_keeps_what_it_read() {
        let fake = namespace();

        // One: a stopped enumeration is an **answer**, not a failure. What it reached comes back
        // with `halted` set, so a caller reports a short list as short rather than losing the
        // work. The prefix is empty here because this fixture's directories hold one entry each.
        let asked = std::cell::Cell::new(0usize);
        let at_once = || {
            asked.set(asked.get() + 1);
            true
        };
        let stopped = Namespace::new(&fake, layout(), globals())
            .expect("the fixture layout is one this crate builds")
            .halting(&at_once);
        let listed = stopped
            .objects_in("\\")
            .expect("a stopped enumeration still answers");
        assert!(listed.halted, "it says the list is a prefix: {listed:?}");
        assert!(
            asked.get() > 0,
            "and the predicate was polled inside the enumeration, not around it"
        );

        // Two: the **chain** poll, on a construction the entry poll cannot reach. A bucket whose
        // entries all name nothing is followed to the bound and refused, and `named_in` never
        // runs because `entries_of` fails first. The loop goes in the **root**, which
        // `objects_in` reaches from the root pointer with no lookup in front of it -- a sub-path
        // would resolve its directory first and halt there instead, proving nothing about the
        // enumeration.
        let mut looping = namespace();
        const EMPTY: u64 = ROOT + 0x8000;
        looping.pointer(ROOT, EMPTY);
        looping.pointer(EMPTY, EMPTY);
        looping.pointer(EMPTY + 0x08, 0);
        let bounded = Namespace::new(&looping, layout(), globals())
            .expect("the fixture layout is one this crate builds");
        assert!(
            matches!(bounded.objects_in("\\"), Err(ObjectError::TooMany { .. })),
            "unstoppable, this walks to its bound"
        );
        let halting = Namespace::new(&looping, layout(), globals())
            .expect("the fixture layout is one this crate builds")
            .halting(&|| true);
        assert_eq!(
            halting.objects_in("\\").map(|found| found.halted),
            Ok(true),
            "and stopped, it comes back at once rather than running to the bound"
        );

        // Three: the **bucket** poll, on a construction neither of the others can reach. An empty
        // directory enters no chain and names no entry, so it is the one shape where the only
        // poll that can fire is the one before a bucket is read -- and without it the walk pays a
        // target read per bucket, up to the thousand a layout may declare, and then says it was
        // not stopped.
        let mut bare = namespace();
        bare.directory(ROOT, &[]);
        let empty = Namespace::new(&bare, layout(), globals())
            .expect("the fixture layout is one this crate builds")
            .halting(&|| true);
        let listed = empty
            .objects_in("\\")
            .expect("an empty directory still lists");
        assert!(
            listed.halted,
            "an empty directory is buckets to read, and stopping means not reading them: {listed:?}"
        );
        assert!(
            !listed.is_complete(),
            "and a halted listing is not a complete one, whatever its counts say"
        );

        // Four: the **entry** poll, and the first two goes at this were both green with the poll
        // deleted. The trap is that every other halt leaves an **empty** listing -- `entries_of`
        // returns before a single entry is named -- and an empty listing is exactly what deleting
        // the entry poll produces too, so `objects.len() == 0` cannot tell them apart. What only
        // a stop *between two namings* can produce is a **proper prefix**: one object out of two.
        //
        // So the directory gets a second entry, and the threshold is counted off the fixture
        // rather than off the walk: one poll per bucket the layout declares, then one per chain
        // link, and only then one per entry. Deriving it from a counting run instead would move
        // with the mutation and pass against it again.
        let mut two = namespace();
        const SECOND: u64 = ROOT + 0x4_0000;
        two.object(SECOND, "Second", obfuscated(3, SECOND), 0);
        two.directory(ROOT, &[DEVICE_DIR, SECOND]);

        // The structure that threshold rests on, asserted rather than assumed -- and on its own
        // enough to fail if a phase stops polling.
        let counted = std::cell::Cell::new(0usize);
        let never = || {
            counted.set(counted.get() + 1);
            false
        };
        let whole = Namespace::new(&two, layout(), globals())
            .expect("the fixture layout is one this crate builds")
            .halting(&never);
        let all = whole.objects_in("\\").expect("nothing stopped this one");
        assert_eq!(
            (all.objects.len(), all.halted),
            (2, false),
            "the fixture holds two and nothing stopped the walk: {all:?}"
        );
        assert_eq!(
            counted.get(),
            layout().buckets + 2 + 2,
            "a poll per bucket, then per chain link, then per entry -- the three phases the \
             threshold below counts past"
        );

        // Held off through every bucket and chain poll and through the *first* entry's, this can
        // only fire on the second -- after one object is listed and before the other is.
        let polls = std::cell::Cell::new(0usize);
        let after_the_first_naming = || {
            polls.set(polls.get() + 1);
            polls.get() > layout().buckets + 2 + 1
        };
        let late = Namespace::new(&two, layout(), globals())
            .expect("the fixture layout is one this crate builds")
            .halting(&after_the_first_naming);
        let listed = late
            .objects_in("\\")
            .expect("a stopped enumeration answers");
        assert_eq!(
            (listed.objects.len(), listed.halted),
            (1, true),
            "one of the two was named and the walk then stopped, which no other poll can do: \
             {listed:?}"
        );

        // And a lookup has no partial answer to give, so it is an error -- **not** one that says
        // the object is absent, since it may be in the part never reached. A caller told
        // `NotFound` here would stop looking for something that is there.
        let stopped = Namespace::new(&fake, layout(), globals())
            .expect("the fixture layout is one this crate builds")
            .halting(&|| true);
        assert!(
            matches!(
                stopped.object_at("\\Device"),
                Err(ObjectError::Halted { .. })
            ),
            "a stopped lookup says it was stopped, not that the name is not there"
        );
    }

    /// **One entry whose name is paged out does not take the directory with it.**
    ///
    /// Measured on a live Windows Server 26100 guest 2026-09-13, which is where this came from
    /// rather than from imagination: `\GLOBAL??` holds some two hundred symbolic links and one
    /// whose `Name.Buffer` is not resident -- the debugger's own `!object` prints it as
    /// `(*** Name not accessible ***)` and carries on. This walk failed the whole listing, and
    /// because `object_at` resolves every component through the same code, it also failed every
    /// lookup whose path crossed that directory. A tool asking "what reaches this device" got
    /// "this directory cannot be listed", which reads as a device nothing reaches.
    #[test]
    fn a_directory_survives_an_entry_whose_name_will_not_read() {
        let mut fake = namespace();
        let header = DEVICE - 0x30;
        let name_info = header - 0x20;
        // The buffer pointer sent somewhere the fixture does not map, which is what a page that
        // is out answers: the string's own length and maximum still agree.
        fake.put(name_info + 0x10, &0xffff_c000_dead_0000u64.to_le_bytes());
        let namespace = Namespace::new(&fake, layout(), globals())
            .expect("the fixture layout is one this crate builds");

        let listed = namespace
            .objects_in("\\Device")
            .expect("the directory still lists");
        assert_eq!(
            (listed.objects.len(), listed.unreadable, listed.malformed),
            (0, 1, 0),
            "the entry is dropped and counted as the transient thing it is"
        );

        // And a lookup of it names the transient fault rather than the structural one, which is
        // the other half of the pair `NotFoundInPart` carries two counts for.
        assert!(
            matches!(
                namespace.object_at("\\Device\\MountPointManager"),
                Err(ObjectError::NotFoundInPart {
                    unreadable: 1,
                    malformed: 0,
                    ..
                })
            ),
            "a page that was out is reported as one, not as corruption"
        );

        // The root still resolves through, which is the half the live failure was really about:
        // a lookup does not have to be *of* the unreadable entry to have been taken away by it.
        assert_eq!(
            namespace.objects_in("\\").map(|found| found
                .objects
                .into_iter()
                .map(|one| one.name)
                .collect::<Vec<_>>()),
            Ok(vec!["Device".to_string()]),
            "a neighbouring directory is untouched by it"
        );
    }

    /// A name that is **not text** lists, and does not resolve.
    ///
    /// An unpaired surrogate is a legal object name and an illegal `String`. Rendering it with
    /// replacements keeps the object visible, which is what a listing is for; matching on that
    /// rendering would let two different names answer to one query, and would let a caller asking
    /// for the replacement character reach an object whose name has no such character in it. For a
    /// device that is answering under a name that is not its own.
    #[test]
    fn a_name_that_is_not_text_lists_but_does_not_resolve() {
        let mut fake = namespace();
        const ODD: u64 = 0xffff_a000_0060_0000;
        const OTHER: u64 = 0xffff_a000_0061_0000;
        // Two different names, each with a lone high surrogate, which render identically.
        fake.units_named(ODD, &[0x41, 0xd800, 0x42], obfuscated(4, ODD));
        fake.units_named(OTHER, &[0x41, 0xdbff, 0x42], obfuscated(4, OTHER));
        fake.directory(DEVICE_DIR, &[DEVICE, ODD, OTHER]);
        let namespace = Namespace::new(&fake, layout(), globals())
            .expect("the fixture layout is one this crate builds");

        let listed = namespace
            .objects_in("\\Device")
            .expect("the directory lists");
        let rendered: Vec<&str> = listed
            .objects
            .iter()
            .filter(|one| !one.exact_name)
            .map(|one| one.name.as_str())
            .collect();
        assert_eq!(
            rendered.len(),
            2,
            "both are listed, so neither object is lost: {listed:?}"
        );
        assert_eq!(
            rendered[0], rendered[1],
            "and they render alike, which is what makes the rendering useless as an identity"
        );

        assert!(
            matches!(
                namespace.object_at(&format!("\\Device\\{}", rendered[0])),
                Err(ObjectError::NotFound { .. })
            ),
            "so neither answers to it"
        );
        assert_eq!(
            namespace
                .object_at("\\Device\\MountPointManager")
                .map(|found| found.address),
            Ok(DEVICE),
            "and the ordinary name beside them still resolves"
        );
    }

    /// A target that cannot name **types** still answers everything that does not need one.
    ///
    /// Requiring the type globals was the previous round's answer and was too broad: resolving a
    /// one-component path, listing the root, and reading a link target all need no type at all. The
    /// guards still fail closed -- they just say [`ObjectError::Untyped`] when they cannot tell.
    #[test]
    fn a_target_that_cannot_name_types_still_answers_what_needs_none() {
        let fake = namespace();
        let untyped = Globals {
            header_cookie: None,
            type_index_table: None,
            ..globals()
        };
        let namespace = Namespace::new(&fake, layout(), untyped)
            .expect("the fixture layout is one this crate builds");

        assert_eq!(
            namespace.object_at("\\Device").map(|found| found.address),
            Ok(DEVICE_DIR),
            "one component needs no type"
        );
        assert_eq!(
            namespace.objects_in("\\").map(|found| found
                .objects
                .into_iter()
                .map(|one| one.name)
                .collect::<Vec<_>>()),
            Ok(vec!["Device".to_string()]),
            "nor does listing the root"
        );
        assert_eq!(
            namespace.object_at("\\Device\\MountPointManager"),
            Err(ObjectError::Untyped {
                component: "Device".to_string()
            }),
            "and descending is refused, saying which of the two it is"
        );
    }

    /// A link is read on a target that resolves **none** of the namespace's globals.
    ///
    /// Reading one needs the symbolic link's own layout and nothing else: not the root pointer, not
    /// the optional-header offsets, not the type table. Requiring the set would take an answer this
    /// target can give away because of a symbol it never reads -- which is the third round of
    /// findings this seam produced, and why the globals are now asked for one at a time.
    #[test]
    fn a_link_is_read_with_none_of_the_namespaces_globals() {
        let mut fake = namespace();
        const LINK: u64 = 0xffff_a000_0045_0000;
        fake.flags(LINK, 0);
        fake.string(LINK + 0x08, LINK + 0x1000, "\\Device\\MountPointManager");
        let nothing = Globals {
            root: None,
            info_mask_to_offset: None,
            header_cookie: None,
            type_index_table: None,
            upcase: None,
        };
        let namespace = Namespace::new(&fake, layout(), nothing)
            .expect("the fixture layout is one this crate builds");

        assert_eq!(
            namespace.link_target(LINK).as_deref(),
            Ok("\\Device\\MountPointManager"),
            "the link reads, because it needs none of them"
        );
        assert_eq!(
            namespace.object_at("\\Device"),
            Err(ObjectError::Unavailable {
                what: "nt!ObpRootDirectoryObject"
            }),
            "and a walk says which one it wanted"
        );
    }

    /// A link target is bounded as a **path**, not as a name.
    ///
    /// A name is one component and a target is a whole path, so holding the second to the first's
    /// bound refuses an ordinary link -- with a message about object names, which is the tell.
    #[test]
    fn a_link_target_is_bounded_as_a_path_rather_than_as_a_name() {
        let mut fake = namespace();
        const LINK: u64 = 0xffff_a000_0046_0000;
        // Longer than a name may be, and far inside what a path may be.
        let long = format!("\\Device\\{}", "D".repeat(MAX_NAME_BYTES));
        fake.flags(LINK, 0);
        fake.string(LINK + 0x08, LINK + 0x1000, &long);
        let namespace = Namespace::new(&fake, layout(), globals())
            .expect("the fixture layout is one this crate builds");
        assert_eq!(
            namespace.link_target(LINK).as_deref(),
            Ok(long.as_str()),
            "a target this long is a path, not a name that got out of hand"
        );
    }

    /// A layout this crate did not build is **refused**, never panicked on.
    ///
    /// [`Layout`] is public and so is [`Namespace::new`], so its fields are a caller's to fill in
    /// -- and every one of them is an index into bytes this walk read. A pointer width of two has
    /// two bytes read and eight taken; an offset past the end of a structure is the same fault by
    /// another route. Both are a panic inside calls whose whole contract is that they return an
    /// error, so both are errors.
    #[test]
    fn a_layout_this_crate_did_not_build_is_refused_rather_than_panicked_on() {
        let fake = namespace();
        let refused = |layout: Layout| match Namespace::new(&fake, layout, globals()) {
            Err(ObjectError::Malformed { reason }) => reason,
            other => panic!("a layout that is not one was accepted: {:?}", other.is_ok()),
        };

        // Every one of these was a separate defect before the layout was checked in one place: a
        // width of two had two bytes read and eight taken, `usize::MAX` overflowed the size
        // arithmetic before any read happened, no buckets made a full directory look empty, too
        // many kept it reading, and a field past the end of its structure was taken from whatever
        // followed.
        assert_eq!(
            refused(Layout {
                pointer: 2,
                ..layout()
            }),
            "a pointer on this target is neither four bytes nor eight"
        );
        assert_eq!(
            refused(Layout {
                pointer: usize::MAX,
                ..layout()
            }),
            "a pointer on this target is neither four bytes nor eight"
        );
        assert_eq!(
            refused(Layout {
                buckets: 0,
                ..layout()
            }),
            "a directory's bucket count is not one a directory has"
        );
        assert_eq!(
            refused(Layout {
                buckets: MAX_BUCKETS + 1,
                ..layout()
            }),
            "a directory's bucket count is not one a directory has"
        );
        assert_eq!(
            refused(Layout {
                unicode_length: 0x40,
                ..layout()
            }),
            "a UNICODE_STRING's lengths sit outside the structure"
        );
        assert_eq!(
            refused(Layout {
                name_info_name: 0x40,
                ..layout()
            }),
            "a name header's string sits outside the name header"
        );
        // **A relation is not a magnitude**, which is the gap the checks above left: these offsets
        // are ordered exactly as a real layout's are, and describe a structure of nearly four
        // gigabytes. What that reaches is a read asked for in gigabytes, which is an allocation
        // failure rather than a refusal.
        assert_eq!(
            refused(Layout {
                pointer: 4,
                unicode_buffer: u32::MAX - 4,
                name_info_name: 0,
                name_info_size: u32::MAX,
                ..layout()
            }),
            "a field sits further into its structure than any of these reach"
        );

        // And the one this crate builds is accepted, so the check is not refusing everything.
        assert!(Namespace::new(&fake, layout(), globals()).is_ok());
    }

    /// Listing with **no path at all** is refused, not answered about the root.
    ///
    /// `\\` is the root and nothing else is. Trimming first made the empty string the same
    /// value, so an argument that went missing came back as a successful listing of a directory
    /// nobody asked about -- and `object_at` had always refused it, so one question had two
    /// answers.
    #[test]
    fn listing_with_no_path_is_refused_rather_than_answered_about_the_root() {
        let fake = namespace();
        let namespace = Namespace::new(&fake, layout(), globals())
            .expect("the fixture layout is one this crate builds");

        // **Every one of these used to list the root**, each through a different hole in a parser
        // `objects_in` kept for itself: nothing at all, a path that never begins at the root, and
        // a path of separators with no name between them. `object_at` refused all three.
        for path in ["", "Device", "\\\\", "\\\\\\"] {
            assert!(
                matches!(namespace.objects_in(path), Err(ObjectError::BadPath { .. })),
                "{path:?} is not the root"
            );
            assert!(
                matches!(namespace.object_at(path), Err(ObjectError::BadPath { .. })),
                "{path:?} is not an object either, and the two agree now"
            );
        }

        // Nor is a path whose components are not all named.
        assert!(
            matches!(
                namespace.object_at("\\Device\\\\MountPointManager"),
                Err(ObjectError::BadPath { .. })
            ),
            "an empty component is refused rather than dropped"
        );

        let root = |path: &str| {
            namespace.objects_in(path).map(|found| {
                found
                    .objects
                    .into_iter()
                    .map(|one| one.name)
                    .collect::<Vec<_>>()
            })
        };
        assert_eq!(
            root("\\"),
            Ok(vec!["Device".to_string()]),
            "while the root itself lists"
        );
        assert_eq!(
            namespace
                .objects_in("\\Device\\")
                .map(|found| found.objects.len()),
            Ok(1),
            "and one trailing separator is still a caller's convenience"
        );
    }

    /// A path that is not a path is refused before anything is read.
    #[test]
    fn a_path_that_is_not_one_is_refused() {
        let fake = namespace();
        let namespace = Namespace::new(&fake, layout(), globals())
            .expect("the fixture layout is one this crate builds");
        assert!(matches!(
            namespace.object_at("Device"),
            Err(ObjectError::BadPath { .. })
        ));
        assert!(matches!(
            namespace.object_at("\\"),
            Err(ObjectError::BadPath { .. })
        ));
    }
}
