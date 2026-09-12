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
//! Names are compared with an **ASCII** case fold, which is what device and directory names are in
//! practice and is stated rather than hidden: the kernel folds with its own upcase table, so a name
//! differing only outside ASCII compares unequal here where the object manager would match it.
//!
//! # Where it works
//!
//! A live kernel, and a kernel dump complete enough to carry `nt`'s data pages. It does **not**
//! work on a kernel minidump: measured against `docs/samples/081226-2187-01.dmp` in the consumer,
//! `nt!ObpRootDirectoryObject` itself reads `????????`, so the walk stops at its first read and
//! says so rather than reporting an empty namespace.

use thiserror::Error;

use crate::dbgeng::{DbgEngError, DebugEngine};

/// The most entries one directory may hold before the walk refuses it.
///
/// `\GLOBAL??` on a busy machine holds a few thousand; this is well above that and far below a
/// chain that has looped. It bounds the whole directory rather than one bucket, because a cycle
/// can be spread across buckets as easily as kept inside one.
const MAX_ENTRIES: usize = 65_536;

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
        Ok(Self {
            memory,
            layout,
            globals,
        })
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
    fn entries_of(&self, directory: u64) -> Result<Vec<u64>, ObjectError> {
        let mut out = Vec::new();
        let mut followed = 0usize;
        for bucket in 0..self.layout.buckets {
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
        Ok(out)
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
    fn named_in(&self, directory: u64) -> Result<Vec<KernelObject>, ObjectError> {
        let mut out = Vec::new();
        for body in self.entries_of(directory)? {
            let Some((name, exact_name)) = self.name_of(body)? else {
                continue;
            };
            out.push(KernelObject {
                address: body,
                name,
                exact_name,
                type_name: self.type_of(body),
                security_descriptor: self.security_of(body)?,
            });
        }
        Ok(out)
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
            let found = self
                .named_in(directory)?
                .into_iter()
                .find(|object| object.exact_name && object.name.eq_ignore_ascii_case(component))
                .ok_or_else(|| ObjectError::NotFound {
                    directory: walked.clone(),
                    component: component.clone(),
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
    pub fn objects_in(&self, path: &str) -> Result<Vec<KernelObject>, ObjectError> {
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
        })
    }

    /// The object filed under a path, as `!object` would find it.
    pub fn object_at(&self, path: &str) -> Result<KernelObject, ObjectError> {
        self.with_namespace(|namespace| namespace.object_at(path))
    }

    /// Everything a directory holds.
    pub fn objects_in(&self, path: &str) -> Result<Vec<KernelObject>, ObjectError> {
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
            "the descriptor field is a fast reference, and the count in its low bits is not              part of the address"
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
            namespace
                .objects_in("\\Device")
                .map(|found| found.into_iter().map(|one| one.name).collect::<Vec<_>>()),
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
    /// buffer into whatever follows -- which the walk then matches a path against, resolving some
    /// other object rather than failing to resolve this one.
    #[test]
    fn a_name_longer_than_its_own_maximum_is_refused() {
        let mut fake = namespace();
        let header = DEVICE - 0x30;
        let name_info = header - 0x20;
        // Length past MaximumLength, with the buffer left as it was.
        fake.put(name_info + 0x08, &200u16.to_le_bytes());
        let namespace = Namespace::new(&fake, layout(), globals())
            .expect("the fixture layout is one this crate builds");
        assert_eq!(
            namespace.objects_in("\\Device"),
            Err(ObjectError::Malformed {
                reason: "a UNICODE_STRING is longer than its own maximum"
            })
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
            namespace
                .objects_in("\\")
                .map(|found| found.into_iter().map(|one| one.name).collect::<Vec<_>>()),
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
            namespace
                .objects_in(path)
                .map(|found| found.into_iter().map(|one| one.name).collect::<Vec<_>>())
        };
        assert_eq!(
            root("\\"),
            Ok(vec!["Device".to_string()]),
            "while the root itself lists"
        );
        assert_eq!(
            namespace.objects_in("\\Device\\").map(|found| found.len()),
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
