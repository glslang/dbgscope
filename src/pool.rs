pub(crate) mod decode;
pub(crate) mod index;
pub(crate) mod layout;
pub(crate) mod render;
pub(crate) mod snapshot;

pub mod query;

/// The two forms a pool tag takes, and the question of which one identifies it.
///
/// A caller that renders [`PoolSpan::display_tag`] and hands the result back to
/// [`query::find_tag`] has a round trip that silently breaks on any tag `display_tag` cannot
/// render — so a consumer showing tags to a human should show [`raw_tag_hex`] wherever
/// [`display_is_ambiguous`] holds, and `parse_tag` takes either form back.
pub use decode::{
    display_is_ambiguous, display_round_trips, parse_raw_tag, parse_tag, raw_tag_hex, tag_label,
};
pub(crate) use index::PoolIndex;
pub(crate) use snapshot::PoolSnapshot;
pub use snapshot::{DIAGNOSTIC_EXAMPLES, DiagnosticShape, PoolDiagnostics, WalkStalls};

/// Exact allocator identity.  Values are deliberately not collapsed into just
/// paged/nonpaged because crossing one of these boundaries creates false holes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PoolKind {
    NonPagedExecutable,
    NonPagedNx,
    Paged,
    PrototypePaged,
    SpecialNonPaged,
    SpecialNonPagedNx,
    SpecialPaged,
    SpecialPrototypePaged,
}

impl PoolKind {
    pub fn is_paged(self) -> bool {
        matches!(
            self,
            Self::Paged | Self::PrototypePaged | Self::SpecialPaged | Self::SpecialPrototypePaged
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PoolBackend {
    Lfh,
    Vs,
    Segment,
    Large,
}

/// What a span is: three kinds of chunk the allocator laid out, and two kinds of span that is
/// not a chunk at all but the walk accounting for address space it could not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PoolState {
    Allocated,
    ReusableFree,
    CachedFree,
    /// A span the walk could not read and **nothing established was empty**. Something may have
    /// been there, so it is a hole in the walk's coverage and clears
    /// [`query::WalkCoverage::complete`].
    ///
    /// **It is the conservative bucket, not a claim that the target has the memory.** Two very
    /// different things land here: a page the memory manager confirms is committed — paged out,
    /// missing from a dump, refused by the debugger — and a page no commitment query could be
    /// made about at all, which is every kernel walk and any target
    /// [`snapshot::PoolMemory::committed_run`] answers `None` for. Only
    /// [`Self::Uncommitted`] carries a positive answer; this one carries the absence of one, and
    /// reading it as confirmed memory would turn *we could not tell* into a fact about the
    /// target.
    Unreadable,
    /// Address space inside a region with **no pages behind it** — reserved, or committed and
    /// since released — as the target's memory manager says, not as the walk inferred from
    /// where the span lies.
    ///
    /// Distinct from [`Self::Unreadable`] because the two are opposite answers to the only
    /// question coverage asks. Nothing can be in memory that does not exist, so a walk that did
    /// not read this missed nothing and stays complete. Collapsing the two, which is what this
    /// walker did until a live user-mode heap was measured against the memory manager's own
    /// record (glslang/windbg-mcp FOLLOWUPS item 98), left `Partial` as the answer on every
    /// healthy live target and so left the one signal for *we could not see something* saying
    /// nothing.
    Uncommitted,
}

impl PoolState {
    /// Whether this span is a chunk the allocator laid out, rather than a gap the walk is
    /// accounting for.
    ///
    /// The distinction every caller that walks *neighbours* needs: a gap has no header, no tag
    /// and no successor, so treating one as a chunk makes a span adjacent to memory that was
    /// never decoded. Asked here rather than at each site, because the sites that get it wrong
    /// are the ones that named `Unreadable` and were never revisited when a second kind of gap
    /// arrived.
    pub fn is_chunk(self) -> bool {
        match self {
            Self::Allocated | Self::ReusableFree | Self::CachedFree => true,
            Self::Unreadable | Self::Uncommitted => false,
        }
    }

    /// Whether a span in this state counts *against* the walk's coverage — the one place that
    /// decides what `complete` means.
    pub fn is_coverage_gap(self) -> bool {
        match self {
            Self::Unreadable => true,
            Self::Allocated | Self::ReusableFree | Self::CachedFree | Self::Uncommitted => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HeapIdentity {
    pub pool_state: u64,
    pub heap: u64,
    pub special: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSpan {
    pub header_address: u64,
    pub usable_address: u64,
    pub size: u64,
    /// Exact requested size when allocator metadata validates it. Kernel pool and user LFH/VS
    /// spans leave this unset rather than guessing from capacity.
    pub requested_size: Option<u64>,
    pub raw_tag: u32,
    pub display_tag: String,
    pub pool_kind: PoolKind,
    pub numa_node: u16,
    pub heap: HeapIdentity,
    pub subsegment: Option<u64>,
    pub backend: PoolBackend,
    pub state: PoolState,
    pub size_class: u32,
}

impl PoolSpan {
    pub fn end(&self) -> u64 {
        self.usable_address.saturating_add(self.size)
    }

    pub fn contains_address(&self, address: u64) -> bool {
        address >= self.header_address && address < self.end()
    }

    /// A span with **synthetic geometry**: `header_address == usable_address`, which no walker
    /// ever emits — `walk_lfh`, `walk_vs` and `walk_page_ranges` all put the usable bytes a
    /// pool header past the header.
    ///
    /// Fine for tests about tags, filters and identity. Not fine for a test about *geometry*,
    /// and this has now hidden two bugs in `chunk_at`'s contiguity check by being the only
    /// thing that satisfied it (glslang/dbgscope#85, then the gate that replaced it). Build a
    /// backend-shaped span by hand for those, as `query`'s `lfh_allocation` and `vs_allocation`
    /// do.
    #[cfg(test)]
    pub(crate) fn allocation(
        address: u64,
        size: u64,
        tag: u32,
        pool_kind: PoolKind,
        heap: HeapIdentity,
        backend: PoolBackend,
    ) -> Self {
        Self {
            header_address: address,
            usable_address: address,
            size,
            requested_size: None,
            raw_tag: tag,
            display_tag: decode::display_tag(tag),
            pool_kind,
            numa_node: 0,
            heap,
            subsegment: None,
            backend,
            state: PoolState::Allocated,
            size_class: size.min(u32::MAX as u64) as u32,
        }
    }
}
