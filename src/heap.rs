//! Typed, version-aware queries over user-mode Segment Heaps.
//!
//! Root discovery is user-specific — `ntdll`'s process heap list, and the PEB's `ProcessHeaps`
//! on a build that keeps none (see `enumerate_roots`); page-segment, LFH, VS, backend, and
//! large-allocation decoding is shared with the kernel-pool walker.

use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use thiserror::Error;
use windows::Win32::System::Diagnostics::Debug::Extensions::{
    DEBUG_STATUS_BREAK, DEBUG_STATUS_NO_DEBUGGEE,
};
use windows::Win32::System::SystemInformation::{
    IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64,
};

use crate::allocator::LayoutProvenance;
use crate::dbgeng::{DbgEngError, DebugEngine, KernelImage};
use crate::pool::layout::{LayoutCache, LayoutError, LayoutKey, LayoutTarget, PoolLayout, Symbols};
use crate::pool::query::WalkCoverage;
use crate::pool::snapshot::{PoolSnapshot, SnapshotError, walk_user_segment_heaps};
use crate::pool::{DiagnosticShape, PoolBackend, PoolState, WalkStalls};

const SEGMENT_HEAP_SIGNATURE: u32 = 0xddee_ddee;
const NT_HEAP_SIGNATURE: u32 = 0xeeff_eeff;
const MAX_PROCESS_HEAPS: usize = 4096;
pub const DEFAULT_WALK_BUDGET: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeapWalk {
    pub refresh: bool,
    pub budget: Option<Duration>,
}

impl HeapWalk {
    pub fn cached() -> Self {
        Self {
            refresh: false,
            budget: Some(DEFAULT_WALK_BUDGET),
        }
    }

    pub fn refreshed() -> Self {
        Self {
            refresh: true,
            ..Self::cached()
        }
    }

    pub fn within(self, budget: Duration) -> Self {
        Self {
            budget: Some(budget),
            ..self
        }
    }
}

impl From<bool> for HeapWalk {
    fn from(refresh: bool) -> Self {
        if refresh {
            Self::refreshed()
        } else {
            Self::cached()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HeapKind {
    Segment,
    Nt,
    Unknown,
    Unreadable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeapRoot {
    /// Position in the enumeration: `ntdll`'s process heap list in its own order, which is the
    /// order `GetProcessHeaps` returns, then any root the PEB names that the list did not hold.
    /// On a build that keeps no list this is the index into the PEB's `ProcessHeaps`.
    pub index: usize,
    pub address: u64,
    pub kind: HeapKind,
    pub supported: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HeapBackend {
    Lfh,
    Vs,
    Segment,
    Large,
}

impl From<PoolBackend> for HeapBackend {
    fn from(value: PoolBackend) -> Self {
        match value {
            PoolBackend::Lfh => Self::Lfh,
            PoolBackend::Vs => Self::Vs,
            PoolBackend::Segment => Self::Segment,
            PoolBackend::Large => Self::Large,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HeapState {
    Allocated,
    ReusableFree,
    CachedFree,
    Unreadable,
}

impl From<PoolState> for HeapState {
    fn from(value: PoolState) -> Self {
        match value {
            PoolState::Allocated => Self::Allocated,
            PoolState::ReusableFree => Self::ReusableFree,
            PoolState::CachedFree => Self::CachedFree,
            PoolState::Unreadable => Self::Unreadable,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeapAllocation {
    pub heap: u64,
    pub backend: HeapBackend,
    pub state: HeapState,
    pub header_address: u64,
    pub user_address: u64,
    pub capacity: u64,
    /// Exact only when the selected schema validates the allocator's unused-byte metadata.
    pub requested_size: Option<u64>,
    pub subsegment: Option<u64>,
    pub size_class: u32,
}

impl HeapAllocation {
    pub fn end(&self) -> u64 {
        self.user_address.saturating_add(self.capacity)
    }

    pub fn contains(&self, address: u64) -> bool {
        address >= self.header_address && address < self.end()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeapScope {
    pub segment_heaps_walked: Vec<u64>,
    pub nt_heaps_skipped: Vec<u64>,
    pub unknown_heaps_skipped: Vec<u64>,
    pub unreadable_heaps_skipped: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeapWalkReport {
    pub coverage: WalkCoverage,
    pub total_chunks: usize,
    pub allocated_chunks: usize,
    pub diagnostic_count: usize,
    pub unreadable_gaps: usize,
    pub refused_headers: u64,
    /// Committed VS bytes the walk declined to decode because it could not place a chunk
    /// boundary in them; see [`crate::pool::PoolSnapshot::unplaced_bytes`].
    pub unplaced_bytes: u64,
    pub stalls: WalkStalls,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeapDiagnosticReport {
    pub categories: Vec<DiagnosticShape>,
    pub examples: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeapNeighbourhood {
    pub allocation: HeapAllocation,
    /// Signed displacement from `user_address`; addresses in the allocator header are negative.
    pub offset: i64,
    pub previous: Option<HeapAllocation>,
    pub next: Option<HeapAllocation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HeapCensusRow {
    pub heap: u64,
    pub backend: HeapBackend,
    pub state: HeapState,
    pub size_class: u32,
    pub chunks: usize,
    pub total_capacity: u64,
}

#[derive(Debug, Clone)]
pub struct HeapAnswer<T> {
    pub found: T,
    pub layout: LayoutProvenance,
    pub scope: HeapScope,
    pub walk: HeapWalkReport,
}

#[derive(Debug, Error)]
pub enum HeapQueryError {
    #[error("heap queries require a user-mode target")]
    NotUserTarget,
    #[error("no debuggee is loaded")]
    NoDebuggee,
    #[error(
        "the target is not stopped (execution status {status:#x}); break in before walking heaps"
    )]
    TargetRunning { status: u32 },
    #[error("heap walking supports x64 and ARM64 targets only (machine {machine:#x})")]
    UnsupportedArchitecture { machine: u32 },
    /// The current thread's TEB names a 32-bit one beside it. The heaps the PEB and `ntdll`
    /// know about are then the 64-bit emulation layer's, and the program's own are 32-bit
    /// structures this walker does not decode.
    #[error(
        "heap walking does not support a WoW64 process (_TEB.WowTebOffset is \
         {wow_teb_offset}): its own heaps are 32-bit, and the 64-bit heaps beside them are the \
         emulation layer's"
    )]
    Wow64Process { wow_teb_offset: i32 },
    #[error("invalid TEB: {0}")]
    InvalidTeb(String),
    #[error("invalid PEB heap metadata: {0}")]
    InvalidPeb(String),
    #[error("heap selector {heap:#x} is not a supported Segment Heap root of the current process")]
    UnsupportedHeap { heap: u64 },
    #[error(
        "missing or unsupported ntdll allocator layout ({0}); run `.reload /f ntdll.dll` and retry"
    )]
    Layout(String),
    #[error("the heap walk was interrupted on request")]
    Interrupted,
    #[error("the heap walk ran out of its budget while resolving the ntdll allocator layout")]
    BudgetExpired,
    #[error("walking the heap failed: {0}")]
    Walk(String),
    #[error(transparent)]
    Engine(#[from] DbgEngError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SnapshotKey {
    target: u64,
    process_system_id: u32,
    peb: u64,
    image: KernelImage,
    generation: u64,
    /// A scoped diagnostic walk is a different snapshot from the all-heaps walk.
    heap: Option<u64>,
}

#[derive(Debug, Clone)]
struct HeapSnapshot {
    roots: Vec<HeapRoot>,
    allocations: Vec<HeapAllocation>,
    layout: LayoutProvenance,
    scope: HeapScope,
    walk: HeapWalkReport,
    diagnostics: HeapDiagnosticReport,
}

#[derive(Debug, Clone, Copy)]
struct ValidatedTarget {
    target: u64,
    process_system_id: u32,
    peb: u64,
    generation: u64,
}

struct ResolvedSchema {
    layout: PoolLayout,
    provenance: LayoutProvenance,
    image: KernelImage,
}

struct BudgetedSymbols<'a> {
    engine: &'a DebugEngine,
    deadline: Option<Instant>,
}

impl BudgetedSymbols<'_> {
    fn check(&self) -> Result<(), HeapQueryError> {
        self.poll().map_err(map_layout_error)
    }
}

impl Symbols for BudgetedSymbols<'_> {
    fn poll(&self) -> Result<(), LayoutError> {
        if self
            .engine
            .interrupted()
            .map_err(|error| LayoutError::Poll {
                detail: error.to_string(),
            })?
        {
            return Err(LayoutError::Interrupted);
        }
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(LayoutError::BudgetExpired);
        }
        Ok(())
    }

    fn symbol(&self, name: &str) -> Result<u64, DbgEngError> {
        self.engine.symbol_offset(name)
    }

    fn type_id(&self, module: u64, name: &str) -> Result<u32, DbgEngError> {
        self.engine.type_id(module, name)
    }

    fn type_size(&self, module: u64, type_id: u32) -> Result<u32, DbgEngError> {
        self.engine.type_size(module, type_id)
    }

    fn field(&self, module: u64, type_id: u32, name: &str) -> Result<u32, DbgEngError> {
        self.engine.field_offset(module, type_id, name)
    }
}

fn map_layout_error(error: LayoutError) -> HeapQueryError {
    match error {
        LayoutError::Interrupted => HeapQueryError::Interrupted,
        LayoutError::BudgetExpired => HeapQueryError::BudgetExpired,
        other => HeapQueryError::Layout(other.to_string()),
    }
}

#[derive(Default)]
struct SnapshotCache {
    entry: Mutex<Option<(SnapshotKey, HeapSnapshot)>>,
}

impl SnapshotCache {
    fn get(&self, key: SnapshotKey) -> Option<HeapSnapshot> {
        self.entry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .filter(|(cached, _)| *cached == key)
            .map(|(_, snapshot)| snapshot.clone())
    }

    fn put(&self, key: SnapshotKey, snapshot: HeapSnapshot) {
        *self
            .entry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((key, snapshot));
    }

    fn invalidate(&self) {
        *self
            .entry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }
}

fn snapshots() -> &'static SnapshotCache {
    static CACHE: OnceLock<SnapshotCache> = OnceLock::new();
    CACHE.get_or_init(SnapshotCache::default)
}

/// Drop the user-heap snapshot while retaining the image-keyed `ntdll` schema.
pub fn invalidate_snapshot() {
    snapshots().invalidate();
}

/// Drop every user-heap snapshot and resolved `ntdll` schema.
pub fn invalidate_caches() {
    invalidate_snapshot();
    LayoutCache::global().invalidate();
}

/// The reads root discovery makes, so it can be driven against a double modelled on a measured
/// process as well as against a live engine.
trait RootMemory {
    fn read(&self, address: u64, size: usize) -> Result<Vec<u8>, DbgEngError>;
    fn interrupted(&self) -> Result<bool, DbgEngError>;
}

impl RootMemory for DebugEngine {
    fn read(&self, address: u64, size: usize) -> Result<Vec<u8>, DbgEngError> {
        self.read_memory(address, size)
    }

    fn interrupted(&self) -> Result<bool, DbgEngError> {
        DebugEngine::interrupted(self)
    }
}

fn read_u32(memory: &impl RootMemory, address: u64) -> Result<u32, DbgEngError> {
    Ok(u32::from_le_bytes(
        memory
            .read(address, 4)?
            .try_into()
            .expect("read_memory returns exactly four bytes or a ShortRead error"),
    ))
}

fn read_u64(memory: &impl RootMemory, address: u64) -> Result<u64, DbgEngError> {
    Ok(u64::from_le_bytes(
        memory
            .read(address, 8)?
            .try_into()
            .expect("read_memory returns exactly eight bytes or a ShortRead error"),
    ))
}

/// The same 128 TiB user half on x64 and ARM64.
fn user_pointer(address: u64) -> bool {
    (0x1_0000..0x0000_8000_0000_0000).contains(&address)
}

fn classify_root(
    segment: Result<u32, String>,
    nt: Result<u32, String>,
) -> (HeapKind, Option<String>) {
    match (segment, nt) {
        (Ok(SEGMENT_HEAP_SIGNATURE), Ok(NT_HEAP_SIGNATURE)) => (
            HeapKind::Unknown,
            Some("root ambiguously matches both Segment and NT heap signatures".into()),
        ),
        (Ok(SEGMENT_HEAP_SIGNATURE), _) => (HeapKind::Segment, None),
        (_, Ok(NT_HEAP_SIGNATURE)) => (
            HeapKind::Nt,
            Some("classic NT heap decoding is outside the v1 Segment Heap walker".into()),
        ),
        (Err(segment), Err(nt)) => (
            HeapKind::Unreadable,
            Some(format!(
                "cannot read Segment signature ({segment}) or NT signature ({nt})"
            )),
        ),
        _ => (
            HeapKind::Unknown,
            Some("root matches neither the PDB-resolved Segment nor NT heap signature".into()),
        ),
    }
}

fn read_root_signatures(
    memory: &impl RootMemory,
    address: u64,
    segment_offset: u64,
    nt_offset: u64,
) -> (Result<u32, String>, Result<u32, String>) {
    let start_offset = segment_offset.min(nt_offset);
    let end_offset = segment_offset.max(nt_offset).saturating_add(4);
    let Some(start) = address.checked_add(start_offset) else {
        let error = "heap signature address overflow".to_string();
        return (Err(error.clone()), Err(error));
    };
    let size = usize::try_from(end_offset.saturating_sub(start_offset))
        .expect("two u32 PDB fields fit in a host-sized read buffer");
    let bytes = match memory.read(start, size) {
        Ok(bytes) => bytes,
        Err(error) => {
            let error = error.to_string();
            return (Err(error.clone()), Err(error));
        }
    };
    let decode = |offset: u64| {
        let relative = usize::try_from(offset - start_offset)
            .expect("a field within the signature buffer has a host-sized offset");
        let value = bytes
            .get(relative..relative + 4)
            .expect("read_memory returns the complete signature buffer or a ShortRead error")
            .try_into()
            .expect("a signature slice is exactly four bytes");
        Ok(u32::from_le_bytes(value))
    };
    (decode(segment_offset), decode(nt_offset))
}

/// Where an entry on `ntdll`'s process heap list keeps the heap it stands for.
///
/// The entry has no type in the public PDB, so this is a measured offset rather than a resolved
/// one: `RtlpProcessHeapsInsert` allocates 0x30 bytes, links them into the list at +0 and stores
/// the heap at +0x10 — the same on 26100.1 ARM64 and 26200 x64 (2026-09-22). What makes reading
/// it safe is the check made on every entry rather than the offset: the heap found here has to
/// name the entry back through its own PDB-typed `UserContext`, and an entry that is not the
/// list's own does not get that by accident.
const LIST_ENTRY_HEAP: u64 = 0x10;

/// The offsets root discovery reads, taken out of the schema once.
#[derive(Debug, Clone, Copy)]
struct RootLayout {
    number_of_heaps: u64,
    process_heaps: u64,
    segment_signature: u64,
    nt_signature: u64,
    /// Where each kind of heap names its entry on `ntdll`'s heap list, when the PDB says.
    segment_entry: Option<u64>,
    nt_entry: Option<u64>,
}

impl RootLayout {
    fn of(layout: &PoolLayout) -> Result<Self, HeapQueryError> {
        let required = |type_name: &str, field: &str| {
            layout
                .field(type_name, field)
                .map(|offset| offset as u64)
                .map_err(|error| HeapQueryError::Layout(error.to_string()))
        };
        let optional = |type_name: &str, field: &str| {
            layout
                .field(type_name, field)
                .ok()
                .map(|offset| offset as u64)
        };
        Ok(Self {
            number_of_heaps: required("_PEB", "NumberOfHeaps")?,
            process_heaps: required("_PEB", "ProcessHeaps")?,
            segment_signature: required("_SEGMENT_HEAP", "Signature")?,
            nt_signature: required("_HEAP", "Signature")?,
            segment_entry: optional("_SEGMENT_HEAP", "UserContext"),
            nt_entry: optional("_HEAP", "UserContext"),
        })
    }
}

struct RootEnumeration {
    roots: Vec<HeapRoot>,
    /// How many roots there are, when that was known before they were all classified — the
    /// PEB's count, on a build that keeps no heap list. A list has no count until it is walked.
    total: Option<usize>,
    budget_expired: bool,
    /// Why roots may exist that this enumeration did not see. `None` means it saw them all.
    unseen: Option<String>,
}

impl RootEnumeration {
    /// Whether a heap absent from `roots` is absent from the process, rather than unseen.
    fn saw_every_root(&self) -> bool {
        !self.budget_expired && self.unseen.is_none()
    }
}

fn root_read_budget_expired(
    memory: &impl RootMemory,
    deadline: Option<Instant>,
) -> Result<bool, HeapQueryError> {
    if memory.interrupted()? {
        return Err(HeapQueryError::Interrupted);
    }
    Ok(deadline.is_some_and(|deadline| Instant::now() >= deadline))
}

fn truncated_root_snapshot(
    classified: usize,
    total: Option<usize>,
    budget: Option<Duration>,
) -> PoolSnapshot {
    let mut snapshot = PoolSnapshot {
        complete: false,
        budget_expired: true,
        ..PoolSnapshot::default()
    };
    let allowed = budget.map_or_else(
        || "walk budget".into(),
        |budget| format!("{budget:?} budget"),
    );
    let coverage = total.map_or_else(
        || format!("{classified} heap roots classified before their number was known"),
        |total| format!("{classified} of {total} PEB heap roots classified"),
    );
    snapshot.diagnostics.push(format!(
        "the walk ran out of its {allowed} while enumerating heap roots: {coverage}; what is \
         missing is unknown, not absent"
    ));
    snapshot
}

/// A walk that covered every root it was handed has still not covered the ones enumeration
/// could not see, and says so rather than reporting itself complete.
fn with_unseen_roots(mut snapshot: PoolSnapshot, unseen: Option<String>) -> PoolSnapshot {
    if let Some(unseen) = unseen {
        snapshot.complete = false;
        snapshot.diagnostics.push(unseen);
    }
    snapshot
}

fn root(index: usize, address: u64, (kind, reason): (HeapKind, Option<String>)) -> HeapRoot {
    HeapRoot {
        index,
        address,
        kind,
        supported: kind == HeapKind::Segment,
        reason,
    }
}

/// What the heap at `address` is, by its PDB-resolved signatures.
fn classify_at(
    memory: &impl RootMemory,
    layout: &RootLayout,
    address: u64,
) -> (HeapKind, Option<String>) {
    if address == 0 {
        return (HeapKind::Unknown, Some("null heap root".into()));
    }
    if !user_pointer(address) {
        return (
            HeapKind::Unknown,
            Some("heap root is outside the user address range".into()),
        );
    }
    let (segment, nt) = read_root_signatures(
        memory,
        address,
        layout.segment_signature,
        layout.nt_signature,
    );
    classify_root(segment, nt)
}

/// Where `heap` names its entry on `ntdll`'s heap list. `Ok(None)` is a heap naming none: a PDB
/// without the field, or a null one — a build that keeps no list.
fn list_entry_of(
    memory: &impl RootMemory,
    layout: &RootLayout,
    heap: u64,
    kind: HeapKind,
) -> Result<Option<u64>, String> {
    let offset = match kind {
        HeapKind::Segment => layout.segment_entry,
        HeapKind::Nt => layout.nt_entry,
        HeapKind::Unknown | HeapKind::Unreadable => {
            return Err(format!(
                "heap {heap:#x} is neither a Segment nor an NT heap, so where it names its entry \
                 is not known"
            ));
        }
    };
    let Some(offset) = offset else {
        return Ok(None);
    };
    match read_u64(memory, heap.saturating_add(offset)) {
        Ok(0) => Ok(None),
        Ok(entry) => Ok(Some(entry)),
        Err(error) => Err(format!(
            "cannot read where heap {heap:#x} names its entry: {error}"
        )),
    }
}

/// The PEB's `ProcessHeaps`, which on a build keeping `ntdll`'s heap list names the process heap
/// alone: `RtlpProcessHeapsInsert` writes the array for the first heap and never again.
fn peb_heaps(
    memory: &impl RootMemory,
    layout: &RootLayout,
    peb: u64,
) -> Result<Vec<u64>, HeapQueryError> {
    let count = read_u32(memory, peb + layout.number_of_heaps)? as usize;
    if count > MAX_PROCESS_HEAPS {
        return Err(HeapQueryError::InvalidPeb(format!(
            "NumberOfHeaps is {count}, maximum is {MAX_PROCESS_HEAPS}"
        )));
    }
    let array = read_u64(memory, peb + layout.process_heaps)?;
    if count != 0 && array == 0 {
        return Err(HeapQueryError::InvalidPeb(
            "ProcessHeaps is null while NumberOfHeaps is nonzero".into(),
        ));
    }
    if count == 0 {
        return Ok(Vec::new());
    }
    if !user_pointer(array) {
        return Err(HeapQueryError::InvalidPeb(format!(
            "ProcessHeaps {array:#x} is outside the user address range"
        )));
    }
    Ok(memory
        .read(array, count.saturating_mul(8))?
        .chunks_exact(8)
        .map(|entry| {
            u64::from_le_bytes(
                entry
                    .try_into()
                    .expect("ProcessHeaps is read as a whole number of pointer-sized entries"),
            )
        })
        .collect())
}

/// Every heap root in the process: the heaps on `ntdll`'s process heap list, in its order —
/// which is the order `GetProcessHeaps` returns them in — then any the PEB names that the list
/// did not hold.
///
/// **The PEB is not the list, and has not been since at least 26100.** Its `ProcessHeaps` holds
/// the process heap and nothing else, so a `HeapCreate` return value is absent from it while
/// `GetProcessHeaps` returns it: measured 2026-09-22 on a live ARM64 26100.1 process holding
/// three heaps against a PEB naming one, and on two x64 26200 dumps whose list head links two
/// entries against a PEB naming one. Walking the PEB alone listed every such process as having
/// one heap and called the answer complete.
///
/// The list is reached through the process heap, which names its entry in `UserContext`, rather
/// than through the list head's symbol: 26200's public PDB names the head
/// (`ntdll!RtlpProcessHeaps`) and 26100.1 ARM64's does not, while both carry the typed field.
/// Every entry is checked rather than trusted — its heap has to name it back, and its `Blink`
/// has to be the entry before it — and exactly one entry, the head, lies inside `ntdll`. A build
/// whose process heap names no entry keeps no list, and its PEB array is the whole answer, as it
/// was for every release before this one. Anything else the walk cannot follow is reported as
/// unseen rather than absent.
fn enumerate_roots(
    memory: &impl RootMemory,
    layout: &RootLayout,
    peb: u64,
    ntdll: Range<u64>,
    deadline: Option<Instant>,
) -> Result<RootEnumeration, HeapQueryError> {
    let mut found = RootEnumeration {
        roots: Vec::new(),
        total: None,
        budget_expired: false,
        unseen: None,
    };
    if root_read_budget_expired(memory, deadline)? {
        found.budget_expired = true;
        return Ok(found);
    }
    let named = peb_heaps(memory, layout, peb)?;
    let listed = match named.first() {
        Some(&process_heap) => {
            follow_heap_list(memory, layout, process_heap, &ntdll, deadline, &mut found)?
        }
        None => false,
    };
    if found.budget_expired {
        return Ok(found);
    }
    if !listed {
        found.total = Some(named.len());
    }
    let on_list: HashSet<u64> = found.roots.iter().map(|root| root.address).collect();
    for address in named {
        if on_list.contains(&address) {
            continue;
        }
        if root_read_budget_expired(memory, deadline)? {
            found.budget_expired = true;
            return Ok(found);
        }
        let index = found.roots.len();
        found
            .roots
            .push(root(index, address, classify_at(memory, layout, address)));
    }
    Ok(found)
}

/// Follow `ntdll`'s heap list from the process heap's own entry, adding each heap on it to
/// `found`. Answers whether there was a list to follow; `false` leaves the PEB as the answer.
fn follow_heap_list(
    memory: &impl RootMemory,
    layout: &RootLayout,
    process_heap: u64,
    ntdll: &Range<u64>,
    deadline: Option<Instant>,
    found: &mut RootEnumeration,
) -> Result<bool, HeapQueryError> {
    if layout.segment_entry.is_none() && layout.nt_entry.is_none() {
        return Ok(false);
    }
    if root_read_budget_expired(memory, deadline)? {
        found.budget_expired = true;
        return Ok(true);
    }
    let (kind, _) = classify_at(memory, layout, process_heap);
    let start = match list_entry_of(memory, layout, process_heap, kind) {
        Ok(Some(entry)) => entry,
        Ok(None) => return Ok(false),
        Err(why) => {
            found.unseen = Some(format!(
                "the process heap could not say where ntdll's heap list is ({why}), so heaps the \
                 PEB does not name are unknown, not absent"
            ));
            return Ok(true);
        }
    };
    let broken = |entry: u64, why: String| {
        format!(
            "ntdll's heap list could not be followed past {entry:#x}: {why}; heaps after it are \
             unknown, not absent"
        )
    };
    let mut visited = HashSet::new();
    let mut heads = Vec::new();
    let mut entry = start;
    let mut previous = None;
    let mut first_blink = 0;
    loop {
        if root_read_budget_expired(memory, deadline)? {
            found.budget_expired = true;
            return Ok(true);
        }
        if !visited.insert(entry) {
            found.unseen = Some(broken(
                entry,
                format!("the list comes back to it without returning to {start:#x}"),
            ));
            return Ok(true);
        }
        let links = match memory.read(entry, 0x18) {
            Ok(bytes) => bytes,
            Err(error) => {
                found.unseen = Some(broken(entry, format!("the entry cannot be read: {error}")));
                return Ok(true);
            }
        };
        let word = |index: usize| {
            u64::from_le_bytes(
                links[index * 8..index * 8 + 8]
                    .try_into()
                    .expect("an entry is read as three whole pointers"),
            )
        };
        let (flink, blink, heap) = (word(0), word(1), word(LIST_ENTRY_HEAP as usize / 8));
        match previous {
            None => first_blink = blink,
            Some(previous) if blink != previous => {
                found.unseen = Some(broken(
                    entry,
                    format!("it links back to {blink:#x} rather than to {previous:#x}"),
                ));
                return Ok(true);
            }
            Some(_) => {}
        }
        if ntdll.contains(&entry) {
            heads.push(entry);
        } else {
            let classified = classify_at(memory, layout, heap);
            let named = match list_entry_of(memory, layout, heap, classified.0) {
                Ok(Some(named)) if named == entry => None,
                Ok(Some(named)) => Some(format!("names {named:#x} instead")),
                Ok(None) => Some("names no entry".into()),
                Err(why) => Some(why),
            };
            if let Some(why) = named {
                found.unseen = Some(broken(
                    entry,
                    format!("it stands for heap {heap:#x}, which {why}"),
                ));
                return Ok(true);
            }
            let index = found.roots.len();
            found.roots.push(root(index, heap, classified));
        }
        previous = Some(entry);
        entry = flink;
        if entry == start {
            break;
        }
    }
    if Some(first_blink) != previous {
        found.unseen = Some(broken(
            start,
            format!(
                "the first entry links back to {first_blink:#x} rather than to the last, {:#x}",
                previous.unwrap_or_default()
            ),
        ));
    } else if heads.len() != 1 {
        found.unseen = Some(format!(
            "the heap list followed from the process heap has {} entries inside ntdll where a list \
             has exactly one head, so it is not the list this walker knows; heaps it did not \
             reach are unknown, not absent",
            heads.len()
        ));
    }
    Ok(true)
}

fn scope_of(roots: &[HeapRoot]) -> HeapScope {
    let mut scope = HeapScope::default();
    for root in roots {
        match root.kind {
            HeapKind::Segment => scope.segment_heaps_walked.push(root.address),
            HeapKind::Nt => scope.nt_heaps_skipped.push(root.address),
            HeapKind::Unknown => scope.unknown_heaps_skipped.push(root.address),
            HeapKind::Unreadable => scope.unreadable_heaps_skipped.push(root.address),
        }
    }
    scope
}

fn scope_for(
    roots: &[HeapRoot],
    heap: Option<u64>,
    enumeration_complete: bool,
) -> Result<HeapScope, HeapQueryError> {
    let mut scope = scope_of(roots);
    if let Some(heap) = heap {
        let selected = roots.iter().find(|root| root.address == heap);
        if selected.is_some_and(|root| root.kind != HeapKind::Segment)
            || (selected.is_none() && enumeration_complete)
        {
            return Err(HeapQueryError::UnsupportedHeap { heap });
        }
        // Diagnostic shapes deliberately generalise addresses. Narrow the roots handed to the
        // walker so complaints from another heap never enter this snapshot's aggregation.
        scope.segment_heaps_walked.retain(|root| *root == heap);
    }
    Ok(scope)
}

fn from_pool_snapshot(
    snapshot: PoolSnapshot,
) -> (Vec<HeapAllocation>, HeapWalkReport, HeapDiagnosticReport) {
    let mut allocations: Vec<_> = snapshot
        .spans
        .iter()
        .map(|span| HeapAllocation {
            heap: span.heap.heap,
            backend: span.backend.into(),
            state: span.state.into(),
            header_address: span.header_address,
            user_address: span.usable_address,
            capacity: span.size,
            requested_size: span.requested_size,
            subsegment: span.subsegment,
            size_class: span.size_class,
        })
        .collect();
    allocations.sort_by_key(|allocation| (allocation.user_address, allocation.heap));
    let walk = HeapWalkReport {
        coverage: match (snapshot.complete, snapshot.budget_expired) {
            (true, _) => WalkCoverage::Complete,
            (false, true) => WalkCoverage::BudgetExpired,
            (false, false) => WalkCoverage::Partial,
        },
        total_chunks: allocations.len(),
        allocated_chunks: allocations
            .iter()
            .filter(|allocation| allocation.state == HeapState::Allocated)
            .count(),
        diagnostic_count: snapshot.diagnostics.emitted(),
        unreadable_gaps: allocations
            .iter()
            .filter(|allocation| allocation.state == HeapState::Unreadable)
            .count(),
        refused_headers: snapshot.refused_chunks,
        unplaced_bytes: snapshot.unplaced_bytes,
        stalls: snapshot.stalls,
    };
    let diagnostics = HeapDiagnosticReport {
        categories: snapshot.diagnostics.shapes().to_vec(),
        examples: snapshot.diagnostics.examples().to_vec(),
    };
    (allocations, walk, diagnostics)
}

fn validate_target(engine: &DebugEngine) -> Result<ValidatedTarget, HeapQueryError> {
    if engine.is_kernel_target()? {
        return Err(HeapQueryError::NotUserTarget);
    }
    match engine.execution_status()? {
        DEBUG_STATUS_NO_DEBUGGEE => return Err(HeapQueryError::NoDebuggee),
        DEBUG_STATUS_BREAK => {}
        status => return Err(HeapQueryError::TargetRunning { status }),
    }
    // The physical processor, not the one the engine is rendering for: it is what fixes a
    // pointer's width. An x64 process emulated on ARM64 is `0xaa64` here and ARM64EC to the
    // engine, and its heaps are the ARM64X `ntdll`'s like a native process's (2026-09-23). What
    // this cannot see is WoW64, which reads the same as a native process on both machines —
    // `refuse_wow64` is the check for that.
    let machine = engine.processor_type()?;
    if ![IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64]
        .iter()
        .any(|supported| u32::from(supported.0) == machine)
    {
        return Err(HeapQueryError::UnsupportedArchitecture { machine });
    }
    let peb = engine.current_process_peb()?;
    if peb == 0 {
        return Err(HeapQueryError::InvalidPeb(
            "DbgEng returned a null PEB".into(),
        ));
    }
    Ok(ValidatedTarget {
        target: engine.target_identity(),
        process_system_id: engine.current_process_system_id()?,
        peb,
        generation: crate::pool::query::generation(),
    })
}

/// Refuses a WoW64 process, by the one field that says so at every stop.
///
/// Neither processor type does. The physical one is the host's, and the effective one is still
/// 64-bit at a WoW64 launch's first break — `ARM64` there on ARM64 26100.1, measured 2026-09-23,
/// and the same on x64 per `windbg-mcp` `FOLLOWUPS.md` item 58. The heaps a walk would find
/// then are real, which is the trouble: the PEB and `ntdll` it reads are the 64-bit emulation
/// layer's, so it would list those and call the answer complete while every heap the program
/// allocates from is 32-bit and absent. `_TEB.WowTebOffset` is the kernel's own statement that
/// the thread has a 32-bit TEB, and it read `+0x2000` at both of that launch's breaks, and zero
/// in a native ARM64 process and in an emulated x64 one.
fn refuse_wow64(
    engine: &DebugEngine,
    ntdll: u64,
    deadline: Option<Instant>,
) -> Result<(), HeapQueryError> {
    let symbols = BudgetedSymbols { engine, deadline };
    symbols.check()?;
    let offset = symbols
        .type_id(ntdll, "_TEB")
        .and_then(|teb| symbols.field(ntdll, teb, "WowTebOffset"))
        .map_err(|error| {
            HeapQueryError::Layout(format!(
                "ntdll's _TEB.WowTebOffset, which says whether this is a WoW64 process: {error}"
            ))
        })?;
    symbols.check()?;
    let teb = engine.current_thread_teb()?;
    wow_teb_offset(engine, teb, u64::from(offset))
}

/// `refuse_wow64`'s reading of a TEB, apart from the engine that finds it.
fn wow_teb_offset(memory: &impl RootMemory, teb: u64, offset: u64) -> Result<(), HeapQueryError> {
    if teb == 0 {
        return Err(HeapQueryError::InvalidTeb(
            "DbgEng returned a null TEB".into(),
        ));
    }
    let field = teb.checked_add(offset).ok_or_else(|| {
        HeapQueryError::InvalidTeb(format!("TEB {teb:#x} + {offset:#x} overflows"))
    })?;
    let bytes = memory.read(field, 4).map_err(|error| {
        HeapQueryError::InvalidTeb(format!("cannot read WowTebOffset at {field:#x}: {error}"))
    })?;
    let wow_teb_offset = i32::from_le_bytes(bytes.as_slice().try_into().map_err(|_| {
        HeapQueryError::InvalidTeb(format!("short read of WowTebOffset at {field:#x}"))
    })?);
    match wow_teb_offset {
        0 => Ok(()),
        wow_teb_offset => Err(HeapQueryError::Wow64Process { wow_teb_offset }),
    }
}

fn resolve_schema(
    engine: &DebugEngine,
    target: ValidatedTarget,
    deadline: Option<Instant>,
) -> Result<ResolvedSchema, HeapQueryError> {
    let symbols = BudgetedSymbols { engine, deadline };
    symbols.check()?;
    let loaded_module = engine.module("ntdll");
    symbols.check()?;
    let loaded_module = loaded_module?;
    let image = KernelImage {
        base: loaded_module.base,
        size: loaded_module.size,
        timestamp: loaded_module.timestamp,
        checksum: loaded_module.checksum,
    };
    let layout_key = LayoutKey {
        image,
        session: target.generation,
    };
    let layout = LayoutCache::global()
        .get_or_resolve(&symbols, layout_key, LayoutTarget::User)
        .map_err(map_layout_error)?;
    // Type lookups above force a deferred module to load. Check provenance afterwards so
    // export-only symbols fail explicitly without preventing the normal deferred-load path.
    symbols.check()?;
    let module = engine.module_identity("ntdll");
    symbols.check()?;
    let module = module?;
    if !module.symbols.has_type_info() || module.symbol_file.is_empty() {
        return Err(HeapQueryError::Layout(
            "DbgEng did not load private PDB type information for ntdll".into(),
        ));
    }
    let provenance = layout.provenance(module).map_err(map_layout_error)?;
    Ok(ResolvedSchema {
        layout,
        provenance,
        image,
    })
}

fn walk_snapshot(
    engine: &DebugEngine,
    walk: HeapWalk,
    started: Instant,
    target: ValidatedTarget,
    schema: ResolvedSchema,
    heap: Option<u64>,
) -> Result<HeapSnapshot, HeapQueryError> {
    let key = SnapshotKey {
        target: target.target,
        process_system_id: target.process_system_id,
        peb: target.peb,
        image: schema.image,
        generation: target.generation,
        heap,
    };
    if walk.refresh {
        snapshots().invalidate();
    } else if let Some(snapshot) = snapshots().get(key) {
        return Ok(snapshot);
    }

    // The absolute deadline keeps schema resolution and root enumeration inside the caller's
    // one budget. An unrepresentably large duration has the same unbounded meaning as the
    // shared walker gives it.
    let deadline = walk.budget.and_then(|budget| started.checked_add(budget));
    let ntdll = schema.image.base
        ..schema
            .image
            .base
            .saturating_add(u64::from(schema.image.size));
    let enumeration = enumerate_roots(
        engine,
        &RootLayout::of(&schema.layout)?,
        target.peb,
        ntdll,
        deadline,
    )?;
    let mut scope = scope_for(&enumeration.roots, heap, enumeration.saw_every_root())?;
    let RootEnumeration {
        roots,
        total,
        budget_expired,
        unseen,
    } = enumeration;
    let pool = if budget_expired {
        // These roots were identified but no allocator region was walked after the deadline.
        scope.segment_heaps_walked.clear();
        truncated_root_snapshot(roots.len(), total, walk.budget)
    } else {
        let remaining = walk
            .budget
            .map(|budget| budget.saturating_sub(started.elapsed()));
        let walked = walk_user_segment_heaps(
            engine,
            &schema.layout,
            target.peb,
            &scope.segment_heaps_walked,
            remaining,
            1_000_000,
        )
        .map_err(|error| match error {
            SnapshotError::Interrupted => HeapQueryError::Interrupted,
            other => HeapQueryError::Walk(other.to_string()),
        })?;
        with_unseen_roots(walked, unseen)
    };
    let (allocations, report, diagnostics) = from_pool_snapshot(pool);
    let snapshot = HeapSnapshot {
        roots,
        allocations,
        layout: schema.provenance,
        scope,
        walk: report,
        diagnostics,
    };
    if snapshot.walk.coverage == WalkCoverage::Complete {
        snapshots().put(key, snapshot.clone());
    }
    Ok(snapshot)
}

fn prepare(engine: &DebugEngine, walk: HeapWalk) -> Result<HeapSnapshot, HeapQueryError> {
    prepare_for_heap(engine, None, walk)
}

fn prepare_for_heap(
    engine: &DebugEngine,
    heap: Option<u64>,
    walk: HeapWalk,
) -> Result<HeapSnapshot, HeapQueryError> {
    let started = Instant::now();
    let deadline = walk.budget.and_then(|budget| started.checked_add(budget));
    let target = validate_target(engine)?;
    let schema = resolve_schema(engine, target, deadline)?;
    refuse_wow64(engine, schema.image.base, deadline)?;
    walk_snapshot(engine, walk, started, target, schema, heap)
}

fn answer<T>(snapshot: &HeapSnapshot, found: T) -> HeapAnswer<T> {
    HeapAnswer {
        found,
        layout: snapshot.layout.clone(),
        scope: snapshot.scope.clone(),
        walk: snapshot.walk.clone(),
    }
}

pub fn list(
    engine: &DebugEngine,
    walk: impl Into<HeapWalk>,
) -> Result<HeapAnswer<Vec<HeapRoot>>, HeapQueryError> {
    let snapshot = prepare(engine, walk.into())?;
    Ok(answer(&snapshot, snapshot.roots.clone()))
}

pub fn allocations(
    engine: &DebugEngine,
    walk: impl Into<HeapWalk>,
) -> Result<HeapAnswer<Vec<HeapAllocation>>, HeapQueryError> {
    let snapshot = prepare(engine, walk.into())?;
    Ok(answer(&snapshot, snapshot.allocations.clone()))
}

pub fn chunk_at(
    engine: &DebugEngine,
    address: u64,
    walk: impl Into<HeapWalk>,
) -> Result<HeapAnswer<Option<HeapNeighbourhood>>, HeapQueryError> {
    let snapshot = prepare(engine, walk.into())?;
    let found = neighbourhood_at(&snapshot.allocations, address);
    Ok(answer(&snapshot, found))
}

fn neighbourhood_at(allocations: &[HeapAllocation], address: u64) -> Option<HeapNeighbourhood> {
    let split = allocations.partition_point(|allocation| allocation.user_address <= address);
    let position = split
        .checked_sub(1)
        .filter(|&index| allocations[index].contains(address))
        .or_else(|| {
            allocations
                .get(split)
                .filter(|allocation| allocation.contains(address))
                .map(|_| split)
        })?;
    let allocation = allocations[position].clone();
    let same_heap = |candidate: &HeapAllocation| {
        candidate.heap == allocation.heap
            && candidate.backend == allocation.backend
            && candidate.subsegment == allocation.subsegment
            && candidate.state != HeapState::Unreadable
    };
    let previous = position
        .checked_sub(1)
        .and_then(|index| allocations.get(index))
        .filter(|candidate| same_heap(candidate) && candidate.end() == allocation.header_address)
        .cloned();
    let next = allocations
        .get(position + 1)
        .filter(|candidate| same_heap(candidate) && allocation.end() == candidate.header_address)
        .cloned();
    Some(HeapNeighbourhood {
        offset: i64::try_from(i128::from(address) - i128::from(allocation.user_address)).unwrap_or(
            if address < allocation.user_address {
                i64::MIN
            } else {
                i64::MAX
            },
        ),
        allocation,
        previous,
        next,
    })
}

fn census_of(allocations: &[HeapAllocation]) -> Vec<HeapCensusRow> {
    let mut rows: HashMap<(u64, HeapBackend, HeapState, u32), HeapCensusRow> = HashMap::new();
    for allocation in allocations {
        let key = (
            allocation.heap,
            allocation.backend,
            allocation.state,
            allocation.size_class,
        );
        let row = rows.entry(key).or_insert(HeapCensusRow {
            heap: allocation.heap,
            backend: allocation.backend,
            state: allocation.state,
            size_class: allocation.size_class,
            chunks: 0,
            total_capacity: 0,
        });
        row.chunks += 1;
        row.total_capacity = row.total_capacity.saturating_add(allocation.capacity);
    }
    let mut rows: Vec<_> = rows.into_values().collect();
    rows.sort_by(|left, right| {
        right
            .total_capacity
            .cmp(&left.total_capacity)
            .then_with(|| right.chunks.cmp(&left.chunks))
            .then_with(|| left.cmp(right))
    });
    rows
}

pub fn census(
    engine: &DebugEngine,
    walk: impl Into<HeapWalk>,
) -> Result<HeapAnswer<Vec<HeapCensusRow>>, HeapQueryError> {
    let snapshot = prepare(engine, walk.into())?;
    let found = census_of(&snapshot.allocations);
    Ok(answer(&snapshot, found))
}

pub fn diagnostics(
    engine: &DebugEngine,
    walk: impl Into<HeapWalk>,
) -> Result<HeapAnswer<HeapDiagnosticReport>, HeapQueryError> {
    let snapshot = prepare(engine, walk.into())?;
    Ok(answer(&snapshot, snapshot.diagnostics.clone()))
}

/// Reports diagnostics from one Segment Heap root.
///
/// The heap is selected before walking and before diagnostic shapes generalise addresses, so
/// category totals and examples both describe only this root. Use [`diagnostics`] for all roots.
pub fn diagnostics_for_heap(
    engine: &DebugEngine,
    heap: u64,
    walk: impl Into<HeapWalk>,
) -> Result<HeapAnswer<HeapDiagnosticReport>, HeapQueryError> {
    let snapshot = prepare_for_heap(engine, Some(heap), walk.into())?;
    Ok(answer(&snapshot, snapshot.diagnostics.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allocation(heap: u64, backend: HeapBackend, address: u64, capacity: u64) -> HeapAllocation {
        HeapAllocation {
            heap,
            backend,
            state: HeapState::Allocated,
            header_address: address,
            user_address: address + 0x10,
            capacity,
            requested_size: None,
            subsegment: Some(heap + 0x1000),
            size_class: capacity as u32,
        }
    }

    #[test]
    fn test_segment_and_nt_signatures_are_not_interchangeable() {
        assert_ne!(SEGMENT_HEAP_SIGNATURE, NT_HEAP_SIGNATURE);
        assert_eq!(SEGMENT_HEAP_SIGNATURE, 0xddee_ddee);
        assert_eq!(NT_HEAP_SIGNATURE, 0xeeff_eeff);
    }

    #[test]
    fn test_root_classification_skips_nt_unknown_unreadable_and_ambiguous_roots() {
        assert_eq!(
            classify_root(Ok(SEGMENT_HEAP_SIGNATURE), Ok(0)),
            (HeapKind::Segment, None)
        );
        assert_eq!(classify_root(Ok(0), Ok(NT_HEAP_SIGNATURE)).0, HeapKind::Nt);
        assert_eq!(classify_root(Ok(0), Ok(0)).0, HeapKind::Unknown);
        assert_eq!(
            classify_root(Err("first read".into()), Err("second read".into())).0,
            HeapKind::Unreadable
        );
        assert_eq!(
            classify_root(Ok(SEGMENT_HEAP_SIGNATURE), Ok(NT_HEAP_SIGNATURE)).0,
            HeapKind::Unknown,
            "conflicting structural evidence must fail closed"
        );
    }

    #[test]
    fn test_user_pointer_bounds_reject_null_kernel_and_noncanonical_roots() {
        assert!(user_pointer(0x1_0000));
        assert!(user_pointer(0x0000_7fff_ffff_ffff));
        assert!(!user_pointer(0));
        assert!(!user_pointer(0xffff_8000_0000_0000));
        assert!(!user_pointer(0x0000_8000_0000_0000));
    }

    #[test]
    fn test_snapshot_identity_separates_current_processes() {
        let image = KernelImage {
            base: 0x0000_7ffb_0000_0000,
            size: 0x20_0000,
            timestamp: 0x1234_5678,
            checksum: 0x9876,
        };
        let key = |process_system_id, heap| SnapshotKey {
            target: 7,
            process_system_id,
            peb: 0x0000_7fff_0000_1000,
            image,
            generation: 3,
            heap,
        };

        assert_ne!(
            key(100, None),
            key(200, None),
            "two current processes may share virtual addresses but never a heap snapshot"
        );
        assert_eq!(key(100, None), key(100, None));
    }

    #[test]
    fn test_snapshot_identity_separates_scoped_diagnostic_walks() {
        let image = KernelImage {
            base: 0x0000_7ffb_0000_0000,
            size: 0x20_0000,
            timestamp: 0x1234_5678,
            checksum: 0x9876,
        };
        let key = |heap| SnapshotKey {
            target: 7,
            process_system_id: 100,
            peb: 0x0000_7fff_0000_1000,
            image,
            generation: 3,
            heap,
        };

        assert_ne!(key(None), key(Some(0x10000)));
        assert_ne!(key(Some(0x10000)), key(Some(0x20000)));
    }

    #[test]
    fn test_user_allocation_contains_header_and_payload_addresses() {
        let allocation = allocation(0x1000, HeapBackend::Vs, 0x2000, 0x40);
        assert!(allocation.contains(0x2000));
        assert!(allocation.contains(0x204f));
        assert!(!allocation.contains(0x2050));
    }

    #[test]
    fn test_scope_lists_unsupported_heaps_explicitly() {
        let roots = vec![
            HeapRoot {
                index: 0,
                address: 1,
                kind: HeapKind::Segment,
                supported: true,
                reason: None,
            },
            HeapRoot {
                index: 1,
                address: 2,
                kind: HeapKind::Nt,
                supported: false,
                reason: Some("classic".into()),
            },
            HeapRoot {
                index: 2,
                address: 3,
                kind: HeapKind::Unknown,
                supported: false,
                reason: Some("unknown".into()),
            },
            HeapRoot {
                index: 3,
                address: 4,
                kind: HeapKind::Unreadable,
                supported: false,
                reason: Some("unreadable".into()),
            },
        ];
        let scope = scope_of(&roots);
        assert_eq!(scope.segment_heaps_walked, vec![1]);
        assert_eq!(scope.nt_heaps_skipped, vec![2]);
        assert_eq!(scope.unknown_heaps_skipped, vec![3]);
        assert_eq!(scope.unreadable_heaps_skipped, vec![4]);
    }

    #[test]
    fn test_scoped_diagnostics_select_one_heap_before_the_walk() {
        let roots = vec![
            HeapRoot {
                index: 0,
                address: 0x10000,
                kind: HeapKind::Segment,
                supported: true,
                reason: None,
            },
            HeapRoot {
                index: 1,
                address: 0x20000,
                kind: HeapKind::Segment,
                supported: true,
                reason: None,
            },
        ];
        let scope = scope_for(&roots, Some(0x20000), true).unwrap();

        assert_eq!(scope.segment_heaps_walked, vec![0x20000]);
    }

    #[test]
    fn test_scoped_diagnostics_reject_unsupported_or_missing_heap() {
        let roots = vec![
            HeapRoot {
                index: 0,
                address: 0x10000,
                kind: HeapKind::Nt,
                supported: false,
                reason: Some("classic".into()),
            },
            HeapRoot {
                index: 1,
                address: 0x20000,
                kind: HeapKind::Unreadable,
                supported: false,
                reason: Some("unreadable".into()),
            },
        ];

        for heap in [0x10000, 0x20000, 0x30000] {
            assert!(matches!(
                scope_for(&roots, Some(heap), true),
                Err(HeapQueryError::UnsupportedHeap { heap: rejected }) if rejected == heap
            ));
        }
    }

    #[test]
    fn test_scoped_diagnostics_leave_unseen_heap_unknown_when_enumeration_expires() {
        let scope = scope_for(&[], Some(0x30000), false).unwrap();

        assert!(scope.segment_heaps_walked.is_empty());
    }

    #[test]
    fn test_root_enumeration_deadline_reports_partial_coverage() {
        let snapshot = truncated_root_snapshot(3, Some(12), Some(Duration::from_secs(2)));
        let (allocations, walk, diagnostics) = from_pool_snapshot(snapshot);

        assert!(allocations.is_empty());
        assert_eq!(walk.coverage, WalkCoverage::BudgetExpired);
        assert_eq!(walk.diagnostic_count, 1);
        assert_eq!(diagnostics.examples.len(), 1);
        assert!(diagnostics.examples[0].contains("2s budget"));
        assert!(diagnostics.examples[0].contains("3 of 12 PEB heap roots classified"));
        assert!(diagnostics.examples[0].contains("unknown, not absent"));
    }

    /// A process for root discovery, byte by byte, so a fixture can be laid out the way a
    /// measurement found one and a test can then break exactly one thing in it.
    #[derive(Default)]
    struct Process {
        bytes: HashMap<u64, u8>,
        interrupted: bool,
    }

    impl Process {
        fn put(&mut self, address: u64, bytes: &[u8]) {
            for (offset, &byte) in bytes.iter().enumerate() {
                self.bytes.insert(address + offset as u64, byte);
            }
        }

        fn put_u64(&mut self, address: u64, value: u64) {
            self.put(address, &value.to_le_bytes());
        }

        fn forget(&mut self, address: u64, size: u64) {
            for offset in 0..size {
                self.bytes.remove(&(address + offset));
            }
        }

        /// A heap of `kind` naming `entry` as its place on the list, at the measured offsets.
        fn heap(&mut self, address: u64, kind: HeapKind, entry: u64) {
            let layout = measured_layout();
            self.put(address, &[0; 0x190]);
            let (signature, named_at) = match kind {
                HeapKind::Segment => (
                    (layout.segment_signature, SEGMENT_HEAP_SIGNATURE),
                    layout.segment_entry,
                ),
                _ => ((layout.nt_signature, NT_HEAP_SIGNATURE), layout.nt_entry),
            };
            self.put(address + signature.0, &signature.1.to_le_bytes());
            self.put_u64(address + named_at.unwrap(), entry);
        }
    }

    impl RootMemory for Process {
        fn read(&self, address: u64, size: usize) -> Result<Vec<u8>, DbgEngError> {
            (0..size)
                .map(|offset| {
                    self.bytes.get(&(address + offset as u64)).copied().ok_or(
                        DbgEngError::ShortRead {
                            address,
                            requested: size,
                            actual: offset,
                        },
                    )
                })
                .collect()
        }

        fn interrupted(&self) -> Result<bool, DbgEngError> {
            Ok(self.interrupted)
        }
    }

    // The process measured on 2026-09-22: `user_heap_smoke`'s child on ARM64 26100.1, stopped at
    // its `DebugBreak` after `HeapCreate(HEAP_CREATE_SEGMENT_HEAP)`. The addresses and offsets
    // are that process's own.
    const PEB: u64 = 0x3e_0cbf_f000;
    /// `ntdll!RtlpPebHeapListStaticBuffer`, which is what the PEB's `ProcessHeaps` points at.
    const PEB_ARRAY: u64 = 0x7ffe_77e9_d5a0;
    /// The list head: a static in `ntdll`'s data with no public symbol on this build.
    const LIST_HEAD: u64 = 0x7ffe_77e9_3440;
    const NTDLL: Range<u64> = 0x7ffe_77b0_0000..0x7ffe_77f0_0000;
    const PROCESS_HEAP: u64 = 0x1a0_4700_0000;
    const NT_HEAP: u64 = 0x1a0_4619_0000;
    /// The heap the child created, which the PEB does not name and `GetProcessHeaps` returns.
    const CREATED_HEAP: u64 = 0x1a0_4740_0000;
    const ENTRIES: [u64; 3] = [0x1a0_4710_2040, 0x1a0_4711_3100, 0x1a0_4713_6920];

    fn measured_layout() -> RootLayout {
        RootLayout {
            number_of_heaps: 0xe8,
            process_heaps: 0xf0,
            segment_signature: 0x10,
            nt_signature: 0x98,
            segment_entry: Some(0x38),
            nt_entry: Some(0x188),
        }
    }

    fn measured_process() -> Process {
        let mut process = Process::default();
        process.put(PEB + 0xe8, &1u32.to_le_bytes());
        process.put_u64(PEB + 0xf0, PEB_ARRAY);
        process.put_u64(PEB_ARRAY, PROCESS_HEAP);
        let heaps = [
            (PROCESS_HEAP, HeapKind::Segment),
            (NT_HEAP, HeapKind::Nt),
            (CREATED_HEAP, HeapKind::Segment),
        ];
        for (&(heap, kind), &entry) in heaps.iter().zip(&ENTRIES) {
            process.heap(heap, kind, entry);
            process.put_u64(entry + LIST_ENTRY_HEAP, heap);
        }
        let ring = [LIST_HEAD, ENTRIES[0], ENTRIES[1], ENTRIES[2]];
        for (position, &entry) in ring.iter().enumerate() {
            process.put_u64(entry, ring[(position + 1) % ring.len()]);
            process.put_u64(entry + 8, ring[(position + ring.len() - 1) % ring.len()]);
        }
        process.put_u64(LIST_HEAD + LIST_ENTRY_HEAP, 0);
        process
    }

    fn enumerate(process: &Process, layout: RootLayout, ntdll: Range<u64>) -> RootEnumeration {
        enumerate_roots(process, &layout, PEB, ntdll, None).unwrap()
    }

    fn addresses(found: &RootEnumeration) -> Vec<u64> {
        found.roots.iter().map(|root| root.address).collect()
    }

    fn unseen(found: &RootEnumeration) -> &str {
        assert!(!found.saw_every_root());
        let unseen = found
            .unseen
            .as_deref()
            .expect("an enumeration that could not see every root said nothing about it");
        assert!(unseen.contains("unknown, not absent"), "{unseen}");
        unseen
    }

    /// The item this exists for (`windbg-mcp` `FOLLOWUPS.md` item 79): the PEB names one heap,
    /// the process has three, and a heap from `HeapCreate` is among the two it does not name.
    #[test]
    fn test_every_heap_on_ntdlls_list_is_a_root_not_only_the_one_the_peb_names() {
        let found = enumerate(&measured_process(), measured_layout(), NTDLL);

        assert_eq!(addresses(&found), [PROCESS_HEAP, NT_HEAP, CREATED_HEAP]);
        let kinds: Vec<_> = found.roots.iter().map(|root| root.kind).collect();
        assert_eq!(kinds, [HeapKind::Segment, HeapKind::Nt, HeapKind::Segment]);
        let indices: Vec<_> = found.roots.iter().map(|root| root.index).collect();
        assert_eq!(
            indices,
            [0, 1, 2],
            "an index is a position in the list's own order"
        );
        assert!(found.saw_every_root(), "{:?}", found.unseen);
        assert_eq!(
            found.total, None,
            "a list has no count to report before it is walked"
        );
    }

    /// A build whose process heap names no entry keeps no list, and gets exactly the answer every
    /// release before this one gave it — the PEB, with its count, null rows included.
    #[test]
    fn test_a_build_keeping_no_list_answers_from_the_peb_as_before() {
        let mut named = measured_process();
        named.put(PEB + 0xe8, &2u32.to_le_bytes());
        named.put_u64(PEB_ARRAY + 8, 0);
        let no_field = RootLayout {
            segment_entry: None,
            nt_entry: None,
            ..measured_layout()
        };
        let mut null_entry = measured_process();
        null_entry.put(PEB + 0xe8, &2u32.to_le_bytes());
        null_entry.put_u64(PEB_ARRAY + 8, 0);
        null_entry.put_u64(PROCESS_HEAP + 0x38, 0);

        for found in [
            enumerate(&named, no_field, NTDLL),
            enumerate(&null_entry, measured_layout(), NTDLL),
        ] {
            assert_eq!(addresses(&found), [PROCESS_HEAP, 0]);
            assert_eq!(found.roots[1].reason.as_deref(), Some("null heap root"));
            assert_eq!(found.total, Some(2));
            assert!(found.saw_every_root(), "{:?}", found.unseen);
        }
    }

    /// An entry is believed only if its heap names it back — the check that makes reading an
    /// untyped offset safe. What the walk listed before the break stays listed.
    #[test]
    fn test_an_entry_its_heap_does_not_name_back_leaves_the_rest_unseen() {
        let mut process = measured_process();
        process.put_u64(NT_HEAP + 0x188, 0x1a0_4799_0000);

        let found = enumerate(&process, measured_layout(), NTDLL);

        assert_eq!(addresses(&found), [PROCESS_HEAP]);
        let unseen = unseen(&found);
        assert!(unseen.contains(&format!("{:#x}", ENTRIES[1])), "{unseen}");
    }

    #[test]
    fn test_an_entry_that_does_not_link_back_leaves_the_rest_unseen() {
        let mut process = measured_process();
        process.put_u64(ENTRIES[2] + 8, ENTRIES[0]);

        let found = enumerate(&process, measured_layout(), NTDLL);

        assert_eq!(addresses(&found), [PROCESS_HEAP, NT_HEAP]);
        unseen(&found);
    }

    #[test]
    fn test_an_unreadable_entry_leaves_the_rest_unseen() {
        let mut process = measured_process();
        process.forget(ENTRIES[1], 0x18);

        let found = enumerate(&process, measured_layout(), NTDLL);

        assert_eq!(addresses(&found), [PROCESS_HEAP]);
        unseen(&found);
    }

    #[test]
    fn test_a_list_that_loops_short_of_where_it_started_is_unseen() {
        let mut process = measured_process();
        process.put_u64(ENTRIES[2], ENTRIES[1]);

        let found = enumerate(&process, measured_layout(), NTDLL);

        assert_eq!(addresses(&found), [PROCESS_HEAP, NT_HEAP, CREATED_HEAP]);
        unseen(&found);
    }

    /// Exactly one entry is the head, and it is the one inside `ntdll`. A ring read with the
    /// wrong image — none of it inside, or all of it — is not the list this walker knows.
    #[test]
    fn test_a_list_is_trusted_only_with_exactly_one_head_inside_ntdll() {
        let outside = enumerate(&measured_process(), measured_layout(), 0..0x1000);
        assert_eq!(addresses(&outside), [PROCESS_HEAP, NT_HEAP, CREATED_HEAP]);
        unseen(&outside);

        let everything = enumerate(&measured_process(), measured_layout(), 0..u64::MAX);
        assert_eq!(
            addresses(&everything),
            [PROCESS_HEAP],
            "no entry was a heap's, so only the PEB's root is known"
        );
        unseen(&everything);
    }

    /// A process heap that cannot be read cannot say whether there is a list, so what the PEB
    /// does not name is unknown — on a dump without heap pages, that is every other heap.
    #[test]
    fn test_a_process_heap_that_cannot_be_read_leaves_the_rest_unseen() {
        let mut process = measured_process();
        process.forget(PROCESS_HEAP, 0x190);

        let found = enumerate(&process, measured_layout(), NTDLL);

        assert_eq!(addresses(&found), [PROCESS_HEAP]);
        assert_eq!(found.roots[0].kind, HeapKind::Unreadable);
        assert!(unseen(&found).contains("process heap"));
    }

    #[test]
    fn test_root_enumeration_honours_an_interrupt_and_a_deadline() {
        let mut process = measured_process();
        process.interrupted = true;
        assert!(matches!(
            enumerate_roots(&process, &measured_layout(), PEB, NTDLL, None),
            Err(HeapQueryError::Interrupted)
        ));

        let found = enumerate_roots(
            &measured_process(),
            &measured_layout(),
            PEB,
            NTDLL,
            Some(Instant::now()),
        )
        .unwrap();
        assert!(found.budget_expired);
        assert!(!found.saw_every_root());
    }

    /// Roots enumeration could not see make a walk of every root it did see partial, rather than
    /// letting it report itself complete.
    #[test]
    fn test_unseen_roots_make_a_complete_walk_partial() {
        let complete = || PoolSnapshot {
            complete: true,
            ..PoolSnapshot::default()
        };

        let (_, walk, _) = from_pool_snapshot(with_unseen_roots(complete(), None));
        assert_eq!(walk.coverage, WalkCoverage::Complete);

        let unseen = "ntdll's heap list could not be followed; unknown, not absent".to_string();
        let (_, walk, diagnostics) =
            from_pool_snapshot(with_unseen_roots(complete(), Some(unseen.clone())));
        assert_eq!(walk.coverage, WalkCoverage::Partial);
        assert_eq!(diagnostics.examples, [unseen]);
    }

    #[test]
    fn test_census_key_separates_heap_backend_state_and_size_class() {
        let left = allocation(1, HeapBackend::Lfh, 0x1000, 0x20);
        let mut right = allocation(2, HeapBackend::Lfh, 0x2000, 0x20);
        right.state = HeapState::ReusableFree;
        assert_ne!(
            (left.heap, left.backend, left.state, left.size_class),
            (right.heap, right.backend, right.state, right.size_class)
        );
    }

    #[test]
    fn test_neighbourhood_requires_contiguity_and_same_allocator_identity() {
        let previous = allocation(1, HeapBackend::Vs, 0x2000, 0x20);
        let current = allocation(1, HeapBackend::Vs, previous.end(), 0x20);
        let next = allocation(1, HeapBackend::Vs, current.end(), 0x20);
        let found = neighbourhood_at(
            &[previous.clone(), current.clone(), next.clone()],
            current.user_address + 3,
        )
        .unwrap();
        assert_eq!(found.offset, 3);
        assert_eq!(found.previous, Some(previous));
        assert_eq!(found.next, Some(next));

        let header =
            neighbourhood_at(std::slice::from_ref(&current), current.header_address).unwrap();
        assert_eq!(header.offset, -0x10);

        let other_heap = allocation(2, HeapBackend::Vs, current.end(), 0x20);
        let found = neighbourhood_at(&[current.clone(), other_heap], current.user_address).unwrap();
        assert!(found.next.is_none(), "neighbours may not cross a heap root");
    }

    #[test]
    fn test_census_totals_and_sorts_heaviest_first() {
        let allocations = vec![
            allocation(1, HeapBackend::Lfh, 0x1000, 0x20),
            allocation(1, HeapBackend::Lfh, 0x2000, 0x20),
            allocation(2, HeapBackend::Large, 0x3000, 0x1000),
        ];
        let rows = census_of(&allocations);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].backend, HeapBackend::Large);
        assert_eq!(rows[0].total_capacity, 0x1000);
        assert_eq!(rows[1].chunks, 2);
        assert_eq!(rows[1].total_capacity, 0x40);
    }

    /// A TEB naming a 32-bit one beside it is refused, whichever side of it that one is, and a
    /// TEB that cannot be read is refused too rather than taken for a native one.
    ///
    /// The offsets are the ones measured on ARM64 26100.1 (2026-09-23): `_TEB.WowTebOffset` at
    /// `+0x180c`, holding `+0x2000` in a WoW64 process at both of its launch breaks and zero in
    /// an emulated x64 one.
    #[test]
    fn test_a_teb_with_a_32_bit_teb_beside_it_is_refused() {
        const TEB: u64 = 0x2fd_e000;
        const FIELD: u64 = 0x180c;
        let with = |value: i32| {
            let mut process = Process::default();
            process.put(TEB + FIELD, &value.to_le_bytes());
            wow_teb_offset(&process, TEB, FIELD)
        };

        assert!(with(0).is_ok());
        assert!(matches!(
            with(0x2000),
            Err(HeapQueryError::Wow64Process {
                wow_teb_offset: 0x2000
            })
        ));
        assert!(matches!(
            with(-0x2000),
            Err(HeapQueryError::Wow64Process {
                wow_teb_offset: -0x2000
            })
        ));
        assert!(matches!(
            wow_teb_offset(&Process::default(), TEB, FIELD),
            Err(HeapQueryError::InvalidTeb(_))
        ));
        assert!(matches!(
            wow_teb_offset(&Process::default(), 0, FIELD),
            Err(HeapQueryError::InvalidTeb(_))
        ));
    }
}
