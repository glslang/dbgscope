//! Opt-in live smoke helper for the typed user Segment Heap walker, on x64 and ARM64.
//!
//! `cargo run --example user_heap_smoke` launches a child under DbgEng. The child creates a
//! Segment Heap, makes allocations spanning the four backends, walks the heap itself with
//! `HeapWalk`, and breaks in; the controller lists roots and checks the walker against both —
//! each witness pointer is covered by an allocation of the backend it was sized for, and the
//! allocated chunks on the created heap are exactly the blocks `HeapWalk` calls busy. It then
//! repeats both checks over a full-memory dump of the same process. This requires DbgEng and
//! the matching `ntdll` PDB. Set `WIN_KEXP_USER_HEAP_SYMBOLS` to a WinDbg symbol path such as
//! `srv*C:\ProgramData\dbg\sym*https://msdl.microsoft.com/download/symbols`; when it is unset,
//! the helper uses `_NT_SYMBOL_PATH` and then that public-server path.

use std::ffi::CString;
use std::hint::black_box;
use std::time::Duration;

use dbgscope::dbgeng::DebugEngine;
use dbgscope::heap::{self, HeapAllocation, HeapBackend, HeapKind, HeapState, HeapWalk};
use windows::Win32::System::Diagnostics::Debug::{DebugBreak, OutputDebugStringA};
use windows::Win32::System::Memory::{
    HEAP_FLAGS, HeapAlloc, HeapCreate, HeapLock, HeapUnlock, HeapWalk as OsHeapWalk,
    PROCESS_HEAP_ENTRY,
};
use windows::core::PCSTR;

const SEGMENT_HEAP_FLAG: HEAP_FLAGS = HEAP_FLAGS(0x100);
/// `PROCESS_HEAP_ENTRY_BUSY`: the entry is an allocated block, not a region or a free one.
const HEAP_ENTRY_BUSY: u16 = 0x4;

fn emit(message: String) {
    // A debugger captures OutputDebugString without needing to inherit the target's console.
    let message = CString::new(message).unwrap();
    unsafe { OutputDebugStringA(PCSTR(message.as_ptr().cast())) };
}

fn target() {
    let heap = unsafe { HeapCreate(SEGMENT_HEAP_FLAG, 0, 0) }.expect("create Segment Heap");
    let mut keep_alive = Vec::new();
    // Exercise the 0x20 bucket until it transitions to LFH, then retain the last slot as the
    // LFH witness. The other three sizes sit well inside their backend's range rather than at
    // an edge, because a process started under a debugger gets the debug heap, whose tail bytes
    // move a request at an edge into the next backend: measured on ARM64 26100.1 (2026-09-23),
    // VS served up to 0x1fff0 and not 0x20000, the page-range backend 0x20000 to 0x3f0000, and
    // Large 0x7f0000 and up. A 0x4000 request is VS, which is what the `segment` witness used to
    // be and why this example failed on the first build it reached.
    for _ in 0..32 {
        let pointer = unsafe { HeapAlloc(heap, HEAP_FLAGS(0), 0x20) } as u64;
        assert_ne!(pointer, 0, "allocate 0x20");
        keep_alive.push(pointer);
    }
    let mut allocations = vec![("lfh", *keep_alive.last().unwrap())];
    allocations.extend(
        [
            ("vs", 0x400usize),
            ("segment", 0x4_0000),
            ("large", 0x80_0000),
        ]
        .into_iter()
        .map(|(backend, size)| {
            let pointer = unsafe { HeapAlloc(heap, HEAP_FLAGS(0), size) } as u64;
            assert_ne!(pointer, 0, "allocate {size:#x}");
            keep_alive.push(pointer);
            (backend, pointer)
        }),
    );
    emit(format!(
        "WIN_KEXP_HEAP={:#x} ALLOCS={}\n",
        heap.0 as usize,
        allocations
            .iter()
            .map(|(backend, pointer)| format!("{backend}:{pointer:#x}"))
            .collect::<Vec<_>>()
            .join(",")
    ));

    // The heap's own account of itself, taken last so nothing allocates on it afterwards. The
    // buffer is reserved up front because it lives on the process heap, which is a different
    // heap, but growing it mid-walk would still be an allocation between two `HeapWalk` calls.
    let mut busy = Vec::with_capacity(4096);
    unsafe { HeapLock(heap) }.expect("lock heap");
    let mut entry = PROCESS_HEAP_ENTRY::default();
    while unsafe { OsHeapWalk(heap, &mut entry) }.is_ok() {
        if entry.wFlags & HEAP_ENTRY_BUSY != 0 {
            assert!(
                busy.len() < busy.capacity(),
                "more busy blocks than reserved"
            );
            busy.push((entry.lpData as u64, u64::from(entry.cbData)));
        }
    }
    unsafe { HeapUnlock(heap) }.expect("unlock heap");
    for chunk in busy.chunks(32) {
        emit(format!(
            "WIN_KEXP_BUSY={}\n",
            chunk
                .iter()
                .map(|(data, size)| format!("{data:#x}:{size:#x}"))
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    black_box((&heap, &keep_alive));
    unsafe { DebugBreak() };
    std::thread::sleep(Duration::from_secs(30));
}

fn parse_hex(value: &str) -> u64 {
    u64::from_str_radix(value.trim().trim_start_matches("0x"), 16).expect("malformed witness")
}

fn expected(output: &str) -> (u64, Vec<(HeapBackend, u64)>) {
    let marker = output
        .lines()
        .find_map(|line| line.split_once("WIN_KEXP_HEAP=").map(|(_, tail)| tail))
        .expect("the target emitted no heap witness");
    let (heap, allocations) = marker
        .split_once(" ALLOCS=")
        .expect("malformed heap witness");
    let allocations = allocations
        .trim()
        .split(',')
        .map(|entry| {
            let (backend, address) = entry.split_once(':').expect("malformed allocation witness");
            let backend = match backend {
                "lfh" => HeapBackend::Lfh,
                "vs" => HeapBackend::Vs,
                "segment" => HeapBackend::Segment,
                "large" => HeapBackend::Large,
                other => panic!("unknown witness backend {other}"),
            };
            (backend, parse_hex(address))
        })
        .collect();
    (parse_hex(heap), allocations)
}

/// The busy blocks `HeapWalk` reported, as `(data, size)`.
fn busy_blocks(output: &str) -> Vec<(u64, u64)> {
    output
        .lines()
        .filter_map(|line| line.split_once("WIN_KEXP_BUSY=").map(|(_, tail)| tail))
        .flat_map(|tail| tail.trim().split(','))
        .map(|entry| {
            let (data, size) = entry.split_once(':').expect("malformed busy block");
            (parse_hex(data), parse_hex(size))
        })
        .collect()
}

fn verify(heap: u64, expected: &[(HeapBackend, u64)], allocations: &[HeapAllocation], phase: &str) {
    for &(backend, pointer) in expected {
        let allocation = allocations
            .iter()
            .find(|allocation| allocation.heap == heap && allocation.contains(pointer))
            .unwrap_or_else(|| panic!("{phase}: pointer {pointer:#x} is not covered"));
        assert_eq!(
            allocation.backend, backend,
            "{phase}: pointer {pointer:#x} used an unexpected backend"
        );
    }
}

/// The allocated chunks on `heap` and the blocks `HeapWalk` called busy are the same set.
///
/// Both directions, because the failure this was added for went both ways at once: reading an
/// LFH block bitmap in the wrong arrangement on ARM64 26100.1 reported free slots as allocated
/// and allocated ones as free, eight and nine of them in one 62-block subsegment, while every
/// witness above still passed.
fn agree_with_heap_walk(
    heap: u64,
    busy: &[(u64, u64)],
    allocations: &[HeapAllocation],
    phase: &str,
) {
    let allocated: Vec<_> = allocations
        .iter()
        .filter(|allocation| allocation.heap == heap && allocation.state == HeapState::Allocated)
        .collect();
    let holds = |allocation: &HeapAllocation, (data, size): (u64, u64)| {
        allocation.user_address <= data && data + size <= allocation.end()
    };
    let undecoded: Vec<_> = busy
        .iter()
        .filter(|&&block| !allocated.iter().any(|allocation| holds(allocation, block)))
        .collect();
    let unbusy: Vec<_> = allocated
        .iter()
        .filter(|allocation| !busy.iter().any(|&block| holds(allocation, block)))
        .collect();
    assert!(
        undecoded.is_empty() && unbusy.is_empty(),
        "{phase}: the walker and HeapWalk disagree about {heap:#x} — busy blocks not decoded as \
         allocated: {undecoded:x?}; allocated chunks HeapWalk does not call busy: {unbusy:#?}"
    );
}

fn load_ntdll_symbols(engine: &DebugEngine) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("{}", engine.execute_command(".reload /f ntdll.dll")?);
    eprintln!("{}", engine.execute_command("lm m ntdll")?);
    Ok(())
}

fn controller() -> Result<(), Box<dyn std::error::Error>> {
    let executable = std::env::current_exe()?;
    let engine = DebugEngine::new();
    let symbol_path = std::env::var("WIN_KEXP_USER_HEAP_SYMBOLS")
        .or_else(|_| std::env::var("_NT_SYMBOL_PATH"))
        .unwrap_or_else(|_| {
            "srv*C:\\ProgramData\\dbg\\sym*https://msdl.microsoft.com/download/symbols".into()
        });
    engine.set_symbol_path(&symbol_path)?;
    engine.launch_process(&format!("\"{}\" --target", executable.display()))?;
    let run = engine.execute_and_wait("g", 30_000)?;
    let (heap, witnesses) = expected(&run.output);
    let busy = busy_blocks(&run.output);
    assert!(!busy.is_empty(), "the target reported no busy blocks");
    load_ntdll_symbols(&engine)?;
    let listed = heap::list(
        &engine,
        HeapWalk::refreshed().within(Duration::from_secs(30)),
    )?;
    // The heap the child created, not merely *a* Segment Heap: the process heap can be one too
    // (it is on ARM64 26100.1), so the weaker check can pass on a listing that never reached the
    // heap this example exists to verify.
    assert!(
        listed
            .found
            .iter()
            .any(|root| root.address == heap && root.kind == HeapKind::Segment),
        "the Segment Heap the child created ({heap:#x}) is not among the roots: {:?}",
        listed.found
    );
    let allocations = heap::allocations(&engine, HeapWalk::cached())?;
    verify(heap, &witnesses, &allocations.found, "live target");
    agree_with_heap_walk(heap, &busy, &allocations.found, "live target");
    eprintln!(
        "{} roots, {} chunks, {} busy blocks agreed, coverage {:?}, layout {} ({})",
        listed.found.len(),
        allocations.found.len(),
        busy.len(),
        allocations.walk.coverage,
        allocations.layout.fingerprint,
        allocations.layout.semantic_family.as_str()
    );

    let dump = std::env::temp_dir().join(format!("dbgscope-user-heap-{}.dmp", std::process::id()));
    engine.execute_command(&format!(".dump /ma \"{}\"", dump.display()))?;
    engine.end_session()?;
    heap::invalidate_caches();
    engine.open_dump(&dump.display().to_string())?;
    engine.wait_for_event(30_000)?;
    load_ntdll_symbols(&engine)?;
    let from_dump = heap::allocations(
        &engine,
        HeapWalk::refreshed().within(Duration::from_secs(30)),
    )?;
    verify(heap, &witnesses, &from_dump.found, "full-memory dump");
    agree_with_heap_walk(heap, &busy, &from_dump.found, "full-memory dump");
    engine.end_session()?;
    std::fs::remove_file(&dump)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().any(|argument| argument == "--target") {
        target();
        Ok(())
    } else {
        controller()
    }
}
