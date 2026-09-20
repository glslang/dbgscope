# Tracing an accepted exit interrupt that does not unwind KDNET

This is a diagnostic checkpoint from 2026-09-20, not a cancellation implementation. It follows
the [live timeout and manual recovery experiment](kernel-attach-probe.md#live-timeout-experiment).
That guest had recovered; these follow-up runs did not attach to it or use its credentials.

## Question and scope

The live probe synchronized, exceeded its 60-second attach deadline, and remained inside the
wait. A later explicit break froze the target without delivering a stop to that controller.
Native KD subsequently collected the pending stop and recovered the guest. The original logs
did not record the watchdog's `SetInterrupt` result, so they could not distinguish a rejected
request from an accepted request that did not unwind the wait.

The source arms `Watchdog::arm` around `WaitForEvent(INFINITE)`. For `Bound::WatchdogExit`, its
closure calls `SetInterrupt(DEBUG_INTERRUPT_EXIT)` and discards the result. The watchdog repeats
every 200 ms after the deadline. The engine thread cannot restore the attach observer or classify
the wait until that native call to `WaitForEvent` returns. A client-side timeout is not that return.

Microsoft documents that
[EXIT interrupts force an active wait to return without forcing a target break](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nf-dbgeng-idebugcontrol-setinterrupt),
and that [live-kernel waits require an infinite timeout](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nf-dbgeng-idebugcontrol-waitforevent).
Neither an accepted interrupt nor the library's local-process test is evidence that a particular
KDNET attach has unwound. The measurements below examine that distinction in this engine build.

## Engine identity

- AMD64 DbgEng `10.0.29617.1000`, loaded beside the diagnostic executable.
- DLL SHA-256: `4352756685E7325288E54ABB3281E768637987517BE8575EC4450E4B4421842F`.
- Requested PDB identity: `dbgeng.pdb/0CEEC4D9B35CD3847CDB119BBFCFD90C1`.
- Microsoft's symbol server returned 404 for that identity during this investigation. Native
  addresses below were derived from the COM call and image disassembly, not guessed symbol names.

The diagnostic executable retained the real library wait and 60-second watchdog. A local CDB
launched it in `timeout` mode with an unused UDP port, the deliberately synthetic key `1.2.3.4`,
and no target address. No announcement or manual ACTIVE break was supplied. CDB's breakpoints
observed the caller and native implementation; no engine state was patched to force cancellation.
The probe's reader control file remained absent throughout.

## What the local trace established

In each of the first two runs, three consecutive native calls received flag `2` (EXIT) and
returned `0x00000000` (`S_OK`). The engine thread remained inside `WaitForEvent`, through KDNET
and `WS2_32!recvfrom` into an operating-system wait. This rules out a watchdog that never fired,
a rejected request, or an engine thread stuck joining the watchdog **in these local runs**.

The second run also observed the internal branch and flags:

```text
call 1: requested=2, internal_before=0x001, state=0x100, target_byte=0
        native branch sets bit 11
        HRESULT=0, internal_after=0x801
call 2: requested=2, internal_before=0x801, same branch, HRESULT=0, after=0x801
call 3: requested=2, internal_before=0x801, same branch, HRESULT=0, after=0x801
```

Thus EXIT was not silently rerouted to the implementation's passive-interrupt branch. The exit
bit was set and persisted across these observations. These three-call runs ended at roughly
61 seconds by terminating only the synthetic, unconnected local probe; by themselves they do
not distinguish a delayed socket return from an indefinitely blocked wait.

A corrected longer run observed **150** native EXIT returns, all `S_OK`, with the flags still
`0x801` at each return. Neither of the two instrumented exit-check sites below was reached with
that bit set, and the wrapper's native `WaitForEvent` return site was not reached. The final
engine-thread stack was still in `recvfrom`, below the synchronization-loop check. The outer
harness finished at 91.1447232 seconds with an explicit completion marker and CDB exit 0;
that exit code means the diagnostic completed, **not** that the attach wait returned. The
synthetic port was free afterward and no probe/debugger process remained.

An earlier extended attempt ended at its outer 180-second limit: the debugger command's bare
`450` was hexadecimal, so its intended call-count limit was wrong. Its partial log records
accepted EXIT requests but is not a completed diagnostic. The corrected run uses `0n150` and
checks its completion marker. Debugger stops perturb timing; neither elapsed value is a latency
benchmark or proof that the wait could never return.

## Where the exit check sits

These RVAs identify only the exact DLL above. They are evidence coordinates, **not an API or
patch recipe**. Do not reuse them against a different engine image.

| RVA | Observed role |
|---|---|
| `0x164990` | Native `SetInterrupt` implementation reached through `IDebugControl4` |
| `0x1649dd` | EXIT branch sets bit 11 of the internal flags word |
| `0x164a41` | Alternate/passive branch sets bit 12; not taken in the second run |
| `0xa3bfe8` | Internal flags word, observed changing from `0x1` to `0x801` |
| `0x177b24` | Transport synchronization loop tests the exit bit between backend calls |
| `0x1778e9` | Another receive-path exit-bit check |
| `0x5a8fb0` | Backend routine on the captured stack, below that synchronization-loop check |

The stack passed through the backend's receive calls at `0x5a9044` / `0x5a9085`. Its disassembly
contains socket retry handling; the stack snapshots landed deeper in `recvfrom`. This supports
an interruption-observation boundary below the outer exit check, corroborated by the longer
run's unvisited check sites. It does not yet prove the same boundary caused the earlier
**synchronized** hypervisor wait to hang.

## Reproducing the diagnostic safely

Use the retained `examples/kernel_attach_probe.rs` and a local user-mode debugger. This procedure
is for a synthetic, unconnected endpoint only; do not substitute a live profile into it.

1. Build the example and install matching engine DLLs beside it. Verify the loaded image and
   hash. Keep the installed MCP server and lab endpoint out of the test.
2. Choose an unused port and a deliberately synthetic key, with no target-address parameter.
   Set the connection only in the disposable child environment. Use a nonexistent control file.
3. Launch the example's `timeout` mode under CDB. Resolve the Rust `IDebugControl4::SetInterrupt`
   wrapper using the example's PDB; disassemble it to find the native call and its return.
   Wrapper offsets change when the executable is rebuilt.
4. Observe the flags at the call, the native function address, and the raw HRESULT immediately
   after return. Capture the engine-thread stack separately from the watchdog-thread stack.
5. For this exact engine image, observe the EXIT/passive branch and flags word above. Reading
   memory with the outer debugger is diagnostic observation, not another cross-thread DbgEng call.
6. Bound the outer harness and keep a completion marker distinct from CDB's exit code. Stopping
   an unconnected synthetic probe says nothing about safe termination of a live kernel controller.
   Use explicit decimal debugger counters (`0n150`), preserve output if the outer bound fires,
   and verify the disposable process and endpoint have actually gone away.

Raw logs remain local. Even user-mode tracing can reveal environment variables or debugger
connection text; using no real key prevents a redaction failure from exposing lab credentials.

## Comparison and remaining work

The focused local-process tests for exit-deadline attribution and missing-announcement callback
restoration both passed with the test executable beside the same engine DLL. A CDB module listing
independently confirmed `10.0.29617.1000` for the exit-deadline comparison. These tests exercise a
local `ping.exe` debuggee, not KDNET, and do not establish live-target liveness.

Do not replace EXIT with repeated ACTIVE interrupts, add another cross-thread DbgEng method,
or patch the private flags. The next live measurement must record the watchdog HRESULT, actual
exit branch, and engine-thread stack **after synchronization**, with one endpoint owner and a
prepared recovery path. Until then, the local mechanism must not be presented as the proven
cause of the synchronized hypervisor failure or as a safe automatic-recovery fix.

## Local evidence index

These filenames identify retained bench artifacts, not portable inputs or committed raw logs:

- `exit-watchdog-unconnected_0610_2026-09-20_07-41-48-431.log`: first three native EXIT returns,
  implementation disassembly, and engine/watchdog thread stacks.
- `exit-watchdog-unconnected_1354_2026-09-20_07-44-23-573.log`: EXIT branch and flags before/after.
- `exit-watchdog-unconnected_12c4_2026-09-20_07-47-12-475.log`: incomplete extended run, terminated
  at the harness's 180-second limit; hexadecimal counter mistake, not an attach result.
- `exit-watchdog-unconnected_1ac0_2026-09-20_07-52-19-635.log`: corrected 150-call run, no wait
  return or exit-check marker, final socket-wait stack and diagnostic completion marker.
- `exit-watchdog-image_06ac_2026-09-20_07-43-29-985.log` and
  `exit-watchdog-transport_22a4_2026-09-20_07-46-06-772.log`: static wait/transport disassembly.
- `exit-watchdog-user-test_0580_2026-09-20_07-48-17-107.log`: loaded engine version and passing
  local-process deadline test under CDB.
- `trace-exit-watchdog-unconnected.ps1` and `trace-exit-watchdog-unconnected.txt`: local bounded
  harness and debugger commands; executable-specific wrapper offsets must be re-derived.
