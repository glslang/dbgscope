# Tracing an accepted exit interrupt that does not unwind KDNET

This is a diagnostic checkpoint from 2026-09-20, not a cancellation implementation. It follows
the [live timeout and manual recovery experiment](kernel-attach-probe.md#live-timeout-experiment).
That guest had recovered. The initial follow-up runs used only a synthetic endpoint; the later
[synchronized measurement](#synchronized-live-measurement) used the responsive guest without
sending a target break.

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

The diagnostic executable retained the real library wait and 60-second watchdog. For the initial
local-only runs, CDB
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
| `0x5a5a90` | Packet receiver on the later synchronized stack |
| `0x5a3d10` | Receive helper called by that packet receiver |

The stack passed through the backend's receive calls at `0x5a9044` / `0x5a9085`. Its disassembly
contains socket retry handling; the stack snapshots landed deeper in `recvfrom`. This supports
an interruption-observation boundary below the outer exit check, corroborated by the longer
run's unvisited check sites. The later synchronized measurement below reached a different
backend receive path. Also, `0x1778e9` is a conditional check: some backend returns bypass it.
For example, the outer function handles `0x80020001` on a separate branch. An absent poll marker
alone therefore cannot establish that a backend call never returned. The live trace did not
capture backend return codes or identify which such branch was taken.

## Synchronized live measurement

A subsequent run used the same engine and the approved diagnostic executable against the live
hypervisor endpoint. Guest identity, boot time, advancing uptime, endpoint ownership, and binary
hashes were checked first. The example's `timeout` mode replaced the announcement observer with
its passive trace, deliberately suppressing the automatic ACTIVE interrupt. No manual break was
requested. The production wait and 60-second EXIT watchdog remained unchanged.

The probe reported transport synchronization before the deadline. Three consecutive native
EXIT calls then returned `S_OK`; each took the bit-11 branch, with the flags changing from `0x1`
to `0x801` on the first call and remaining set. Neither instrumented exit-check marker nor the
native wait-return marker appeared. After the third return, the outer user-mode debugger held
the local probe for inspection. The engine thread was still inside `WaitForEvent`, through
the packet receiver at `0x5a5a90`, helper `0x5a3d10`, and `WS2_32!recvfrom`. This differs from the
unconnected synchronization backend at `0x5a8fb0`.

This supplies native evidence of accepted-but-not-yet-acted-on EXIT requests **after reported
synchronization**, not merely on an unused endpoint. It excludes a missing watchdog or rejected
interrupt in this run. It does not prove an indefinite wait: the held checkpoint was only about
0.4 seconds after the first deadline request, and tracing perturbs timing. The earlier 143-second
synchronized wait is separate evidence without native HRESULT tracing. Nor does this no-break
measurement reproduce or fully explain the earlier freeze after ACTIVE.

Before reclaiming the probe, a fresh independent check found the same responsive guest and boot,
with uptime 65045.803 seconds. Only then did `q` in the **outer user-mode CDB** terminate its held
probe. This was not target `qd`, a returning attach wait, or successful cancellation/detach.
Both local processes exited, the UDP endpoint was free, and two further guest checks on the
same boot showed uptime advancing from 65070.157 to 65072.473 seconds. No ACTIVE interrupt,
native-KD recovery, reboot/reset, installed-server replacement, or outer-host change was made.

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

### Direct-COM comparison across two engine builds

The retained [raw example](../examples/raw_kernel_exit.rs) removes the dbgscope session driver,
announcement observer, output/event callbacks, and engine-option changes. It uses the Windows
bindings directly: `DebugCreate<IDebugClient>`, `QueryInterface<IDebugControl>`, `AttachKernel`,
then one raw `WaitForEvent(0, INFINITE)` on the owner thread. A scoped helper calls only
`SetInterrupt(EXIT)`, starting after 60 seconds and repeating 150 times at 200 ms intervals.
Native HRESULTs are logged without converting successful values to a generic `Ok`.

Only synthetic ports `50192` and `50193` are accepted; the key is hard-coded as `1.2.3.4` and no
target address, live profile, or caller-supplied connection is read. The connection buffer and
COM owners outlive the wait/helper. COM reference management stays on the owner thread; the
helper's narrow borrowed wrapper exposes only the documented cross-thread `SetInterrupt` call.

On 2026-09-20, the identical executable ran in two separate processes with unused synthetic
endpoints. The harness verified each actual loaded engine path/version and exclusive endpoint
ownership. It drained both output streams and reclaimed only its own synthetic child at the
100-second outer deadline. Neither run used CDB or paused the probe for tracing.

| Loaded DbgEng | Accepted EXIT calls | Native wait returned | Outer elapsed seconds |
|---|---|---|---|
| `10.0.29617.1000` | 150, all `S_OK` | No | 100.0952016 |
| `10.0.26100.1` | 150, all `S_OK` | No | 100.5128272 |

Both runs logged completion of all 150 requests but no `RAW_WAIT_RETURN`. The last request
returned at 90763 ms and 90734 ms respectively; the wait still had not returned when the outer
deadline reclaimed the process. Both processes were independently verified gone and both UDP
ports free. Process exit `-1` records forced synthetic-probe reclamation, not cancellation.

The executable SHA-256 was
`1D686673505807DC4F26C1A7348DD0E13C2134DEEAC0E8BB1D0AD0FE631F0E9F`.
The newer DLL hash is recorded above; the System32 `10.0.26100.1` DLL SHA-256 was
`BFA188B10EB64A94F1EB59BFB0F8D85EB5DFC803CD0F6B5C554816FE311A236E`.
These compare the locally installed engine environments, not a controlled replacement of one DLL
with every dependent binary held identical.

Thus dbgscope's callback, guard, and watchdog implementation are not required to reproduce the
**unconnected** cancellation failure. It is also not unique to `10.0.29617.1000`. No synchronized
live-target comparison was performed on `10.0.26100.1`, and these raw runs captured neither
internal flags nor thread stacks. They do not prove every engine version has the issue, an
indefinite wait, or the complete mechanism of the earlier post-ACTIVE freeze.

To repeat this comparison, build with `cargo build --example raw_kernel_exit` and run the binary
under an external 100-second process deadline, with argument `50192` or `50193` after verifying
the selected port is unused. Do not run it expecting its helper to bound the process: that
assumption is exactly what it measures. Use separate executable directories to select engine
environments, verify the actual loaded module, capture stdout/stderr, and check the exact child
and endpoint are gone afterward. Do not adapt this forced-cleanup harness to a live profile.

Validation: both example input tests passed natively and under Miri; they exercise input rejection,
not native FFI or cross-thread engine behavior. The normal suite passed 395 tests with 13 ignored,
plus four doctests. Formatting and focused Clippy passed, with five existing library warnings;
an extra `-D warnings` attempt failed on those unchanged warnings. The two native comparisons
above, not the pure tests or Miri, measure DbgEng behavior. No production library code changed.

### Remaining boundaries

The focused local-process tests for exit-deadline attribution and missing-announcement callback
restoration both passed with the test executable beside the same engine DLL. A CDB module listing
independently confirmed `10.0.29617.1000` for the exit-deadline comparison. These tests exercise a
local `ping.exe` debuggee, not KDNET, and do not establish live-target liveness.

Do not replace EXIT with repeated ACTIVE interrupts, add another cross-thread DbgEng method,
or patch the private flags. The synchronized trace now records the watchdog HRESULT, actual exit
branch, and engine-thread stack, but does not establish a safe automatic-recovery procedure.
The direct-COM comparison strengthens the evidence for a native DbgEng/KDNET cancellation
limitation or defect across these two unconnected engine environments, rather than a dependency
on dbgscope's implementation. Synchronized cross-build behavior and the complete post-ACTIVE
failure mechanism remain unresolved. These are measurements, not a documented general API
restriction. Until the native wait returns, a deadline remains a cancellation request, not
permission to abandon a controller whose target may be stopped.

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
- `exit-watchdog-live-20260920-080437.log`: synchronized no-ACTIVE trace, three accepted EXIT
  calls, packet-receive stack, fresh guest health, and verified local-probe reclamation.
- `exit-watchdog-live-health-20260920.md`: independent post-reclamation health and process checks.
- `trace-exit-watchdog-live.ps1` and `trace-exit-watchdog-live.txt`: guarded live harness and
  debugger commands; no automatic process kill, target break, or reset.
- `exit-watchdog-synchronized-image_11f4_2026-09-20_08-06-31-891.log`: packet-receiver and helper
  function disassembly. Its final `u` starts mid-instruction at `0x1777e0`; ignore that fragment
  and use the earlier full-function image log for the outer receive path.
- `raw-kernel-exit-bundled-20260920-082923.log`: direct-COM synthetic run on `10.0.29617.1000`.
- `raw-kernel-exit-system-20260920-082938.log`: identical executable on `10.0.26100.1`.
- `run-raw-kernel-exit.ps1`: local two-environment runner, loaded-module checks, drained output,
  100-second synthetic-process limit, and endpoint cleanup checks.
