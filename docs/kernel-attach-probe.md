# Kernel attach timing probe

`examples/kernel_attach_probe.rs` is an opt-in disposable-lab diagnostic for the hypervisor
detach investigation. It is **not a production attach policy** and changes no library default.
It connects without `DEBUG_ENGOPT_INITIAL_BREAK`, records selected diagnostic notifications,
requests a break, and calls the candidate typed `end_session` at the resulting stop. It does not
execute the ordinary attach helper's artifact-absorption `g`.

## Safety and setup

Use one controller on the lab endpoint. Verify guest identity, debugger host address, endpoint,
and key before starting. Arrange independent console/management access and a native-KD recovery
path. Do not use this example on a production target. **Its kernel wait can block indefinitely**;
there is no watchdog, and a missing announcement or unreachable target does not become a clean
timeout. Do not kill a probe holding a broken-in target or reset the guest as routine cleanup.

Load `DBGSCOPE_KERNEL_CONNECTION` from an existing local secret/profile without printing it.
It is the complete DbgEng connection string. Do not pass it as an argument or commit it. Install
the matching DbgEng DLLs beside the example executable (`target/debug/examples`, or the equivalent
under `CARGO_TARGET_DIR`); otherwise the test can load a different engine from System32.
Record the loaded version. A new executable path may need the owner's firewall approval.

The example does not echo raw DbgEng output or the connection string. It prints selected fixed
markers and typed event/status fields. Those still contain target addresses; keep raw run logs
local unless reviewed. This example enables diagnostic output masks, so its timings are not a
performance benchmark.

## Modes

Both arguments are required. The control file must not exist, preventing replay of an old break.

```powershell
cargo run --example kernel_attach_probe -- announcement .\target\attach-control-01.txt
```

| Mode | Break request |
|---|---|
| `manual` | A reader waits for the new control file to contain exactly `break` |
| `early` | One `InterruptHandle::interrupt` before the first wait; the control file remains a manual fallback |
| `announcement` | KDNET only: one request when normal output begins a line with `Connected to target` followed by a space; the control file remains a manual fallback |

For a manual request, observe synchronization and independently verify guest responsiveness first,
then create that control file containing `break`. Never run a second debugger against the same
endpoint while the first is waiting. No mode automatically resets the target.

The announcement matcher is a bounded, line-anchored, one-shot stream matcher. It accepts only
`DEBUG_OUTPUT_NORMAL`, handles a prefix split across callbacks, ignores other output masks,
and buffers no address or key. Five offline tests exercise chunk boundaries, one-shot behavior,
line anchoring, mask filtering, mismatch recovery, and a long unrelated line:

```powershell
cargo test --example kernel_attach_probe
```

The five matcher tests also passed `cargo +nightly miri test --example kernel_attach_probe` on
this bench. They do not invoke DbgEng: this checks the parser, not foreign calls or target safety.

The output callback only signals a channel. The reader uses the existing `InterruptHandle`; the
engine and every call other than `SetInterrupt` stay on the engine thread. Session/engine-state
callbacks only log their arguments and do not change execution status.

## Measurement on 2026-09-19

Engine: DbgEng 10.0.29617.1000. Target: four-processor Hyper-V 29671, guest OS 29671.1000. Typed
teardown: dbgscope `16403fa`. All comparisons retained the same boot; no reset or host configuration
change was made.

- `ChangeEngineState(EXECUTION_STATUS, GO)` arrived before transport synchronization.
  `SessionStatus(ACTIVE)` arrived only after the first break. Neither was a usable readiness
  signal for requesting that first break in this run. Microsoft's
  [session callback documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nf-dbgeng-idebugeventcallbacks-sessionstatus)
  describes session activation, not a KDNET synchronization notification.
- A pre-wait interrupt logged a break-in send **before** synchronization but did not produce a
  stop. WinRM still answered. A later manual request reached CPU 0; typed teardown then left the
  guest responsive. A successful `SetInterrupt` call alone did not establish delivery.
- Two local announcement-trigger prototypes and two runs of this example's source each recorded
  one break-in send, reached a first-chance `0x80000003` at `hv+0x404a60`, and returned
  `Ok(KernelRunning)` followed by `DEBUG_STATUS_NO_DEBUGGEE`. Independent WinRM checks answered
  twice after each run with unchanged boot time and advancing uptime.

The announcement was normal output (mask `0x1`), not the internal protocol trace. It was emitted
before the synchronization-complete message; the requested break-in send appeared afterward.
This is an **observed ordering**, not a documented transport-readiness contract. It is why the
matcher remains in an example rather than becoming the library's default. Engines with different
output, localization, reconnect behavior, or timing need separate measurement. Do not replace
the missing contract with a fixed sleep or a fixed number of resumes.

The source was live-tested using the lab's already-approved diagnostic executable path, linked
against the pinned candidate library. The normal Cargo example entry point was compiled and its
offline tests run separately. These are not MCP end-to-end tests. Live NT behavior, owning-engine
drop, stepping, breakpoint hits, failed/missing announcement cleanup, and the existing automatic
attach path remain separate validation work. Always check guest health independently after detach.
