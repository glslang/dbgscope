# Kernel teardown

`DebugEngine::end_session` and the owning engine's `Drop` share the live-kernel teardown path:

1. Refuse execution-control commands if the engine has no debuggee.
2. Remove breakpoints through the typed interfaces, failing if any removal fails.
3. Execute the engine's fixed `qd` command and require that it no longer holds a target.
4. Perform passive session cleanup, regardless of the preceding outcome.

The command is encapsulated inside the typed teardown, not exposed as a new text-based API.
The previous `SetExecutionStatus(GO)` followed by `EndSession(ACTIVE_DETACH)` is not equivalent
to native KD's quit path. A finite kernel event wait is unsupported, and adding an infinite
wait would let teardown park indefinitely. No additional cross-thread engine call is used.

A failed command, failed breakpoint removal, failed status query, or a command returning with
the target still present cannot produce `TargetLeft::KernelRunning`. If passive cleanup succeeds,
the disposition is `KernelHalted`: resume is unconfirmed, and recovery may be necessary. A cleanup
failure remains an error. `KernelRunning` describes completion of the quit path, not an independent
measurement of guest health; a target can stop again afterward.

## Evidence and limits

On 2026-09-19, the previous MCP teardown reported a successful resume/detach from a disposable
29671 Microsoft hypervisor, but its guest had a black console and stopped answering WinRM.
Native KD's subsequent `qd` sent an acknowledged continue packet and recovered the guest without
a reboot. Both controllers used the same DbgEng 10.0.29617.1000 image. An offline native-KD trace
against an image target also showed the frontend's passive cleanup after `qd`.

These observations motivate this implementation; they do **not** validate it against a live
hypervisor. A later diagnostic stalled during initial KDNET synchronization, before reaching any
detach experiment. Its explicit-target native-KD recovery attempt crashed, and passive reconnection
did not establish a session. Further live validation requires recovery of that lab target.

The new local tests cover the no-debuggee guard, rejection of a target that remains present,
breakpoint removal, and quit/detach leaving a disposable attached user-mode process alive. The
default tests and doctests pass. Neither these tests nor Miri proves kernel transport behavior.

Before treating this path as validated, test NT and hypervisor endpoints separately, including
explicit teardown and owning-engine drop, and check console/management responsiveness and uptime
after each detach. Keep only one controller on an endpoint and have native KD recovery available.
Do not reset a target merely because an attach times out.

Microsoft documents the deferred nature of
[SetExecutionStatus](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nf-dbgeng-idebugcontrol-setexecutionstatus).
Its [qd reference](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/qd--quit-and-detach-)
lists user-mode support only; the hypervisor recovery above is an observation on a specific build,
not a documented cross-version guarantee.
