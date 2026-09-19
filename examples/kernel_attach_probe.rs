//! Disposable-lab measurement, not a production attach policy.
//!
//! Set DBGSCOPE_KERNEL_CONNECTION locally; never put a KDNET key on the command line.
//! Usage: kernel_attach_probe <manual|early|announcement|production|timeout> <new-control-file>
//! Manual fallback: create the control file containing exactly "break" after synchronization.
//! Install matching DbgEng DLLs beside this executable. See docs/kernel-attach-probe.md.
use dbgscope::dbgeng::{DebugEngine, TargetLeft};
use std::{
    ffi::CString,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::Duration,
};
use windows::{
    Win32::System::Diagnostics::Debug::Extensions::*,
    core::{Interface, PCSTR, implement},
};

#[implement(IDebugOutputCallbacks)]
struct Trace {
    connected: mpsc::SyncSender<()>,
    notice: Mutex<ConnectionNotice>,
}
impl IDebugOutputCallbacks_Impl for Trace_Impl {
    fn Output(&self, mask: u32, text: &PCSTR) -> windows::core::Result<()> {
        // SAFETY: callback text is NUL-terminated and valid until the callback returns.
        let text = unsafe { text.to_string() }?;
        // Deliberately do not echo raw DbgEng output: it may include the connection key.
        if text.contains("Target synchronized successfully") {
            println!("PROBE transport synchronization reported (diagnostic text)");
        }
        if text.contains("Send Break in ...") {
            println!("PROBE transport break-in send reported (diagnostic text)");
        }
        if self
            .notice
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .feed(mask, text.as_bytes())
        {
            println!("PROBE connection announcement mask={mask:#x}");
            let _ = self.connected.try_send(());
        }
        Ok(())
    }
}

#[implement(IDebugEventCallbacks)]
struct Events;
#[allow(non_snake_case)]
impl IDebugEventCallbacks_Impl for Events_Impl {
    fn GetInterestMask(&self) -> windows::core::Result<u32> {
        Ok(DEBUG_EVENT_SESSION_STATUS
            | DEBUG_EVENT_CHANGE_ENGINE_STATE
            | DEBUG_EVENT_CHANGE_DEBUGGEE_STATE)
    }
    fn SessionStatus(&self, status: u32) -> windows::core::Result<()> {
        println!("PROBE EVENT SessionStatus status={status:#x}");
        Ok(())
    }
    fn ChangeEngineState(&self, flags: u32, argument: u64) -> windows::core::Result<()> {
        println!("PROBE EVENT ChangeEngineState flags={flags:#x} argument={argument:#x}");
        Ok(())
    }
    fn ChangeDebuggeeState(&self, flags: u32, argument: u64) -> windows::core::Result<()> {
        println!("PROBE EVENT ChangeDebuggeeState flags={flags:#x} argument={argument:#x}");
        Ok(())
    }
    fn ChangeSymbolState(&self, _: u32, _: u64) -> windows::core::Result<()> {
        Ok(())
    }
    fn Breakpoint(&self, _: windows::core::Ref<'_, IDebugBreakpoint>) -> windows::core::Result<()> {
        Ok(())
    }
    fn Exception(
        &self,
        _: *const windows::Win32::System::Diagnostics::Debug::EXCEPTION_RECORD64,
        _: u32,
    ) -> windows::core::Result<()> {
        Ok(())
    }
    fn CreateThread(&self, _: u64, _: u64, _: u64) -> windows::core::Result<()> {
        Ok(())
    }
    fn ExitThread(&self, _: u32) -> windows::core::Result<()> {
        Ok(())
    }
    fn CreateProcessA(
        &self,
        _: u64,
        _: u64,
        _: u64,
        _: u32,
        _: &PCSTR,
        _: &PCSTR,
        _: u32,
        _: u32,
        _: u64,
        _: u64,
        _: u64,
    ) -> windows::core::Result<()> {
        Ok(())
    }
    fn ExitProcess(&self, _: u32) -> windows::core::Result<()> {
        Ok(())
    }
    fn LoadModule(
        &self,
        _: u64,
        _: u64,
        _: u32,
        _: &PCSTR,
        _: &PCSTR,
        _: u32,
        _: u32,
    ) -> windows::core::Result<()> {
        Ok(())
    }
    fn UnloadModule(&self, _: &PCSTR, _: u64) -> windows::core::Result<()> {
        Ok(())
    }
    fn SystemError(&self, _: u32, _: u32) -> windows::core::Result<()> {
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mode = args
        .next()
        .ok_or("mode required: manual, early, announcement, production, timeout")?;
    if !matches!(
        mode.as_str(),
        "manual" | "early" | "announcement" | "production" | "timeout"
    ) {
        return Err("mode must be manual, early, announcement, production, or timeout".into());
    }
    let control_file = PathBuf::from(args.next().ok_or("new control file required")?);
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    if control_file.exists() {
        return Err("refusing to replay an existing control file".into());
    }
    // Retain the connection buffer until after EndSession; never print it.
    let connection = CString::new(
        std::env::var("DBGSCOPE_KERNEL_CONNECTION")
            .map_err(|_| "set DBGSCOPE_KERNEL_CONNECTION from a local profile")?,
    )
    .map_err(|_| "connection contains an interior NUL")?;
    if mode == "announcement"
        && !connection
            .as_bytes()
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"net:"))
    {
        return Err("the announcement experiment supports KDNET connections only".into());
    }
    // SAFETY: all engine calls stay on this thread. Only the existing InterruptHandle crosses it.
    let client: IDebugClient6 = unsafe { DebugCreate()? };
    let control: IDebugControl4 = client.cast()?;
    let engine = DebugEngine::try_from_client_interface(client.clone())?;
    let (connected, readiness) = mpsc::sync_channel(1);
    let trace: IDebugOutputCallbacks = Trace {
        connected,
        notice: Mutex::new(ConnectionNotice::default()),
    }
    .into();
    let events: IDebugEventCallbacks = Events.into();
    unsafe {
        client.SetEventCallbacks(&events)?;
        client.SetOutputCallbacks(&trace)?;
        client.SetOutputMask(u32::MAX)?;
        control.RemoveEngineOptions(DEBUG_ENGOPT_INITIAL_BREAK)?;
        if !matches!(mode.as_str(), "production" | "timeout") {
            client.AttachKernel(
                DEBUG_ATTACH_KERNEL_CONNECTION,
                PCSTR(connection.as_ptr().cast()),
            )?;
        }
    }
    let handle = engine.interrupt_handle();
    if mode == "early" {
        println!("PROBE one pre-wait interrupt: {:?}", handle.interrupt());
    }
    let finished = Arc::new(AtomicBool::new(false));
    let done = Arc::clone(&finished);
    let automatic = mode == "announcement";
    let recovery_control = control_file.clone();
    let reader = std::thread::spawn(move || {
        while !done.load(Ordering::Acquire) {
            if automatic && readiness.recv_timeout(Duration::from_millis(100)).is_ok() {
                println!("PROBE one announcement interrupt: {:?}", handle.interrupt());
                return;
            }
            if std::fs::read_to_string(&control_file).is_ok_and(|s| s.trim() == "break") {
                println!("PROBE one manual interrupt: {:?}", handle.interrupt());
                return;
            }
            if !automatic {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    });
    println!("PROBE mode={mode}; manual fallback available through the new control file");
    let started = std::time::Instant::now();
    let mut waited = if matches!(mode.as_str(), "production" | "timeout") {
        let pending = engine.attach_kernel_announcement_begin(connection.to_str()?)?;
        if mode == "timeout" {
            // Deliberate example-only fault injection: hide announcements from the library's
            // observer, retaining this passive trace. Production code and deadline are unchanged.
            unsafe { client.SetOutputCallbacks(&trace)? };
            println!("PROBE injected missing announcement; real 60-second attach deadline armed");
        }
        pending.wait()
    } else {
        engine.wait_for_event(u32::MAX).map(|_| ())
    };
    finished.store(true, Ordering::Release);
    let _ = reader.join();
    println!("PROBE wait={waited:?}");
    println!("PROBE elapsed={:?}", started.elapsed());
    println!("PROBE status={:?}", unsafe { control.GetExecutionStatus() });
    if mode == "timeout" {
        println!("PROBE timeout stage complete; holding controller, NOT detaching");
        let status = unsafe { control.GetExecutionStatus() };
        let event = engine.last_event();
        println!("PROBE held status={status:?} event={event:?}");
        println!("PROBE after inspecting the stop, write detach; this sends NO second interrupt");
        wait_for_control(&recovery_control, "detach");
        let break_in = event
            .as_ref()
            .ok()
            .and_then(|e| e.as_ref())
            .is_some_and(|e| {
                e.first_chance && e.exception.as_ref().is_some_and(|e| e.code == 0x80000003)
            });
        if status != Ok(DEBUG_STATUS_BREAK) || !break_in {
            println!("PROBE refusing detach without a confirmed break-in; controller remains held");
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        // The attach failed as intended. This explicit cleanup is not a successful attach.
        waited = Ok(());
    }
    if waited.is_ok()
        && matches!(
            unsafe { control.GetExecutionStatus() },
            Ok(DEBUG_STATUS_BREAK)
        )
    {
        println!(
            "PROBE processor={:?} ip={:?}",
            engine.current_processor(),
            engine.instruction_pointer()
        );
        println!("PROBE last_event={:?}", engine.last_event());
        println!("PROBE breakpoints={:?}", engine.breakpoints());
    }
    let ended = engine.end_session();
    println!("PROBE typed end_session={ended:?}");
    println!("PROBE final status={:?}", unsafe {
        control.GetExecutionStatus()
    });
    if !matches!(ended?, TargetLeft::KernelRunning) {
        return Err(
            "kernel quit path did not confirm resume; inspect the target before retrying".into(),
        );
    }
    waited?;
    Ok(())
}

fn wait_for_control(path: &std::path::Path, expected: &str) {
    while !std::fs::read_to_string(path).is_ok_and(|s| s.trim() == expected) {
        std::thread::sleep(Duration::from_millis(100));
    }
}

// A bounded, one-shot stream matcher for this experiment's English DbgEng announcement.
// No address/key buffering; unrelated output and callback chunk boundaries are immaterial.
#[derive(Default)]
struct ConnectionNotice {
    matched: usize,
    skip_line: bool,
    fired: bool,
}
impl ConnectionNotice {
    fn feed(&mut self, mask: u32, bytes: &[u8]) -> bool {
        const PREFIX: &[u8] = b"Connected to target ";
        if mask != DEBUG_OUTPUT_NORMAL || self.fired {
            return false;
        }
        for &byte in bytes {
            if byte == b'\n' {
                self.matched = 0;
                self.skip_line = false;
            } else if !self.skip_line {
                if byte == PREFIX[self.matched] {
                    self.matched += 1;
                    if self.matched == PREFIX.len() {
                        self.fired = true;
                        return true;
                    }
                } else {
                    self.matched = 0;
                    self.skip_line = true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notice_handles_every_chunk_boundary_and_fires_once() {
        let line = b"Connected to target ";
        for split in 0..=line.len() {
            let mut notice = ConnectionNotice::default();
            let first = notice.feed(DEBUG_OUTPUT_NORMAL, &line[..split]);
            let second = notice.feed(DEBUG_OUTPUT_NORMAL, &line[split..]);
            assert_eq!(usize::from(first) + usize::from(second), 1);
            assert!(!notice.feed(DEBUG_OUTPUT_NORMAL, line));
        }
    }

    #[test]
    fn test_notice_is_line_anchored_and_ignores_other_announcements() {
        let mut notice = ConnectionNotice::default();
        assert!(!notice.feed(
            DEBUG_OUTPUT_NORMAL,
            b"noise Connected to target x\r\nConnected to Microsoft Hypervisor\r\n"
        ));
        assert!(notice.feed(DEBUG_OUTPUT_NORMAL, b"Connected to target "));
    }

    #[test]
    fn test_notice_ignores_non_normal_output_between_fragments() {
        let mut notice = ConnectionNotice::default();
        assert!(!notice.feed(DEBUG_OUTPUT_NORMAL, b"Connected to "));
        assert!(!notice.feed(DEBUG_OUTPUT_WARNING, b"unrelated\nConnected to target "));
        assert!(notice.feed(DEBUG_OUTPUT_NORMAL, b"target "));
    }

    #[test]
    fn test_notice_recovers_from_a_partial_mismatch_at_next_line() {
        let mut notice = ConnectionNotice::default();
        assert!(!notice.feed(DEBUG_OUTPUT_NORMAL, b"Connected to nope\r\n"));
        assert!(notice.feed(DEBUG_OUTPUT_NORMAL, b"Connected to target "));
    }

    #[test]
    fn test_notice_does_not_buffer_an_unbounded_line() {
        let mut notice = ConnectionNotice::default();
        for _ in 0..100_000 {
            assert!(!notice.feed(DEBUG_OUTPUT_NORMAL, b"x"));
        }
        assert_eq!(notice.matched, 0);
        assert!(notice.feed(DEBUG_OUTPUT_NORMAL, b"\nConnected to target "));
    }
}
