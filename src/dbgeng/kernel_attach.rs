//! Opt-in KDNET attach experiment. The announcement is observed DbgEng text, not an API contract.
use super::*;
use windows::Win32::System::Diagnostics::Debug::Extensions::{
    DEBUG_STATUS_BREAK, IDebugOutputCallbacksWide, IDebugOutputCallbacksWide_Impl,
};
use windows::core::implement;

impl DebugEngine {
    /// Experimental attach for a known-running KDNET lab target.
    ///
    /// Requests one break upon the English `Connected to target ` output prefix, without
    /// INITIAL_BREAK or the default attach's extra `g`. This text is NOT a Microsoft readiness
    /// contract. Missing/changed output, interruption, and timeout fail without a fallback break.
    /// An unconnected transport may still block indefinitely; use an isolated worker process.
    ///
    /// Call the returned guard's `wait()` immediately. Dropping it restores the previous output
    /// callback but does not cancel the transport claim. Existing output callbacks are forwarded
    /// through DbgEng's wide interface without retaining their text. No reconnect auto-break is armed
    /// after the first announcement. An already-stopped target is not a validated use case.
    pub fn attach_kernel_announcement_begin(
        &self,
        connection_string: &str,
    ) -> Result<PendingTarget<'_>, DbgEngError> {
        if !connection_string
            .as_bytes()
            .get(..4)
            .is_some_and(|p| p.eq_ignore_ascii_case(b"net:"))
        {
            return Err(DbgEngError::ExperimentalKernelAttach(
                "KDNET connection required",
            ));
        }
        let connection =
            CString::new(connection_string).map_err(|_| DbgEngError::InvalidCommand)?;
        let observer = AnnouncementGuard::install(self)?;
        unsafe {
            self.control
                .RemoveEngineOptions(DEBUG_ENGOPT_INITIAL_BREAK)
                .map_err(DbgEngError::CommandFailed)?;
            self.client
                .AttachKernel(
                    DEBUG_ATTACH_KERNEL_CONNECTION,
                    PCSTR(connection.as_ptr().cast()),
                )
                .map_err(DbgEngError::AttachFailed)?;
        }
        self.retain_deferred_input(TargetInput::Ansi(connection));
        self.forget_the_previous_session();
        Ok(PendingTarget::new(
            self,
            WaitKind::KernelAnnouncement(observer),
        ))
    }
}

#[derive(Default)]
struct Notice {
    matched: usize,
    skip_line: bool,
    fired: bool,
}
impl Notice {
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

#[derive(Default)]
struct Observation {
    notice: Notice,
    requested: Option<HRESULT>,
}

#[implement(IDebugOutputCallbacksWide)]
struct Observer {
    observation: Arc<Mutex<Observation>>,
    control: IDebugControl4,
    previous: Option<IDebugOutputCallbacksWide>,
    previous_mask: u32,
}
impl IDebugOutputCallbacksWide_Impl for Observer_Impl {
    fn Output(&self, mask: u32, text: &PCWSTR) -> windows::core::Result<()> {
        // SAFETY: DbgEng supplies callback text valid until this callback returns.
        let decoded = unsafe { text.to_string() }.unwrap_or_default();
        let fire = self
            .observation
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .notice
            .feed(mask, decoded.as_bytes());
        if fire {
            // SetInterrupt is documented safe at any time. No wait or other engine call is
            // reentered here; mark the notice fired before this call to reject recursive output.
            let result = unsafe { self.control.SetInterrupt(DEBUG_INTERRUPT_ACTIVE) };
            self.observation
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .requested = Some(result.err().map_or(S_OK, |e| e.code()));
        }
        if mask & self.previous_mask != 0
            && let Some(previous) = &self.previous
        {
            unsafe { previous.Output(mask, *text) }?;
        }
        Ok(())
    }
}

pub(super) struct AnnouncementGuard<'a> {
    engine: &'a DebugEngine,
    previous: Option<IDebugOutputCallbacksWide>,
    mask: u32,
    observation: Arc<Mutex<Observation>>,
    restored: RefCell<bool>,
}
impl<'a> AnnouncementGuard<'a> {
    fn install(engine: &'a DebugEngine) -> Result<Self, DbgEngError> {
        unsafe {
            // The generated getter treats S_OK + NULL (no callback) as an error. Read the
            // nullable, AddRef-owned COM result through the vtable instead.
            let mut raw = std::ptr::null_mut();
            (engine.client.vtable().GetOutputCallbacksWide)(engine.client.as_raw(), &mut raw)
                .ok()
                .map_err(DbgEngError::CommandFailed)?;
            let previous = (!raw.is_null()).then(|| IDebugOutputCallbacksWide::from_raw(raw));
            let mask = engine
                .client
                .GetOutputMask()
                .map_err(DbgEngError::CommandFailed)?;
            let observation = Arc::new(Mutex::new(Observation::default()));
            let observer: IDebugOutputCallbacksWide = Observer {
                observation: observation.clone(),
                control: engine.control.clone(),
                previous: previous.clone(),
                previous_mask: mask,
            }
            .into();
            let guard = Self {
                engine,
                previous,
                mask,
                observation,
                restored: RefCell::new(false),
            };
            engine
                .client
                .SetOutputMask(mask | DEBUG_OUTPUT_NORMAL)
                .map_err(DbgEngError::CommandFailed)?;
            engine
                .client
                .SetOutputCallbacksWide(&observer)
                .map_err(DbgEngError::CommandFailed)?;
            Ok(guard)
        }
    }

    fn restore(&self) -> Result<(), DbgEngError> {
        if *self.restored.borrow() {
            return Ok(());
        }
        unsafe {
            self.engine
                .client
                .SetOutputCallbacksWide(self.previous.as_ref())
                .map_err(DbgEngError::CommandFailed)?;
            self.engine
                .client
                .SetOutputMask(self.mask)
                .map_err(DbgEngError::CommandFailed)?;
        }
        *self.restored.borrow_mut() = true;
        Ok(())
    }

    pub(super) fn wait(&self) -> Result<(), DbgEngError> {
        self.wait_with_timeout(KERNEL_ATTACH_WAIT_MS)
    }

    fn wait_with_timeout(&self, timeout_ms: u32) -> Result<(), DbgEngError> {
        let operation = self.engine.begin_operation();
        let result = self
            .engine
            .pump(Bound::WatchdogExit(timeout_ms), &operation);
        self.restore()?;
        let observation = self.observation.lock().unwrap_or_else(|e| e.into_inner());
        validate_observation(observation.requested)?;
        if !matches!(result?, WaitOutcome::Stopped { .. }) {
            return Err(DbgEngError::ExperimentalKernelAttach(
                "attach wait was interrupted or expired",
            ));
        }
        if unsafe { self.engine.control.GetExecutionStatus() }
            .map_err(DbgEngError::CommandFailed)?
            != DEBUG_STATUS_BREAK
        {
            return Err(DbgEngError::ExperimentalKernelAttach(
                "target stop was not confirmed",
            ));
        }
        Ok(())
    }
}
impl Drop for AnnouncementGuard<'_> {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

fn validate_observation(requested: Option<HRESULT>) -> Result<(), DbgEngError> {
    match requested {
        Some(S_OK) => Ok(()),
        Some(_) => Err(DbgEngError::ExperimentalKernelAttach(
            "one-shot interrupt request failed",
        )),
        None => Err(DbgEngError::ExperimentalKernelAttach(
            "connection announcement was not observed",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_OUTPUT_WARNING;

    #[cfg(not(miri))]
    #[implement(IDebugOutputCallbacks)]
    struct AnsiSink(Arc<Mutex<Vec<u32>>>);
    #[cfg(not(miri))]
    impl windows::Win32::System::Diagnostics::Debug::Extensions::IDebugOutputCallbacks_Impl
        for AnsiSink_Impl
    {
        fn Output(&self, mask: u32, _: &PCSTR) -> windows::core::Result<()> {
            self.0.lock().unwrap().push(mask);
            Ok(())
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn test_ansi_callback_is_forwarded_only_its_original_mask_and_restored() {
        let _debuggee = super::super::tests::one_debuggee();
        use windows::Win32::System::Diagnostics::Debug::Extensions::DebugCreate;
        let client: IDebugClient6 = unsafe { DebugCreate().unwrap() };
        let engine = DebugEngine::try_from_client_interface(client.clone()).unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let sink: IDebugOutputCallbacks = AnsiSink(received.clone()).into();
        unsafe {
            client.SetOutputCallbacks(&sink).unwrap();
            client.SetOutputMask(DEBUG_OUTPUT_WARNING).unwrap();
        }
        {
            let _guard = AnnouncementGuard::install(&engine).unwrap();
            let active = unsafe { client.GetOutputCallbacksWide().unwrap() };
            unsafe {
                active
                    .Output(DEBUG_OUTPUT_NORMAL, windows::core::w!("unrelated\n"))
                    .unwrap();
                active
                    .Output(DEBUG_OUTPUT_WARNING, windows::core::w!("warning\n"))
                    .unwrap();
            }
        }
        unsafe {
            client
                .GetOutputCallbacksWide()
                .unwrap()
                .Output(DEBUG_OUTPUT_WARNING, windows::core::w!("after\n"))
                .unwrap();
            client.SetOutputCallbacks(None).unwrap();
        }
        assert_eq!(
            *received.lock().unwrap(),
            vec![DEBUG_OUTPUT_WARNING, DEBUG_OUTPUT_WARNING]
        );
    }

    #[test]
    fn test_notice_chunk_boundaries_and_reconnect_are_one_shot() {
        let prefix = b"Connected to target ";
        for split in 0..=prefix.len() {
            let mut notice = Notice::default();
            let a = notice.feed(DEBUG_OUTPUT_NORMAL, &prefix[..split]);
            let b = notice.feed(DEBUG_OUTPUT_NORMAL, &prefix[split..]);
            assert_eq!(usize::from(a) + usize::from(b), 1);
            assert!(!notice.feed(DEBUG_OUTPUT_NORMAL, b"\nConnected to target "));
            assert!(Notice::default().feed(DEBUG_OUTPUT_NORMAL, prefix));
        }
    }
    #[test]
    fn test_notice_anchoring_masks_and_bounded_state() {
        let mut notice = Notice::default();
        for _ in 0..100_000 {
            assert!(!notice.feed(DEBUG_OUTPUT_NORMAL, b"x"));
        }
        assert!(!notice.feed(
            DEBUG_OUTPUT_NORMAL,
            b"Connected to target \nConnected to nope\nConnected to "
        ));
        assert!(!notice.feed(DEBUG_OUTPUT_WARNING, b"other\nConnected to target "));
        assert!(notice.feed(DEBUG_OUTPUT_NORMAL, b"target "));
    }
    #[test]
    fn test_missing_or_failed_announcement_never_succeeds() {
        assert!(validate_observation(None).is_err());
        assert!(validate_observation(Some(E_FAIL)).is_err());
        assert!(validate_observation(Some(S_OK)).is_ok());
    }

    #[test]
    #[cfg(not(miri))]
    fn test_observer_restores_existing_callback_and_mask_without_a_target() {
        let _debuggee = super::super::tests::one_debuggee();
        use windows::Win32::System::Diagnostics::Debug::Extensions::DebugCreate;
        let client: IDebugClient6 = unsafe { DebugCreate().unwrap() };
        let engine = DebugEngine::try_from_client_interface(client.clone()).unwrap();
        let saved_mask = DEBUG_OUTPUT_WARNING;
        let observation = Arc::new(Mutex::new(Observation::default()));
        let previous: IDebugOutputCallbacksWide = Observer {
            observation,
            control: engine.control.clone(),
            previous: None,
            previous_mask: 0,
        }
        .into();
        unsafe {
            client.SetOutputCallbacksWide(&previous).unwrap();
            client.SetOutputMask(saved_mask).unwrap();
        }
        {
            let guard = AnnouncementGuard::install(&engine).unwrap();
            assert_eq!(
                unsafe { client.GetOutputMask().unwrap() },
                saved_mask | DEBUG_OUTPUT_NORMAL
            );
            assert!(validate_observation(guard.observation.lock().unwrap().requested).is_err());
        }
        unsafe {
            assert_eq!(client.GetOutputCallbacksWide().unwrap(), previous);
            assert_eq!(client.GetOutputMask().unwrap(), saved_mask);
            client.SetOutputCallbacksWide(None).unwrap();
        }
        // Null is a valid prior callback too, and a new attach gets fresh one-shot state.
        AnnouncementGuard::install(&engine)
            .unwrap()
            .restore()
            .unwrap();
        let mut raw = std::ptr::null_mut();
        unsafe {
            (client.vtable().GetOutputCallbacksWide)(client.as_raw(), &mut raw)
                .ok()
                .unwrap()
        };
        assert!(raw.is_null());
    }

    #[test]
    #[cfg(not(miri))]
    fn test_missing_announcement_deadline_fails_and_restores_the_callback() {
        let _debuggee = super::super::tests::one_debuggee();
        let engine = DebugEngine::new();
        engine
            .launch_process("ping.exe -n 30 127.0.0.1")
            .expect("launch failed");
        let received = Arc::new(Mutex::new(Vec::new()));
        let sink: IDebugOutputCallbacks = AnsiSink(received.clone()).into();
        unsafe {
            engine.client.SetOutputCallbacks(&sink).unwrap();
            engine.client.SetOutputMask(DEBUG_OUTPUT_WARNING).unwrap();
            engine.control.SetExecutionStatus(DEBUG_STATUS_GO).unwrap();
        }
        let guard = AnnouncementGuard::install(&engine).unwrap();
        let result = guard.wait_with_timeout(100);
        assert!(matches!(
            result,
            Err(DbgEngError::ExperimentalKernelAttach(
                "connection announcement was not observed"
            ))
        ));
        assert_eq!(guard.observation.lock().unwrap().requested, None);
        assert!(
            *guard.restored.borrow(),
            "restore must happen before guard drop"
        );
        unsafe {
            assert_eq!(engine.client.GetOutputMask().unwrap(), DEBUG_OUTPUT_WARNING);
            engine
                .client
                .GetOutputCallbacksWide()
                .unwrap()
                .Output(DEBUG_OUTPUT_WARNING, windows::core::w!("after deadline\n"))
                .unwrap();
        }
        assert_eq!(received.lock().unwrap().last(), Some(&DEBUG_OUTPUT_WARNING));
        drop(guard);
        engine.end_session().expect("test process cleanup failed");
    }
}
