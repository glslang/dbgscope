//! Direct-COM comparison for an unconnected, synthetic KDNET endpoint only.
//!
//! No dbgscope APIs, callbacks, execution options, real profiles, or ACTIVE interrupts.
//! Run under an external process deadline; EXIT may not unwind WaitForEvent.
//! See docs/kernel-exit-watchdog.md before running. The only argument is 50192 or 50193.
use std::{ffi::CString, sync::mpsc, time::Duration};
use windows::{
    Win32::System::Diagnostics::Debug::Extensions::{
        DEBUG_ATTACH_KERNEL_CONNECTION, DEBUG_END_PASSIVE, DEBUG_INTERRUPT_EXIT, DebugCreate,
        IDebugClient, IDebugControl,
    },
    core::{HRESULT, Interface, PCSTR},
};

struct ExitOnly<'a>(&'a IDebugControl);

// SAFETY: the scoped thread can call only SetInterrupt, documented as thread-safe.
// The COM owner outlives the scope; QueryInterface/AddRef/Release stay on its thread.
unsafe impl Sync for ExitOnly<'_> {}

impl ExitOnly<'_> {
    fn request(&self) -> HRESULT {
        // SAFETY: the borrowed control remains alive until the scoped thread joins.
        // Preserve the native HRESULT, rather than flattening successful values.
        unsafe { (self.0.vtable().SetInterrupt)(self.0.as_raw(), DEBUG_INTERRUPT_EXIT) }
    }
}

fn synthetic_connection(args: &[String]) -> Result<CString, &'static str> {
    if args.len() != 1 || !matches!(args[0].as_str(), "50192" | "50193") {
        return Err("usage: raw_kernel_exit <50192|50193> (unused synthetic endpoint only)");
    }
    // Deliberately not a credential. No host address or caller-supplied key is accepted.
    CString::new(format!("net:port={},key=1.2.3.4", args[0]))
        .map_err(|_| "invalid synthetic connection")
}

fn run(connection: &CString) -> windows::core::Result<()> {
    // SAFETY: all session APIs and COM reference management stay on this owner thread.
    let client: IDebugClient = unsafe { DebugCreate()? };
    let control: IDebugControl = client.cast()?;
    // Keep the connection buffer alive across the deferred attach and wait.
    unsafe {
        client.AttachKernel(
            DEBUG_ATTACH_KERNEL_CONNECTION,
            PCSTR(connection.as_ptr().cast()),
        )?
    };
    println!("RAW_ATTACH accepted; synthetic endpoint; no callbacks or engine options");

    let interrupt = ExitOnly(&control);
    let (stop, stopped) = mpsc::channel::<()>();
    let clock = std::time::Instant::now();
    std::thread::scope(|scope| {
        let interrupt = &interrupt;
        scope.spawn(move || {
            if !matches!(
                stopped.recv_timeout(Duration::from_secs(60)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                return;
            }
            for call in 1..=150 {
                let result = interrupt.request();
                println!(
                    "RAW_EXIT call={call} hresult={:08x} elapsed_ms={}",
                    result.0 as u32,
                    clock.elapsed().as_millis()
                );
                if !matches!(
                    stopped.recv_timeout(Duration::from_millis(200)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ) {
                    return;
                }
            }
            println!("RAW_REQUESTS_COMPLETE count=150; not a wait-return marker");
        });
        println!("RAW_WAIT_ENTER timeout=INFINITE");
        // SAFETY: this owner started the session; the wait is neither concurrent nor reentrant.
        let result = unsafe { (control.vtable().WaitForEvent)(control.as_raw(), 0, u32::MAX) };
        println!(
            "RAW_WAIT_RETURN hresult={:08x} elapsed_ms={}",
            result.0 as u32,
            clock.elapsed().as_millis()
        );
        let _ = stop.send(());
    });
    // Synthetic unconnected case only, after the wait and interrupt thread have ended.
    let result = unsafe { (client.vtable().EndSession)(client.as_raw(), DEBUG_END_PASSIVE) };
    println!("RAW_END_SESSION hresult={:08x}", result.0 as u32);
    result.ok()
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let connection = match synthetic_connection(&args) {
        Ok(connection) => connection,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    };
    if let Err(error) = run(&connection) {
        eprintln!("RAW_FAILURE hresult={:08x}", error.code().0 as u32);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_only_reserved_synthetic_ports_are_accepted() {
        for port in ["50192", "50193"] {
            let connection = synthetic_connection(&[port.into()]).unwrap();
            assert_eq!(
                connection.to_str().unwrap(),
                format!("net:port={port},key=1.2.3.4")
            );
        }
    }

    #[test]
    fn test_real_connections_and_extra_arguments_are_rejected() {
        for args in [
            vec![],
            vec!["50011".into()],
            vec!["net:port=50011,key=secret".into()],
            vec!["50192".into(), "key=secret".into()],
        ] {
            assert!(synthetic_connection(&args).is_err());
        }
    }
}
