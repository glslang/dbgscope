//! Measurement for `DebugEngine::function_extent`: what the engine fills in, and what it says
//! when there is nothing to fill.
//!
//! Two questions the API's documentation does not answer, and both decide code:
//!
//! - **Which failure means "no entry"?** `GetFunctionEntryByOffset` returns `Result<()>`, and a
//!   leaf function, a data address and a broken engine are all `Err`. Mapping every one of them to
//!   `None` makes a failed query indistinguishable from a function that has no unwind record.
//! - **What is the entry's layout off x64?** The x64 record is three `u32` RVAs. ARM64's is two
//!   words whose second is packed unwind data or an `.xdata` RVA — so reading it as an end address
//!   is a bogus extent rather than an error, which is the worst shape a wrong answer can take.
//!
//! ```text
//! cargo run --example function_entry_probe -- <dump> <addr-or-symbol>... [--exepath <path>]
//! ```

use dbgscope::dbgeng::{DebugEngine, FunctionExtent};

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(dump) = args.next() else {
        eprintln!("usage: function_entry_probe <dump> <addr-or-symbol>... [--exepath <path>]");
        std::process::exit(2);
    };
    let mut wanted = Vec::new();
    let mut image_path = None;
    let mut effmach = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--exepath" => image_path = args.next(),
            // `.effmach` is the one way to make the physical and effective processor types
            // disagree on a fixture that is not a WOW64 or emulated target.
            "--effmach" => effmach = args.next(),
            _ => wanted.push(arg),
        }
    }

    let e = DebugEngine::new();
    e.open_dump(&dump).expect("opening the dump failed");
    e.wait_for_event(30_000).expect("the dump did not load");
    if let Some(path) = &image_path {
        e.execute_command(&format!(".exepath+ {path}"))
            .expect("setting the image search path failed");
        e.reload_symbols("/f").expect("reloading failed");
    }

    if let Some(machine) = &effmach {
        e.execute_command(&format!(".effmach {machine}"))
            .expect("setting the effective machine failed");
    }

    // Physical against effective: `Disassemble` renders with the second, so the second is what
    // discriminates the reading. They diverge wherever one machine runs another's code.
    println!(
        "processor: physical {:?} effective {:?} -> {:?}\n",
        e.processor_type().map(|m| format!("{m:#x}")),
        e.effective_processor_type().map(|m| format!("{m:#x}")),
        e.instruction_set()
    );
    for name in &wanted {
        let address = match name.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16).expect("a hexadecimal address"),
            None => match e.symbol_offset(name) {
                Ok(address) => address,
                Err(error) => {
                    println!("{name}: did not resolve ({error})\n");
                    continue;
                }
            },
        };
        println!("{name} = {address:#x}");
        match e.function_extent(address) {
            Ok(FunctionExtent::Region { begin, end }) => {
                println!("  region {begin:#x}..{end:#x} ({} bytes)\n", end - begin)
            }
            Ok(FunctionExtent::NoEntry) => println!("  no entry\n"),
            Ok(FunctionExtent::Unsupported(set)) => println!("  not decoded for {set:?}\n"),
            Err(error) => println!("  error: {error}\n"),
        }
    }
}
