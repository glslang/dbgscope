//! Drives a live debug session with randomised command sequences and checks, after every one of
//! them, the single property a session has to keep: **it either still holds a target and answers,
//! or it says it holds none — and this process is still running.**
//!
//! Written because the three defects behind [windbg-mcp#242] were all found by hand, one
//! sequence at a time, and each one looked like an isolated corner until it was measured:
//!
//! - a raw `Execute` of `g` that set the run state and moved nothing (windbg-mcp#226),
//! - a target that exited while the pump was running, reported as a catastrophic failure with
//!   its output discarded,
//! - execution-control text reaching an engine with no debuggee, which is a
//!   `STATUS_ACCESS_VIOLATION` inside DbgEng and takes the host process down.
//!
//! What they have in common is that none of them is about a *command*. They are about the state
//! the previous command left the engine in, and the number of ways to reach a given state is
//! larger than anyone enumerates by hand — an alias, a `.if` branch and `dx …ExecuteCommand("g")`
//! all reach execution without saying so, which is why the fixes ask the engine rather than
//! reading the text. A fuzzer is the honest way to look for the next one.
//!
//! [windbg-mcp#242]: https://github.com/glslang/windbg-mcp/issues/242
//!
//! ```text
//! cargo run --example session_fuzz                      # 20 rounds, seed from the clock
//! cargo run --example session_fuzz -- --seed 42          # replay exactly
//! cargo run --example session_fuzz -- --rounds 200 --steps 12
//! ```
//!
//! Every step is printed **before** it runs and the stream is flushed, because the failure this
//! exists to catch is the process dying: there is no unwind, no panic message and no summary, so
//! the last line on the terminal is the whole report. A violation that is *not* a crash exits
//! non-zero and prints the round's sequence, which `--seed` replays.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use dbgscope::dbgeng::{DbgEngError, DebugEngine};

/// Bound on every wait the fuzzer issues.
///
/// Short on purpose. A `g` on the long-lived target reaches no stop, so this is the watchdog
/// forcing a break — which is a state worth generating, not one to avoid — and it keeps a round
/// to seconds rather than minutes.
const WAIT_MS: u32 = 2_000;

/// The two targets, and the difference between them is the point.
///
/// The short one exits on the first resume, so its exit *races the pump* — the windbg-mcp#242
/// case. The long one never ends on its own, so every resume bounds out and the session has to
/// survive being broken into repeatedly.
const TARGETS: &[&str] = &["cmd.exe /c exit", "cmd.exe /c ping -n 30 127.0.0.1"];

/// `DEBUG_STATUS_NO_DEBUGGEE`, spelled out rather than asked of the crate under test.
///
/// `DebugEngine::has_target` answers the same question, and using it here would make the oracle
/// agree with the code by construction — a fuzzer that shares its subject's notion of the state
/// cannot report a wrong one. Reading the raw status is also what lets this run unchanged against
/// a build from *before* the fix, which is the only way to know it would have found anything.
const NO_DEBUGGEE: u32 = 7;

/// One thing the fuzzer can do to a session.
#[derive(Clone, Copy, Debug)]
enum Step {
    /// The typed path: `execute_and_wait`, which is what a `go`/`step` tool is built on.
    Resume(&'static str),
    /// The raw hatch, driven the way windbg-mcp's `execute` tool drives it — a plain `Execute`,
    /// then a `settle` to pump whatever it left running. Both halves, because the bug they were
    /// written for lives in the seam between them.
    Raw(&'static str),
    /// `run_to_address`, the third wait, at a symbol that may or may not be reached.
    RunTo(&'static str),
    /// A settle with nothing before it: the "there was nothing to pump" branch.
    Settle,
    /// Ctrl+Break and then a resume, which is the race the interrupt drain is about.
    InterruptThenResume,
}

/// The corpus.
///
/// Deliberately *not* a grammar over command text. These are the shapes that have produced a
/// state worth being in: something that resumes, something that resumes without saying so,
/// something that ends the target, something that arms a breakpoint whose command resumes again,
/// and the read-only commands that used to be the only ones still answering on a half-dead
/// session.
const CORPUS: &[Step] = &[
    Step::Resume("g"),
    Step::Resume("p"),
    Step::Resume("t"),
    Step::Resume("gu"),
    Step::Raw("g"),
    Step::Raw("p"),
    Step::Raw("t"),
    // Two resumes in one string: the second meets an engine that is already running, which is
    // where DbgEng answers 0x8000FFFF and is *right* to.
    Step::Raw("g; g"),
    // Execution reached without a command name saying so — the reason none of the guards reads
    // the text.
    Step::Raw(".if (1) { g }"),
    Step::Raw("bp ntdll!NtCreateFile \".echo FUZZ-HIT; g\""),
    Step::Raw("bp ntdll!NtCreateFile"),
    Step::Raw("bc *"),
    Step::Raw("k 3"),
    Step::Raw("r"),
    Step::Raw("lm"),
    Step::Raw(".echo alive"),
    Step::Raw(".lastevent"),
    Step::Raw("sxe ld:ntdll.dll"),
    // The four that take the target away, each by a different route: two immediately, one on the
    // next resume, one by ending the debugger's session.
    Step::Raw(".detach"),
    Step::Raw(".kill"),
    Step::Raw("q"),
    Step::Raw("qd"),
    Step::RunTo("ntdll!NtCreateFile"),
    Step::RunTo("ntdll!NtTerminateProcess"),
    Step::Settle,
    Step::InterruptThenResume,
];

/// What the session is after a step. Not a health scale — two states, and the fuzzer's whole job
/// is that the engine is always unambiguously in one of them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Health {
    /// Holds a target, is stopped, and answers.
    Holding,
    /// Holds none, and says so on every road in. Terminal: the round ends here.
    Gone,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // The clock reading is taken as it comes. It used to be `| 1` as well, which cost a bare bit
    // of entropy and, worse, meant a run seeded from the clock could never be an even seed — so
    // half the space was unreachable by default as well as by `--seed`. [`Rng::new`] is where the
    // one forbidden state is handled, and it is the only place that needs to.
    let seed = numeric(&args, "--seed").unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|since| since.as_nanos() as u64)
            .unwrap_or(0x243F_6A88_85A3_08D3)
    });
    let rounds = numeric(&args, "--rounds").unwrap_or(20);
    let steps = numeric(&args, "--steps").unwrap_or(8);

    println!("session_fuzz: seed {seed}, {rounds} rounds of up to {steps} steps");
    println!("replay this run with: cargo run --example session_fuzz -- --seed {seed}");
    println!();

    let mut rng = Rng::new(seed);
    let mut violations = 0u64;
    for round in 1..=rounds {
        let target = TARGETS[rng.below(TARGETS.len() as u64) as usize];
        println!("---- round {round}/{rounds}: {target}");
        flush();

        let engine = DebugEngine::new();
        if let Err(why) = engine.launch_process(target) {
            // Not a violation: a launch can fail for reasons that have nothing to do with the
            // session invariant (the machine, the image, a previous target still winding down).
            println!("     launch failed, skipping the round: {why}");
            continue;
        }

        let mut sequence = Vec::new();
        for _ in 0..steps {
            let step = CORPUS[rng.below(CORPUS.len() as u64) as usize];
            sequence.push(step);
            println!("     {}", describe(step));
            flush();

            run(&engine, step);
            match check(&engine) {
                Ok(Health::Holding) => {}
                Ok(Health::Gone) => {
                    println!("     (the target is gone; the round ends here)");
                    break;
                }
                Err(violation) => {
                    violations += 1;
                    println!();
                    println!("!! VIOLATION on round {round}: {violation}");
                    println!("!! target:   {target}");
                    println!("!! sequence: {sequence:?}");
                    println!("!! replay:   --seed {seed} --rounds {rounds} --steps {steps}");
                    println!();
                    break;
                }
            }
        }
        let _ = engine.end_session();
    }

    flush();
    match violations {
        0 => println!("\nno violations in {rounds} rounds (seed {seed})"),
        n => {
            println!("\n{n} violation(s) — see above (seed {seed})");
            std::process::exit(1);
        }
    }
}

/// Runs one step. Its `Result` is discarded on purpose: a command failing is not a violation —
/// `bp` on an unresolvable symbol, a `g` refused because the engine is already running, a
/// `run_to_address` that never arrives are all ordinary. What is checked is the state left
/// behind, by [`check`].
fn run(e: &DebugEngine, step: Step) {
    match step {
        Step::Resume(command) => {
            let _ = e.execute_and_wait(command, WAIT_MS);
        }
        Step::Raw(command) => {
            let _ = e.execute_command_bounded(command, WAIT_MS);
            // The settle is half of what this step is: windbg-mcp runs one after every raw
            // command, and the seam between the two is where the reported bug lived.
            let _ = e.settle(WAIT_MS);
        }
        Step::RunTo(symbol) => {
            if let Some(address) = evaluate(e, symbol) {
                let _ = e.run_to_address(address, WAIT_MS);
            }
        }
        Step::Settle => {
            let _ = e.settle(WAIT_MS);
        }
        Step::InterruptThenResume => {
            let _ = e.interrupt_handle().interrupt();
            let _ = e.execute_and_wait("g", WAIT_MS);
        }
    }
}

/// The invariant, asked of the engine after every step.
///
/// Each arm below is a state that has actually shipped. "Says it holds none on one road and
/// answers on another" is the half-dead session of windbg-mcp#242; "holds a target and reads as
/// running" is windbg-mcp#226's unpumped resume, which leaves every later `g` failing
/// `0x80040205`; and an unreadable status is neither answer, which is worth knowing about rather
/// than defaulting.
fn check(e: &DebugEngine) -> Result<Health, String> {
    let status = e
        .execution_status()
        .map_err(|why| format!("the engine could not say what state it is in: {why}"))?;

    if status == NO_DEBUGGEE {
        // Every road in has to give the same answer. A read that succeeds here, or a resume that
        // reaches DbgEng, is the chain the guard exists to end — and the resume is the one that
        // used to be an access violation, so reaching this line at all is part of the assertion.
        for command in ["k 3", "r", ".echo alive"] {
            match e.execute_command_bounded(command, WAIT_MS) {
                Err(DbgEngError::NoDebuggee) => {}
                Err(other) => {
                    return Err(format!(
                        "the target is gone and `{command}` answered `{other}` instead of saying so"
                    ));
                }
                Ok(run) => {
                    return Err(format!(
                        "the target is gone and `{command}` answered anyway: {:?}",
                        run.output
                    ));
                }
            }
        }
        match e.execute_and_wait("g", WAIT_MS) {
            Err(DbgEngError::NoDebuggee) => {}
            other => {
                return Err(format!(
                    "the target is gone and a resume was not refused: {other:?}"
                ));
            }
        }
        match e.settle(WAIT_MS) {
            Ok(None) => {}
            other => {
                return Err(format!(
                    "the target is gone and settle found work: {other:?}"
                ));
            }
        }
        return Ok(Health::Gone);
    }

    // Holding one. Nothing may be left un-pumped: every step above either waits itself or
    // settles, so an engine reading as running here is a resume that moved nothing, which is
    // exactly the state that refuses all later execution control.
    match e.is_running() {
        Ok(false) => {}
        Ok(true) => {
            return Err(
                "the engine holds a target and reads as running — a resume was left unpumped"
                    .to_string(),
            );
        }
        Err(why) => return Err(format!("the run state could not be read: {why}")),
    }
    // And it answers. `.echo` rather than `k`, because a target can legitimately be somewhere
    // with no stack to walk while the session itself is perfectly healthy.
    e.execute_command_bounded(".echo alive", WAIT_MS)
        .map_err(|why| format!("the engine holds a target and refused `.echo`: {why}"))?;
    Ok(Health::Holding)
}

/// A symbol's address, through the evaluator, so an unresolvable one simply skips the step.
///
/// `? <expr>` answers `Evaluate expression: <decimal> = <hex>`, and the hex half carries WinDbg's
/// backtick between the two halves of a 64-bit value.
fn evaluate(e: &DebugEngine, expr: &str) -> Option<u64> {
    let out = e.execute_command(&format!("? {expr}")).ok()?;
    let tail = out.split("Evaluate expression: ").nth(1)?;
    let hex = tail.split(" = ").nth(1)?.trim().replace('`', "");
    u64::from_str_radix(hex.split_whitespace().next()?, 16).ok()
}

fn describe(step: Step) -> String {
    match step {
        Step::Resume(command) => format!("resume        `{command}`"),
        Step::Raw(command) => format!("raw + settle  `{command}`"),
        Step::RunTo(symbol) => format!("run_to        {symbol}"),
        Step::Settle => "settle".to_string(),
        Step::InterruptThenResume => "interrupt, then resume".to_string(),
    }
}

fn flush() {
    let _ = std::io::stdout().flush();
}

fn numeric(args: &[String], flag: &str) -> Option<u64> {
    let at = args.iter().position(|arg| arg == flag)?;
    args.get(at + 1)?.parse().ok()
}

/// xorshift64*, so a seed replays a run and no dependency is added for it.
///
/// Randomness quality is beside the point here: what the seed buys is a failing sequence someone
/// else can reproduce, which a `HashMap`-ordering-style "random" would not.
struct Rng(u64);

impl Rng {
    /// **The forbidden state is zero, not "even".**
    ///
    /// This was `seed | 1`, which quietly folded every even seed onto the odd one above it: `42`
    /// and `43` were one run, `6` and `7` were one run, and half of what `--seed` can name walked
    /// a sequence something else already walked. That defeats the flag: its whole purpose is to
    /// let someone reproduce a failing run and then *vary* it, and a seed that silently aliases
    /// looks like a new sequence while covering nothing new.
    ///
    /// Measured over the first 512 seeds, drawing ten corpus steps each: `seed | 1` gives **256**
    /// distinct walks and this gives **512**. Running a SplitMix64 finalizer over the seed first
    /// also gives 512, and was tried and dropped — adjacent seeds already walk differently
    /// without it, so it would be machinery bought with nothing. The one collision left is `0`
    /// against the constant it maps to, which is the state xorshift64* cannot be given rather
    /// than a pair of ordinary seeds.
    ///
    /// Found downstream, where this example had been ported to drive windbg-mcp's tool surface
    /// and the seed is a small integer someone types while scanning
    /// ([windbg-mcp#268](https://github.com/glslang/windbg-mcp/pull/268)).
    fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x243F_6A88_85A3_08D3
        } else {
            seed
        })
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound.max(1)
    }
}
