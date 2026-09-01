# Repository Guidelines

## Project Structure & Module Organization

This Rust 2024 library gives typed access to a WinDbg/DbgEng debug session, plus allocator walkers built on one. Public modules live in `src/`: `dbgeng.rs` (the session driver), `pool.rs` with `pool/` (kernel pool walking), `heap.rs` (user-mode Segment Heap), and `allocator.rs` (decoding shared by both). `pool_extension.rs` holds the `!dbgscope.poolmap` WinDbg extension exports. `examples/` holds scratch Debug Engine smoke tests, not public API. Docs are `README.md` and `CLAUDE.md`.

The crate is Windows-only in practice: most modules use the `windows` crate directly and are not broadly `cfg`-gated.

## Build, Test, and Development Commands

- `cargo build --verbose`: build the library for the active Windows target.
- `cargo fmt --all -- --check`: verify formatting, matching CI.
- `cargo fmt --all`: apply Rust formatting.
- `cargo nextest run --verbose`: preferred test runner and CI path.
- `cargo test`: standard fallback test runner.
- `cargo miri test --verbose`: nightly/Miri check for unsafe-code issues. CI runs it on merges to `main`, weekly, and on demand — **not on pull requests** (see `.github/workflows/miri.yml`), so run it yourself when a change touches unsafe code.
- `cargo run --example kdtest -- "<kd connection>"`: run the kernel-debugging smoke test.
- `cargo run --example breakpoint_probe -- all`: re-validate the breakpoint API against a real engine. Copy the engine DLLs into `target/debug/examples/` first — an example loads from its own directory, so otherwise it gets System32's `dbgeng.dll` and silently measures the wrong thing.

There is no build script and no assembler step; both left with the exploitation half of this crate.

## Coding Style & Naming Conventions

Use `rustfmt` defaults. Prefer `snake_case` for functions and variables, `PascalCase` for types, and concise module-level APIs. Model library failures with `Result`/`Option` and `thiserror` instead of panics. Keep `unsafe` blocks small, localized, and tied directly to Windows FFI calls. When adding Windows APIs, update the feature list under `[dependencies.windows]` in `Cargo.toml`.

Assembly uses MASM syntax for x86_64 and ARMASM syntax for ARM64.

## Testing Guidelines

Place focused unit tests in the module being tested under `#[cfg(test)]`. Test names use `test_*`. Pool and heap decoding is the UB-prone code here — it reads kernel structures out of byte slices with no `unsafe` in sight — which is why `miri.yml` exists and why a change there wants a Miri run.

## Commit & Pull Request Guidelines

Commit subjects use lowercase prefixes seen in history, such as `fix:`, `feat:`, `docs:`, `style:`, `refactor:`, `test:`, `perf:`, and `chore:`. Keep the summary imperative and specific.

Pull requests should describe the behavioral change, call out architecture-impacting changes, link related issues when applicable, and include the commands run. Ensure formatting and relevant Windows tests pass before requesting review.

## Security & Configuration Notes

This repository contains exploit-research utilities. Keep examples scoped to controlled research environments, avoid committing generated build artifacts or local debugger state, and document any new environment variables alongside the command that consumes them.
