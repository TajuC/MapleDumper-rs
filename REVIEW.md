# Review guide for a full-codebase audit

This branch exists only to make the entire tree appear as one diff against an empty base, so
`/code-review ultra <this PR#>` audits the whole repository rather than a recent change set. Delete the
`empty-base` and `full-audit` branches after the audit.

## Threat model
MapleDumper-rs consumes UNTRUSTED input: on-disk PE client binaries (the signature maker and `mksig`)
and live process memory (the Windows scanner). Parsing and resolving must never panic, read out of
bounds, or trust attacker-controlled sizes or offsets.

## Highest-value areas to scrutinize
- `crates/maple-core/src/fileimage.rs`: hand-rolled PE parser over untrusted files. Check every
  header, section, relocation and import read for bounds and overflow; it must return Err, never panic
  or read out of bounds.
- `crates/maple-core/src/process.rs`: Windows process attach, `NtReadVirtualMemory`, handle and
  privilege handling, partial-copy semantics. Unsafe FFI: check handle lifetimes, buffer sizes, and
  error mapping.
- `crates/maple-core/src/engine.rs`, `scanner.rs`: the scan and resolve pipeline, chunking, partial
  reads, RVA bounds (`checked_rva`), and parallelism (no data races or UB).
- `crates/maple-core/src/resolver.rs`: iced-x86 instruction decoding and the typed resolve ops. Check
  operand-index and offset handling, and that a malformed instruction stream cannot mis-resolve or
  panic.
- `crates/maple-core/src/sigmaker/`: cross-build scoring (`scoring.rs`), `FnIdentity::similarity`, and
  string-anchor resolution. Check scoring soundness (grade derived from `final_score`, gates, negative
  cap) and that anchor resolution over untrusted images is bounds-safe.
- `crates/maple-app/src/fileio.rs`: Tauri file IO. Path canonicalization, extension allowlist, and
  traversal / NUL / alternate-data-stream rejection. Look for any bypass.
- `crates/maple-app/src/scan.rs`, `history.rs`: the command layer and SQLite. Confirm SQL is
  parameterized (no injection) and review the arch-mismatch and warnings paths.
- `crates/maple-app/frontend/*.js`: DOM `innerHTML` sinks fed untrusted strings (signature names,
  paths, traces). Confirm `esc()` is applied at every sink, and review the CSP.

## Severity guidance
P0: memory unsafety, out-of-bounds read or write, panic on untrusted input, command or SQL injection,
path-traversal bypass, privilege misuse. P1: an incorrect resolve or score that silently exports a
wrong offset. P2: robustness and usability. Skip style nits unless they hide a correctness bug.
