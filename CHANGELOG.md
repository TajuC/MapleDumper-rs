# Changelog

All notable changes to this project are documented here. The format is based on Keep a Changelog, and
the project aims to follow Semantic Versioning while in its 0.x line.

## [Unreleased]

## [0.6.0] - 2026-06-10

A desktop-app release: ship the GUI, surface the engine's full analysis, and add a deep per-function
inspector so an advanced user can investigate what the engine did and why.

### Added
- The **desktop app installer** is now built and published with every release (Tauri/NSIS,
  `MapleDumper_<version>_x64-setup.exe`, bundling the WebView2 bootstrapper), alongside the CLI.
- A deep **Investigate** inspector for any address: the enclosing function's CFG-lite shape, inbound
  cross-reference count, callers and callees from the decode-verified call graph (clickable to navigate),
  the imported APIs it calls, its referenced strings and distinctive constants, a re-scannable string
  anchor, vtable membership (slot / table / count) with a best-effort MSVC RTTI class name, and a NASM
  disassembly listing. Backed by a new public `inspect_function` engine API.
- An **address-display setting** (RVA / Absolute / Both); absolute = image base + RVA, applied across the
  signature maker and the inspector.

### Changed
- The signature maker now **surfaces the full analysis** instead of discarding it: a declined cross-build
  result explains itself (template-clone family vs. partial byte coverage), lists the structural family per
  build with a minted AOB to copy, shows the relocation evidence ledger (which anchor located it, who
  corroborated, any conflict), and adds the per-build minted AOB. Result addresses are clickable into the
  inspector.

## [0.5.0] - 2026-06-09

A cross-version fingerprinting release: the relocation engine moves from a single-anchor fallback chain to
a globally-informed, ensemble-validated identification engine, and the v95 class refactor that defeated the
structural matchers is now bridged. Every change is validated on the real GMS unprotected lineage
(v61.1 to v111.1) with the false-positive floor held at zero and the golden snapshot byte-stable.

### Added
- Call-graph seed densification that **bridges the v95 break**: the global alignment now seeds with the
  import-set and rare-constant 1:1 channels in addition to strings, so propagation reaches across the major
  class refactor that string-only seeding could not. Measured on the real lineage, reverse-consistent at
  zero confirmed false positives: v83 to v95.1 propagation 0 to 25, v83 to v91 66 to 780.
- An opt-in static data-flow strand channel (register- and order-invariant computation hashing), enabled
  with `MAPLE_STRAND_CHANNEL`. It holds the false-positive floor at zero where it fires but adds no coverage
  the cheaper channels do not already carry, so it ships off the default path.
- Real-corpus `--ignored` harnesses: a graph seed-densification measurement, a strand-efficacy and
  false-positive sweep, and a fingerprint-scan equivalence oracle.

### Changed
- The fingerprint scan decodes each code section **once** instead of re-decoding every overlapping window,
  cutting relocation-generation time by about 20 percent (criterion: 137.8 to 112.3 ms at 256 KiB, 555 to
  439 ms at 1 MiB). Proven output-identical to the previous scan at every instruction boundary and field on
  v61/v83/v95.1/v111, so behaviour, grades, and the false-positive floor are unchanged.
- `sigmaker/mod.rs` decomposed into a thin orchestrator: the byte-path minting moved to `bytepath.rs`
  (1234 to 618 lines), completing the module split.

## [0.4.0] - 2026-06-08

An audit-remediation and hardening release driven by an external code review.

### Added
- 32-bit (x86) support is verified: a PE32+ image base that cannot fit a 32-bit address space is
  rejected rather than truncated, and a `win32` CI job builds and tests the engine and CLI for
  `i686-pc-windows-msvc`.
- Community health files (CONTRIBUTING, SECURITY, CODE_OF_CONDUCT), issue and pull request templates,
  and a Dependabot configuration; `ARCHITECTURE.md`, `CHANGELOG.md`, `.editorconfig`, and a
  vendored-Monaco manifest with aggregated third-party license notes.
- A tag-triggered release workflow that publishes the CLI with an embedded dependency list
  (`cargo auditable`), a CycloneDX SBOM, and SHA-256 checksums.
- `cargo-deny` policy gating advisories, licenses, bans, and sources; a forced-AVX2 scanner test; a
  frontend render job and public-API doctests in CI; and two `--ignored` real-corpus diagnostics (a
  cross-version coverage/false-positive sweep and a grade-calibration harness).
- `maple_core::scan_live` (shared live-scan orchestration), `output::export` (single format
  dispatcher), `Arch::parse`/`arch_mismatch` (validated, shared), and `apply_negatives`.

### Changed
- Hardened CI: least-privilege token, SHA-pinned actions, clippy `--all-features`, doctest and
  all-targets test steps, and dependency caching.
- The CLI and desktop app share one live-scan path and one architecture-mismatch message instead of
  drifting copies; the negative corpus is scored once; export-format selection is dispatched once.
- The profiler measures the shipping scanner; the history connection uses one poison-recovering lock.
- Reframed the README cross-version efficacy figures around measured sweep results.

### Fixed
- `module_arch` rejects ARM and other non-x86/x64 machines instead of mapping them onto a bitness.
- The negative-corpus re-grade reads typed `packed`/`gated` flags instead of substring-matching reasons.
- Bounds and overflow hardening: checked `rel32` slicing, saturating region arithmetic, and the
  compiled-pattern anchor encoded as a non-optional field.
- The desktop workspace value cell is HTML-escaped consistently with every other field.

## [0.3.0] - 2026-06-08

### Added
- Cross-version function relocation: when a byte pattern no longer matches a recompiled build, the
  Signature Maker relocates the function by a recompile-stable handle (referenced string, imported-API
  set, string-anchored caller, C++ vtable structure with constructor grounding, or encoding
  fingerprint) and mints a fresh per-build AOB, reporting the version ranges each pattern covers.

## [0.2.0] - 2026-05-29

### Added
- Signature Maker scoring with independent sub-scores, cross-build validation, holdout, negative
  corpus, and string anchors; the desktop workspace and history; structured resolution traces.

## [0.1.3] - 2026-05-28
## [0.1.2] - 2026-05-27
## [0.1.1] - 2026-05-27

### Added
- Iterative hardening of the scanner, resolver, PE reader, CLI, and desktop app across the early
  releases.

## [0.1.0] - 2026-05-26

### Added
- Initial Rust implementation: AVX2 masked scanner, process reader, decode-driven resolver,
  module-relative RVA output, the CLI, and the desktop GUI.
