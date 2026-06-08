# Changelog

All notable changes to this project are documented here. The format is based on Keep a Changelog, and
the project aims to follow Semantic Versioning while in its 0.x line.

## [Unreleased]

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
