# Architecture

MapleDumper is a single engine crate with two thin presentation shells. All algorithms (PE parsing,
decoding, scanning, resolution, scoring, memory access) live once in `maple-core`; the CLI and the
desktop app delegate to it, so a fix lands everywhere.

## Crates

| Crate | Role |
|-------|------|
| `maple-core` | The engine. Pattern grammar and parser, the AVX2/scalar masked scanner and the multi-pattern index, the decode-driven resolver, the scan pipeline, the Signature Maker (generation, cross-build validation, holdout, negative corpus, scoring), the on-disk PE reader, live process/memory access (Windows), and the output writers. |
| `maple-cli` | A `clap` front end with one module per command (`scan`/`lint`/`diff`/`asm`/`mksig`/`profile`/`unpack` under `commands/`), a stable 0-6 exit-code contract, and `--json` output. |
| `maple-app` | A Tauri v2 desktop workspace: a Rust backend wiring commands to per-feature modules, each delegating to `maple-core`, and a webview frontend. |

## Dependency direction

`maple-cli -> maple-core` and `maple-app -> maple-core`. The engine is self-contained. Within the
engine: the Signature Maker uses the scanner, resolver, PE reader, and memory abstraction; the resolver
uses the memory abstraction and `iced-x86`; the scan pipeline composes the scanner, resolver, and
output writers.

## Key modules (`maple-core/src`)

- `pattern.rs` parses pattern text (strict and lenient) into a `Signature` plus an optional typed
  resolve plan.
- `scanner.rs` compiles a `Signature` to a `CompiledPattern` anchored on its rarest fixed byte, and
  matches it with an AVX2 path (runtime-detected, scalar fallback) or a single-pass multi-pattern index.
- `resolver.rs` lowers a resolve plan to a granular operation and executes it by decoding instructions
  (never by byte-scanning), with a typed failure taxonomy.
- `engine/` orchestrates the scan (`scan.rs`): reader threads stream fixed-size blocks through a
  bounded channel while a rayon pool scans them, then resolves matches and records partial-read gaps.
  `types.rs` holds the result vocabulary and `profile.rs` the read/scan/resolve benchmark pipeline.
- `fileimage.rs` is a bounds-checked, fuzz-tested PE32/PE32+ reader (sections, relocations, pack
  detection, RVA mapping).
- `process.rs` (Windows) enumerates processes, modules, and memory regions with least-privilege,
  RAII-wrapped handles and partial-read tolerance.
- `sigmaker/` is the Signature Maker: `mod.rs` (generation and the cross-build validation loop),
  `scoring.rs` (independent sub-scores blended into a final score the grade is read from),
  `identity.rs` (cross-build callee similarity), `types.rs` (the report data model), and the
  relocation anchors `identity` (string), `imports`, `callers`, `vtable`, and `encoding`.

## Data flow (live scan)

A target is attached (by PID, name, or window class) or a client `.exe` is read from disk. Executable
regions are enumerated, patterns are compiled, and the pipeline scans them into matches. Each match is
resolved to a module-relative RVA (ASLR-immune) and validated against its expected section; only
unambiguous, in-module results are exportable. Output is sorted, de-duplicated, and emitted as a C/C++
header, a plain report, or a Cheat Engine table.

## Data flow (signature generation)

Several client builds are opened as PE images. The generator proposes candidates (direct match, branch
or pointer anchors, string anchors), masks volatile operands and relocated addresses, and keeps only
candidates that resolve the same target uniquely in every build. Candidates are scored into independent
sub-scores blended into a final score, the A-F grade is read off that score, and a negative corpus and
leave-one-out holdout adjust confidence. When no byte pattern survives, the relocation anchors pin the
function by a recompile-stable handle and mint a fresh per-build pattern.

## Concurrency and persistence

The scan pipeline uses `std::thread::scope` with bounded reader threads, a bounded channel, and a rayon
pool; results are collected and sorted for determinism. The desktop app runs commands on
`spawn_blocking` with per-job cancellation tokens, and stores scan history in a local SQLite database
with `user_version` migrations and content-hash de-duplication.

## Notes for contributors

Preserve the load-bearing safety properties: the fuzzed PE parser, the differentially-tested AVX2
matcher, the decode-driven resolver, the export gate that prevents an ambiguous match from becoming a
trusted offset, and the one-directional scoring (grade is always the band of the final score). See
`.github/CONTRIBUTING.md` for the build and quality bar.
