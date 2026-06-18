# MapleDumper

Cross-version signature and offset toolkit for MapleStory clients.

[![CI](https://github.com/TajuC/MapleDumper-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/TajuC/MapleDumper-rs/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Platform: Windows](https://img.shields.io/badge/platform-Windows%20x64%20%7C%20x86-informational)
![Rust 2024](https://img.shields.io/badge/rust-2024%20edition-orange)

MapleDumper finds, generates, and validates byte signatures and offsets that survive client patches.
It attaches to a running process, scans the target module with an AVX2-accelerated masked matcher,
resolves matches into stable module-relative RVAs, and emits a reusable C/C++ header, a Cheat Engine
table, or a plain report. Its headline feature, the **Signature Maker**, reads several client builds
straight from disk and produces the highest-confidence pattern that resolves the same target in
every version.

It ships as a frameless desktop workspace that keeps a local history of every scan, alongside a
scriptable command-line tool. Both are built on the same engine crate.

> **Terminology.** An **AOB** (array of bytes) is a sequence of byte values, some fixed and some
> wildcarded, used to locate code or data in memory. A **pattern** in MapleDumper is a named AOB
> plus an optional resolver suffix that says how to turn a raw match into a useful address. These
> two terms are used throughout the documentation.

## Why MapleDumper is different

- **Cross-version by design.** The Signature Maker validates each candidate against every supplied
  build, so the signature it ships is the one that already resolves the same target in all of them,
  not a guess from a single client.
- **Instruction-aware and relocation-aware.** Signatures are masked using `iced-x86` instruction
  decoding and the PE base relocation table, so volatile operands and relocated addresses become
  wildcards instead of brittle fixed bytes.
- **Deterministic output.** Scans and generated signatures sort and de-duplicate to a stable order,
  which makes diffs and version comparisons meaningful.
- **Offline and local.** The desktop app makes no network requests. A Content-Security-Policy blocks
  every remote origin, and the scan history lives in a local SQLite database.

## Feature highlights

**Engine (`maple-core`)**

- Read/scan pipeline. A few reader threads stream the target's memory in parallel into a bounded
  channel while the rayon thread pool scans each block as it lands, so reading and scanning overlap.
  Work units are kept small (256 KiB) so the scan spreads evenly across every core.
- AVX2 masked matcher that anchors each pattern on its rarest fixed byte (a static frequency table),
  with a scalar fallback selected at runtime.
- Scans executable regions only by default, with a one-switch fallback to the full module, so a live
  dump reads far fewer bytes.
- Wait-and-attach. Point it at a process that is not running yet and it polls, then attaches the
  instant the process and module appear (cancellable).
- Suffix-driven resolvers: RIP-relative and `rel32` pointers, nested calls, struct displacements,
  and packet-header immediates, arch-aware for x64 and x86.
- Output as deterministic, sorted, de-duplicated module RVAs, immune to ASLR.
- Unpack pipeline. Turn a Themida-packed client into a clean, analyzable binary: a native static
  clean phase (repoint the exception directory to the real `.pdata`, rebuild the IAT directory, strip
  the dead packer sections) plus verification gates, with the inherently dynamic dump step
  orchestrated through unlicense. The clean phase is deterministic and code bytes are never touched.

**Desktop workspace (`maple-app`)**

- Frameless dark dashboard: target toolbar, status-colored results table grouped by category, and a
  metadata inspector (RVA, absolute address, signature, type, hit count, notes).
- Signature Maker view. Drop in several client builds and generate a cross-version signature without
  leaving the app: target by signature, by address, or both, queue many at once (one per line), and
  cross-validate a signature against the address it should resolve to. Files are checked for packing
  as you add them, and the chosen result saves straight into your pattern list.
- Version history. Every scan is saved to a local SQLite database, grouped by build (a content hash
  of the code section), so many client versions stay organized. Identical re-scans are de-duplicated.
- Compare across versions. Open any scan, compare any two builds (moved, new, or removed offsets), or
  line every version up in a matrix to track an offset across the whole timeline. Click a changed
  symbol to see its bytes and x86/x64 disassembly side by side.
- Assembly scan. Find code by instruction instead of bytes: type lines of assembly with wildcards
  (`*` zero-or-more, `?` one character, `^` line start, `$` line end), and it disassembles the target
  and lists every address where those instructions appear back to back.
- Unpack panel. Point it at a packed client (or an existing dump) and produce a cleaned binary with
  live dump, clean, and verify progress and a results card: OEP, import count, `.pdata` entries,
  virtualization sample, `.text` identity, and output size.
- Built-in pattern manager (add, edit, delete, notes) and a syntax-highlighted editor.
- Privacy mask. One click hides every signature, name, address, category, and note for screenshots.
  Pick blur, or a showcase mode that swaps in realistic fake values instead. Visual only; the real
  data is untouched.
- Five interface languages: English, Japanese, Chinese, Korean, and Hebrew (right to left).
- Fully offline. The editor and the history database are local, and a Content-Security-Policy blocks
  every remote origin.

**Command line (`maple-cli`)**

- A subcommand per task (`scan`, `lint`, `diff`, `asm`, `mksig`, `profile`, `unpack`), suitable for
  scripting and CI. Run `mapledumper help <command>` for the flags of any one.
- Offline helpers that need no target: `lint` flags weak signatures, `diff` reports which offsets
  moved between two dumps, and `profile` breaks a live scan into read/scan/resolve timing.
- `asm` runs the same instruction scan as the desktop Assembly scan, over an optional address range.
- `mksig` runs the Signature Maker from the command line, with `--json` output for tooling.
- `unpack` turns a packed client into a clean binary: clean an existing dump (`--clean-only`, no
  external tool) or run the full packed-to-min flow (dump via unlicense, then clean and verify).
- A `maple.conf` in the working directory (or `--config <file>`) supplies defaults for the process,
  module, arch, pattern file, and output directory; explicit flags always win.

## Signature Maker

A single-version signature breaks when the next client patch shifts code or rewrites an instruction.
The Signature Maker addresses this by working across builds:

1. Feed it two or more client `.exe` files. It reads each one as a PE image from disk, no running
   process required.
2. Choose a target by an existing AOB to harden, by a reference address (RVA) in one build, or both
   at once.
3. It searches for three kinds of anchor: the target's own bytes (Direct), a call or jump to the
   target (`_CALL` / `_JMP`), and a memory reference to the target (`_PTR`).
4. Each candidate is masked using instruction decoding and the relocation table, then validated
   against every build for a unique match and a callee that stays similar across builds.
5. Each candidate is scored on independent measures (uniqueness, recompile stability, byte entropy,
   validated semantic content, resolver confidence, and cross-build agreement), blended into a single
   `final_score`, and graded A through F from that score. Candidates sort deterministically and the
   best one is chosen.

The desktop **Signature Maker** view runs the whole flow interactively: queue many targets in a single
run (one signature or address per line), and switch on **Cross-validate** to pair each signature with
the address it should resolve to and confirm they agree, the quickest way to check that a hand-written
AOB still lands where you expect. The command-line `mksig` drives the same generator for scripting
and CI.

The letter grade is read off `final_score` (it is not chosen first and back-filled): a
content-validated anchor (a branch or RIP-relative reference whose target is code in every build with
a consistent callee) scores into **A**; a reloc-safe but unvalidated reference (a direct match, or a
stable data/import reference) lands around **B**; absolute, unresolved, or cross-build-inconsistent
references are weaker (**C**); a packed input is capped at **D**; and hard gates (too few fixed bytes,
low fixed-byte ratio, no opcode bytes, an unsupported relocation) force **F**. The report shows each
sub-score, the `final_score`, and the reasons behind them, plus per-build evidence (match RVA,
resolved target, target kind, and the callee fingerprint similarity to the reference build).

The callee comparison is a pragmatic *similarity*, not equality and not a decompiler. It blends an
order-preserving comparison of the mnemonic stream (the Dice ratio of their longest common
subsequence, so an inserted or shifted instruction costs one position instead of desynchronising the
rest), a CFG-lite block/call/branch/return shape, and the distinctive-constant and string-reference
sets. Absent evidence is treated as unknown rather than as a match: two functions that simply
reference no constants or strings are not counted as a perfect constant/string match. The numeric
similarity is banded High / Medium / Low: a High band reads as the same function, a Low band emits a
hard "callee diverges across builds" downgrade, and a Medium band is a softer "differs slightly"
note. This is a heuristic identity over a short instruction window, not a full control-flow or
data-flow analysis.

A **string anchor** matches on a read-only string the function references, so it is scored from
string-anchor evidence, not from the string's bytes as code-byte entropy: the string must resolve to
exactly one function in every required build, how specifically it pins that function (uniqueness of
resolution, reference count, with string length only a supporting factor), the cross-build stability
of the resolved target, and its callee similarity. It only earns A when validated across more than
one build (a single-build anchor is capped below A, since there is no cross-version evidence); a
missing string yields no candidate, and a generic or inconsistent one is downgraded.

Generation proves a signature is unique among the supplied builds, which does not by itself prove it
is specific. Pass a negative corpus of unrelated modules (`--negative` / `--negative-dir`) and the
chosen signature is scanned against each one. The downgrade scales with the number of distinct
modules it matches (the real generality signal), nudged up when one module matches it many times, and
the evidence (modules scanned, modules hit, total matches, and the maximum in any one module) is
recorded in the reason text and exposed in the JSON `negative_summary`. Any match lowers the
signature's uniqueness and final score, and can drop its grade.

### Relocating across major versions

When no single byte pattern survives every supplied build, the generator falls back through a layered
stack of recompile-stable anchors, tried strongest first and stopping at the first that pins the
function confidently:

- **String anchor** — a read-only string the function references (build-invariant, so it survives a
  recompile that moves every byte; see the measured cross-version coverage below).
- **Import anchor** — the distinctive set of imported APIs it calls.
- **Caller anchor** — a string-anchored *caller*, with the target re-found as the caller's callee whose
  identity matches, so a function with no handle of its own is reachable through one that has.
- **Vtable anchor** — for a C++ virtual method, the class's vtable is matched across builds by a
  distinctiveness-weighted, semi-global affine alignment of its per-slot fingerprints, so methods
  inserted or removed across a major version shift the match instead of breaking it; the target's slot
  is then read back, following any adjustor thunk. When a refactor drifts the table past the per-slot
  matcher, the table is **grounded through the constructor that installs it** (the constructor pins
  itself by a build-stable class string), recovering the vtable address directly.
- **Encoding and mnemonic fingerprints** — structural fallbacks for template-instance siblings.
- **Shortlist** — when nothing pins the function uniquely, a per-build list of the structural family it
  belongs to, each with a minted AOB, instead of a confidently-wrong answer.

A long version jump is crossed over the highest-confidence **chain** through intermediate builds rather
than one low-confidence leap, with every hop verified against the original so the chain cannot drift
method by method.

Each reached build is handed a freshly minted, operand-masked byte AOB, and the report collapses these
into **version-coverage ranges**: the contiguous runs of builds each AOB stays valid across, with a
fresh AOB minted automatically where the bytes break. A relocated signature can report, for example,
that one AOB works for v83 through v88 and a second takes over for v91 through v95. Coverage is partial
by design: the function is pinned in every build a confident path reaches and reported unreached in the
rest. Relocation is x86 / PE32.

## Desktop workspace

Launch `maple-app.exe`. In the Workspace view:

1. Enter the target process (for example `MapleStory.exe`) and the module to scan.
2. Pick the architecture. Leave **Wait for target** on to attach the moment the process starts, or
   switch to **Find by window class** to locate it by class instead of name. **Code regions only**
   (on by default) scans executable memory; turn it off to scan the whole module.
3. Load or edit your pattern list (Patterns or Editor views), then press **Start Scan**.
4. Inspect any result, then **Export** an `offsets.h`, a Cheat Engine table, or a plain report.
5. Every scan is saved to **History**: revisit it, compare two builds, open the **Matrix** to track
   an offset across all versions, or click a changed symbol for its bytes and disassembly.

Use the eye button in the title bar to hide signatures before sharing a screenshot, using either
blur or the showcase randomizer in Settings.

## Command line

```
mapledumper <command> [options]      ( --config <file> is accepted on any command )

  scan      attach to a process and dump offsets from a pattern file
  lint      check a pattern file for weak signatures
  diff      compare two saved dumps and report what moved
  asm       scan a live process by assembly instructions
  mksig     build a cross-version signature from client files on disk
  profile   measure the read/scan/resolve split against a live target
  unpack    turn a packed client into a clean binary (clean a dump, or dump then clean)

scan / profile share the attach and pattern options:
  --process <name>   attach by process name (e.g. MapleStory.exe)
  --class <class>    attach by top-level window class
  --pid <pid>        attach by process id (when several share a name)
  --module <name>    module to scan (default: process name)
  --patterns <file>  pattern file (default: patterns.txt)
  --arch <32|64>     architecture section to load (default: 64)
  --no-wait          do not wait for the process; fail if it is not running
  --timeout <secs>   give up waiting after this many seconds
  --lenient          accept malformed pattern lines instead of failing
scan also takes:
  --out <dir>        output directory (default: .)
  --ce               write update.txt as a Cheat Engine table
  --no-offsets       do not write offsets.h
  --json             emit the scan result as JSON on stdout (progress goes to stderr)
lint also takes:
  --json             emit the lint result as JSON on stdout
asm takes a positional <file> plus --from/--to <addr> to clip the address range.
mksig:
  --client <exe>     a client binary (repeat for each version)
  --client-dir <dir> add every .exe in a folder as a client
  --sig <aob>        target: locate this existing AOB in each client and harden it
  --ref <exe> --rva <hex>   target: an address in one reference client
  --min-fixed-ratio <f>     reject signatures below this fixed-byte ratio (default 0.30)
  --negative <exe> / --negative-dir <dir>   unrelated modules the result must not match
  --holdout          leave-one-out: regenerate per subset and confirm each held-out build matches
  --json / --json-out <path>   emit the full report as JSON
unpack takes a positional <input> plus:
  --out <path>       output path for the cleaned binary (required)
  --clean-only       input is an existing dump; skip the dynamic dump step
  --packed <exe>     packed original, for the strong .text-identity proof in --clean-only
  --unlicense <exe>  path to unlicense.exe (default: beside the input, then PATH)
  --keep-bound-iat / --keep-timestamp   keep the dump host's bound IAT / the timestamp
  --json             emit the full report as JSON

mapledumper help <command>   prints the full options for one command.
```

```
mapledumper scan --process MapleStory.exe --patterns patterns.txt --out .

# check signature quality without attaching to anything
mapledumper lint --patterns patterns.txt

# see which offsets moved between two game versions
mapledumper diff old/update.txt new/update.txt

# find code by instruction: every push, then a call, then test eax,eax (one instruction per line)
mapledumper asm --process MapleStory.exe find.asm

# generate a cross-version signature from several client builds
mapledumper mksig --client-dir ./clients --sig "48 8B ?? ?? ?? ?? ?? 48" --json

# unpack a packed client to a clean binary (dump via unlicense, then clean and verify)
mapledumper unpack 269.1.exe -o unpacked_269.1.min.exe
# or clean an existing dump with no external tool
mapledumper unpack --clean-only unpacked_269.1.exe -o clean.exe --packed 269.1.exe

# keep the common settings in maple.conf and just run the verb
printf 'process = MapleStory.exe\narch = 64\nout = dump\n' > maple.conf
mapledumper scan
```

### Exit codes

The CLI returns a stable, specific exit code so a script can branch on the outcome instead of
treating every nonzero result the same:

| Code | Meaning |
|------|---------|
| `0`  | success, nothing to flag |
| `1`  | internal error (unexpected) |
| `2`  | success with warnings (`lint` flagged weak signatures; `mksig` matched the negative corpus) |
| `3`  | a scan ran but some patterns were not found or matched without resolving |
| `4`  | a scan ran but at least one pattern matched in several places (ambiguous) |
| `5`  | invalid input: bad flags, bad config, bad/empty patterns, or the target could not be located |
| `6`  | access denied opening the target process (try running as administrator) |

`unpack` reuses these codes: `0` for a verified clean binary, `2` with advisory warnings only, `3`
when verification fails and no binary is written, `5` for invalid input or a missing `unlicense`, and
`6` for a denied read or write.

A scan with `--arch` set to the wrong bitness for the target module fails fast with an architecture
mismatch (exit `5`) rather than silently reporting everything "not found", and a region that reads
short is reported as a partial-read warning so a "not found" over unreadable memory is not mistaken
for a confident absence. With `--json`, each finding carries a structured resolution trace (resolver
kind, instruction offset, operand, computed target, section, and any failure reason).

## Quick start

1. Build the workspace: `cargo build --release`.
2. Desktop: run `target/release/maple-app.exe`, set a target process, press Start Scan.
3. CLI: run `target/release/mapledumper.exe scan --process <name> --patterns patterns.txt`.
4. Run elevated so `OpenProcess` and `SeDebugPrivilege` succeed against a protected target.

## Build

Requires a stable Rust toolchain (MSVC) and the Windows SDK. The desktop app needs the
[WebView2 runtime](https://developer.microsoft.com/microsoft-edge/webview2/) at run time, which
ships with current versions of Windows.

```
cargo build --release
```

- Desktop app: `target/release/maple-app.exe`
- CLI: `target/release/mapledumper.exe`

## Pattern syntax

Each non-empty line defines one signature. Accepted forms:

```
Name = AA BB ?? CC
Name: 0xAA ?? CC
Name AA ?? CC
```

- Wildcards: `?` or `??`. Commas between bytes are allowed.
- Notes and comments: text after `;` or `#` is captured as the symbol's note (and shown in the app);
  a leading `#` line is a comment.
- Architecture sections: `#32BIT` and `#64BIT` headers select which block is loaded. Patterns before
  any section apply to both.
- Category sections: `[name]` sets the namespace used for the following symbols in `offsets.h`
  (default `globals`).

A name suffix selects how a match is resolved. This is the compatibility form, kept so existing
pattern files keep working:

| Suffix   | Meaning                                                                 |
|----------|-------------------------------------------------------------------------|
| `_PTR`   | Resolve a RIP-relative load (`mov`/`lea`/`cmp`/SSE) or `rel32` jmp/call. |
| `_CALL`  | Treat the match as a call and resolve the (nested) call target.         |
| `_OFF`   | Extract a struct member displacement (emitted as a raw offset).         |
| `_HDR`   | Extract an immediate operand, for example a packet header opcode.       |
| (none)   | Emit the match address itself.                                          |

For an explicit, typed plan, append `@key=value` directives instead of relying on the name. `@kind`
selects the resolver as a value rather than parsing it from a suffix, and the strict loader parses
and validates every directive into the pattern's typed plan, rejecting an unknown key or value with
a line number:

```
CUserLocal = 48 8B 0D ?? ?? ?? ?? @kind=ptr @section=code @hits=unique
```

| Directive   | Values                                | Meaning |
|-------------|---------------------------------------|---------|
| `@kind`     | `ptr`, `call`, `off`, `hdr`, `direct` | The resolver kind, overriding any suffix. Drives resolution. |
| `@section`  | `code`, `data`, `rodata`, `import`    | The section the resolved target must land in. Enforced on a live scan: a target that lands in the wrong kind of memory is reported as a failure, not a clean find. |
| `@hits`     | `unique`, `any`, `>=N`                | How many matches the pattern should produce. |
| `@instr`    | a number                              | Which decoded instruction in the match window to resolve from. |
| `@operand`  | a number                              | Which operand of that instruction to read. |

See [patterns.sample.txt](patterns.sample.txt) for a worked example.

A live process exposes page protection but not its on-disk section table, so `@section` is enforced
at the granularity that protection allows: `code` requires the resolved target to land in an
executable region, and `data`, `rodata` and `import` require it to land outside one. When a target
fails its expected section the pattern is reported as `out of expected section` (and never exported),
which is the signal that the signature matched the wrong instruction.

**String-anchored patterns.** Instead of bytes, a pattern can name a read-only string the target
function references. The string survives a recompile that shifts the surrounding bytes, so it locates
the same function across client versions where a byte signature breaks:

```
StatWindow = @string=UI/UIWindow2.img/Stat
```

If no single string is unique to the function, add a second with `@also`; the target is the one
referencing both:

```
StatWindow = @string=UI/UIWindow2.img/Stat @also=UI/UIWindow2.img/Stat/main
```

The engine finds the string in data, follows the unique code reference to it, and resolves to the
enclosing function entry.

**Measured cross-version coverage.** The `--ignored` harness
`cross_version_relocation_coverage_and_false_positive_sweep` (in `crates/maple-core/src/sigmaker/`)
sweeps the GMS v83 to v95.1 lineage and reports, per anchor, how many functions relocate and at what
wrong-address rate. False positives are judged by checks independent of the anchor under test (a
reverse round-trip, a second referenced-string corroboration, and post-recompile identity). On a
local client corpus the string anchor resolves the same function in 100% of adjacent builds
(v83 through v91) and 71% across the v95 class refactor, over the v83 string-anchorable population,
and the import, caller, and vtable anchors had zero confirmed wrong-address landings. A plain byte
signature, by contrast, rarely survives a recompile that moves operands and reorders code, which is
why these recompile-stable anchors exist. The figures are reproducible with that harness against your
own client builds (the real clients are copyrighted and not redistributable, so no corpus ships in
this repository).

## Architecture at a glance

| Crate        | Role                                                                          |
|--------------|-------------------------------------------------------------------------------|
| `maple-core` | The engine: pattern parsing, the SIMD scanner, process memory access, the resolver, the scan pipeline, the Signature Maker, the PE disk reader, and the output writers. |
| `maple-app`  | The desktop workspace: a Rust backend with an embedded web UI (Tauri v2).     |
| `maple-cli`  | The command-line front end.                                                   |

## Performance

The matcher anchors each pattern on its rarest fixed byte (a static frequency table), not the first
one, so common bytes like `0x48` (REX.W) do not flood the prefilter. It uses an AVX2 path chosen at
runtime via `is_x86_feature_detected!` with a scalar fallback. For large pattern sets it switches to
a single-pass multi-pattern index, so cost grows with the buffer plus matches rather than the buffer
times the pattern count.

Synthetic throughput (criterion `cargo bench`, 8 MiB code-like buffer) on the author's hardware: the
single-pattern AVX2 path with a rarest-byte anchor scans at roughly 29 GiB/s, versus roughly 0.8 GiB/s
when forced onto a common byte like `0x48`, about a 37x difference, which is exactly why the anchor
heuristic exists. (The multi-pattern index path is scalar, so it trades that per-byte speed for
O(buffer + matches) instead of O(buffer x patterns); the 29 GiB/s figure is the single-pattern case.) (`cargo run --release --example
throughput` is a dependency-light equivalent.) These figures are synthetic and hardware-dependent;
reproduce them locally with `cargo bench`.

Against a live process, `--profile` breaks the wall clock into its read, scan, and resolve phases
(and sweeps work-unit sizes) so the tuning is measured, not guessed.

## License

MIT. See [LICENSE](LICENSE).
