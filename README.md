# MapleDumper

[![CI](https://github.com/TajuC/MapleDumper-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/TajuC/MapleDumper-rs/actions/workflows/ci.yml)

A fast AOB / pattern scanner and offset dumper for Windows x64 (and x86) processes. MapleDumper
attaches to a running process, scans the target module with an AVX2-accelerated masked matcher,
resolves the matches into stable **module-relative RVAs**, and emits a reusable C/C++ header, a
Cheat Engine table, or a plain report.

It ships as a **frameless desktop workspace** — which keeps a local history of every scan so you can
compare offsets across game versions — and a **scriptable command-line tool**, both built on the
same engine crate.

## Highlights

**Engine**
- **Read/scan pipeline** — a few reader threads stream the target's memory in parallel into a
  bounded channel while the rayon thread-pool scans each block as it lands, so reading and scanning
  overlap. Work units are kept small (256 KiB) so the scan spreads evenly across every core.
- AVX2 masked matcher that anchors each pattern on its **rarest fixed byte** (static frequency
  table), with a scalar fallback selected at runtime.
- Scans **executable regions only** by default (where code signatures live), with a one-switch
  fallback to the full module — so a live dump reads far fewer bytes.
- **Wait-and-attach** — point it at a process that is not running yet and it polls, then attaches
  the instant the process and module appear (cancellable).
- Suffix-driven resolvers: RIP-relative / `rel32` pointers, nested calls, struct displacements,
  and packet-header immediates, arch-aware for x64 and x86.
- Output as deterministic, sorted, de-duplicated module RVAs — immune to ASLR.

**Desktop workspace** (`maple-app`)
- Frameless dark dashboard: target toolbar, status-colored results table grouped by category, and
  a metadata inspector (RVA, absolute address, signature, type, hit count, notes).
- **Version history** — every scan is saved to a local SQLite database, grouped by build (a content
  hash of the code section), so 50+ game versions stay organized. Identical re-scans are de-duplicated.
- **Compare across versions** — a tabbed workspace: open any scan, compare any two builds
  (moved / new / removed offsets), or line every version up in a **matrix** to track an offset across
  the whole timeline. Click a changed symbol to see its **bytes and x86/x64 disassembly** side by side.
- **Assembly scan** — find code by *instruction* instead of bytes (à la Cheat Engine): type lines of
  assembly (`push`, `call`, `test eax,eax`) with wildcards (`*` zero-or-more, `?` one char, `^` line
  start, `$` line end), and it disassembles the target and lists every address where those
  instructions appear back-to-back. Narrow it with an optional From/To range, and save any match
  straight into your pattern list.
- Built-in **pattern manager** (add / edit / delete / notes) and a syntax-highlighted **editor**.
- **Privacy mask** — one click hides every signature, name, address, category, and note for
  screenshots. Pick **blur**, or a **showcase mode** that swaps in realistic fake values instead.
  Visual only; the real data is untouched.
- **Press Ctrl+F** anywhere to filter the current table; everything stays in-app, with copy-to-clipboard
  and smart auto-named exports (`offsets.h`, a Cheat Engine table, or plain text).
- Live **scan metrics** — scanned size, effective throughput, and attach time.
- **Fully offline** — the editor and the history database are local, and a strict
  Content-Security-Policy blocks every remote origin. The app makes no network requests, ever.

**Command line** (`maple-cli`)
- The same scan and output pipeline, suitable for scripting and CI.
- Offline helpers that need no target: `--lint` flags weak signatures, `--diff` reports which
  offsets moved between two dumps, and `--profile` breaks a live scan into read/scan/resolve timing.
- `--asm` runs the same instruction scan as the desktop Assembly scan, over an optional address range.

## Workspace layout

| Crate        | Role                                                                          |
|--------------|-------------------------------------------------------------------------------|
| `maple-core` | The engine: pattern parsing, the SIMD scanner, process memory access, the resolver, the scan pipeline, and the output writers. |
| `maple-app`  | The desktop workspace — a Rust backend with an embedded web UI (Tauri).        |
| `maple-cli`  | The command-line front end.                                                    |

## Build

Requires a stable Rust toolchain (MSVC) and the Windows SDK. The desktop app needs the
[WebView2 runtime](https://developer.microsoft.com/microsoft-edge/webview2/) at run time, which
ships with current versions of Windows.

```
cargo build --release
```

- Desktop app: `target/release/maple-app.exe`
- CLI: `target/release/mapledumper.exe`

Run elevated so `OpenProcess` and `SeDebugPrivilege` succeed against a protected target.

## Desktop workspace

Launch `maple-app.exe`. In the Workspace view:

1. Enter the **target process** (e.g. `MapleStory.exe`) and the **module** to scan.
2. Pick the architecture. Leave **Wait for target** on to attach the moment the process starts, or
   switch to **Find by window class** to locate it by class instead of name. **Code regions only**
   (on by default) scans executable memory; turn it off to scan the whole module.
3. Load or edit your pattern list (Patterns / Editor views), then press **Start Scan**.
4. Inspect any result, then **Export** an `offsets.h`, a Cheat Engine table, or a plain report.
5. Every scan is saved to **History** — revisit it, compare two builds, open the **Matrix** to track an
   offset across all versions, or click a changed symbol for its bytes and disassembly.

Use the **eye** button in the title bar to hide signatures before sharing a screenshot — blur, or the
showcase randomizer in Settings.

## Command line

```
mapledumper (--process <name> | --class <window-class>) [options]

  --process <name>   attach by process name (e.g. MapleStory.exe)
  --class <class>    attach by top-level window class
  --module <name>    module to scan (default: process name)
  --patterns <file>  pattern file (default: patterns.txt)
  --arch <32|64>     architecture section to load (default: 64)
  --out <dir>        output directory (default: .)
  --ce               write update.txt as a Cheat Engine table
  --no-offsets       do not write offsets.h
  --no-wait          do not wait for the process; fail if it is not running
  --timeout <secs>   give up waiting after this many seconds
  --profile          measure the read/scan/resolve split against the live target and exit
  --lint             check the pattern file for weak signatures and exit
  --diff <a> <b>     compare two saved dumps and report what moved, then exit
  --asm <file>       scan by assembly instructions (one per line, wildcards * ? ^ $), then exit
  --from <addr>      with --asm, only report matches at or above this address (hex)
  --to <addr>        with --asm, only report matches below this address (hex)
  -h, --help         print help
```

```
mapledumper --process MapleStory.exe --patterns patterns.txt --out .

# check signature quality without attaching to anything
mapledumper --lint --patterns patterns.txt

# see which offsets moved between two game versions
mapledumper --diff old/update.txt new/update.txt

# find code by instruction: every push, then a call, then test eax,eax (one instruction per line)
mapledumper --process MapleStory.exe --asm find.asm
```

## Patterns

Each non-empty line defines one signature. Accepted forms:

```
Name = AA BB ?? CC
Name: 0xAA ?? CC
Name AA ?? CC
```

- **Wildcards:** `?` or `??`. Commas between bytes are allowed.
- **Notes / comments:** text after `;` or `#` is captured as the symbol's note (and shown in the
  app); a leading `#` line is a comment.
- **Architecture sections:** `#32BIT` / `#64BIT` headers select which block is loaded. Patterns
  before any section apply to both.
- **Category sections:** `[name]` sets the namespace used for the following symbols in `offsets.h`
  (default `globals`).

Name suffixes select how a match is resolved:

| Suffix   | Meaning                                                                 |
|----------|-------------------------------------------------------------------------|
| `_PTR`   | Resolve a RIP-relative load (`mov`/`lea`/`cmp`/SSE) or `rel32` jmp/call. |
| `_CALL`  | Treat the match as a call and resolve the (nested) call target.         |
| `_OFF`   | Extract a struct member displacement (emitted as a raw offset).         |
| `_HDR`   | Extract an immediate operand, e.g. a packet header opcode.              |
| _(none)_ | Emit the match address itself.                                          |

See `patterns.sample.txt` for a worked example.

## Output

- **`offsets.h`** — module-relative RVAs grouped by category:

  ```c
  #pragma once
  #include <cstdint>

  // module-relative RVAs for MapleStory.exe (base 0x140000000)
  namespace maple {
      namespace globals {
          inline constexpr uintptr_t
              CClickBase = 0x9E9568,
              CUserLocal = 0x9E9298;
      }
  }
  ```

  RVAs are relative to the module base, so they remain valid across restarts (add the runtime
  module base to rebase). `_OFF` symbols are raw struct offsets.

- **`update.txt`** — a plain report by default, or a Cheat Engine table with `--ce`
  (`define(Name, "module"+RVA)` / `registersymbol(Name)`). The plain report carries a `# build:`
  stamp — a content hash of the code section, its size, the PE timestamp, and the file version — so
  `--diff` and the History tab can tell builds apart.

## How it works

1. Enable `SeDebugPrivilege`, locate the process by name or window class, and open it with
   `PROCESS_VM_READ` (waiting for it to appear if requested).
2. Enumerate the module's committed regions — executable only by default — and coalesce adjacent
   ones.
3. Stream the regions through the pipeline: a few reader threads issue `NtReadVirtualMemory` reads
   in parallel (tolerating partial copies) while the thread-pool scans each 256 KiB block with the
   AVX2 masked matcher as soon as it lands, so reading and scanning overlap.
4. Resolve each match according to its suffix and convert addresses to module RVAs.
5. Emit `offsets.h`, a Cheat Engine table, or a plain report.

## Performance

The matcher anchors each pattern on its **rarest fixed byte** (a static frequency table), not the
first one, so common bytes like `0x48` (REX.W) don't flood the prefilter. It uses an AVX2 path
chosen at runtime via `is_x86_feature_detected!` with a scalar fallback, and read buffers use
uninitialized capacity to skip a redundant zeroing pass.

Synthetic throughput (criterion `cargo bench`, 8 MiB code-like buffer): the rarest-byte anchor
scans at **~29 GiB/s**, versus **~0.8 GiB/s** when forced onto a common byte like `0x48` — about a
**37x** difference, which is exactly why the anchor heuristic exists.
(`cargo run --release --example throughput` is a dependency-light equivalent.)

Against a **live** process, `--profile` breaks the wall clock into its read, scan, and resolve
phases (and sweeps work-unit sizes) so the tuning is measured, not guessed. On a 143 MB code
section with 52 patterns the picture was clear: the cross-process read via `NtReadVirtualMemory`
(the primitive `ReadProcessMemory` wraps) is fast — ~2.3 GB/s on one thread, scaling past 5 GB/s
with a few readers — and resolving is negligible. The time was going into the scan, which a
too-coarse work unit left poorly balanced across cores. Sizing the accept window at 256 KiB and
streaming the reads on a few threads spreads the scan evenly and overlaps it with the read, taking
that dump from ~287 ms to **~49 ms**. Scanning executable regions only keeps the byte count down.

Deliberately not used: `PssCaptureSnapshot` gives a consistent snapshot but throttles reads to
~30 MB/s; a kernel driver (`MmCopyVirtualMemory`) could read faster but conflicts with anti-cheat;
reading the image from disk is fast but misses the target's runtime state. AVX-512 and Teddy-style
multi-pattern prefilters give diminishing returns now that finer chunking already balances the scan
against the read.

## License

MIT. See `LICENSE`.
