# MapleDumper

[![CI](https://github.com/TajuC/MapleDumper-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/TajuC/MapleDumper-rs/actions/workflows/ci.yml)

A fast AOB / pattern scanner and offset dumper for Windows x64 (and x86) processes. MapleDumper
attaches to a running process, scans a target module with an AVX2-accelerated masked matcher,
resolves the matches into stable **module-relative RVAs**, and emits a reusable C/C++ header, a
Cheat Engine table, or a plain report.

It ships as a **frameless desktop workspace** and a **scriptable command-line tool**, both built
on the same engine crate.

## Highlights

**Engine**
- AVX2 masked matcher that anchors each pattern on its **rarest fixed byte** (static frequency
  table), with a runtime-selected scalar fallback and per-region parallelism via rayon.
- Reads through `NtReadVirtualMemory` directly — the lowest documented user-mode read primitive —
  one large read per coalesced, committed, readable region; partial copies tolerated.
- **Wait-and-attach**: point it at a process that is not running yet and it polls, then attaches
  the instant the process and module appear (cancellable).
- Suffix-driven resolvers: RIP-relative / `rel32` pointers, nested calls, struct displacements,
  and packet-header immediates, arch-aware for x64 and x86.
- Output as deterministic, sorted, de-duplicated module RVAs — immune to ASLR.

**Desktop workspace** (`maple-app`)
- Enterprise dark dashboard: target toolbar, status-colored results table grouped by category,
  and a metadata inspector (RVA, absolute address, signature, type, hit count, notes).
- Built-in **pattern manager** (add / edit / delete / notes) and a syntax-highlighted **editor**.
- One-click export to `offsets.h`, a Cheat Engine table, or plain text.
- Fully **offline** — the editor and all assets are embedded in the executable; no network calls.

**Command line** (`maple-cli`)
- The same scan and output pipeline, suitable for scripting and CI.

## Workspace layout

| Crate       | Role                                                                          |
|-------------|-------------------------------------------------------------------------------|
| `maple-core`| The engine: pattern parsing, the SIMD scanner, process memory access, the resolver, the scan orchestrator, and the output writers. |
| `maple-app` | The desktop workspace — a Rust backend with an embedded web UI (Tauri).        |
| `maple-cli` | The command-line front end.                                                    |

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
2. Choose the architecture, and leave **Wait for target** on to attach as soon as the process
   starts. Optionally find the process **by window class** instead of name.
3. Load or edit your pattern list (Patterns / Editor views), then press **Start Scan**.
4. Inspect any result, then **Export** an `offsets.h`, a Cheat Engine table, or a plain report.

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
  --no-wait          do not wait for the process; fail if it is not running
  --timeout <secs>   give up waiting after this many seconds
  -h, --help         print help
```

```
mapledumper --process MapleStory.exe --patterns patterns.txt --out .
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
  (`define(Name, "module"+RVA)` / `registersymbol(Name)`).

## How it works

1. Enable `SeDebugPrivilege`, locate the process by name or window class, and open it with
   `PROCESS_VM_READ` (waiting for it to appear if requested).
2. Enumerate the target module's committed, readable regions and coalesce adjacent ones.
3. Read each region with `NtReadVirtualMemory` (tolerating partial copies) and scan it in parallel
   with an AVX2 masked matcher that anchors on the rarest fixed byte, with a scalar fallback
   selected at runtime.
4. Resolve each match according to its suffix and convert addresses to module RVAs.
5. Emit `offsets.h`, a Cheat Engine table, or a plain report.

## Performance

- Each pattern anchors on its **rarest fixed byte** (a static frequency table), not the first one,
  so common bytes like `0x48` (REX.W) don't flood the prefilter. The matcher uses an AVX2 path
  chosen at runtime via `is_x86_feature_detected!` with a scalar fallback, and regions are scanned
  in parallel with rayon. Region buffers are read into uninitialized capacity to skip a redundant
  zeroing pass.
- Reads go through `NtReadVirtualMemory` directly — the lowest documented user-mode read primitive
  (`ReadProcessMemory` merely wraps it) — with one large read per coalesced region.
- Deliberately not used: `PssCaptureSnapshot` yields a consistent snapshot but its reads are
  throttled to ~30 MB/s, far too slow to scan a whole module; AVX-512 / Teddy multi-pattern
  prefilters were skipped because consumer AVX-512 support is inconsistent and Teddy lacks wildcard
  support, which the rare-byte AVX2 prefilter already covers.

Measured throughput (criterion `cargo bench`, 8 MiB code-like buffer): the rarest-byte anchor scans
at **~29 GiB/s**, versus **~0.8 GiB/s** when forced onto a common byte like `0x48` — about a **37x**
difference, which is exactly why the anchor heuristic exists.
(`cargo run --release --example throughput` is a dependency-light equivalent.)

## License

MIT. See `LICENSE`.
