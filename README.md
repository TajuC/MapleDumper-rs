# MapleDumper

A fast AOB / pattern scanner and offset dumper for Windows x64 processes.

MapleDumper attaches to a running process, scans a target module with an AVX2-accelerated
masked matcher, resolves RIP-relative and `rel32` targets, and writes the results as a
reusable C/C++ header of **module-relative RVAs** plus a human-readable report.

## Workspace

- `maple-core` — the engine: pattern parsing, the SIMD scanner, process memory access,
  the target resolver, the scan orchestrator, and the output writers.
- `maple-cli` — a command-line front end.

A Slint GUI (`maple-gui`) builds on the same engine.

## Build

Requires a stable Rust toolchain (MSVC) and the Windows SDK.

```
cargo build --release
```

The CLI binary is named `mapledumper`.

## Usage

```
mapledumper (--process <name> | --class <window-class>) [options]

  --process <name>   attach by process name (e.g. MapleStory.exe)
  --class <class>    attach by top-level window class
  --module <name>    module to scan (default: process name)
  --patterns <file>  pattern file (default: patterns.txt)
  --arch <32|64>     architecture section to load (default: 64)
  --out <dir>        output directory (default: .)
  --ce               write update.txt as a Cheat Engine table
  -h, --help         print help
```

Run elevated so `OpenProcess` and `SeDebugPrivilege` succeed. Example:

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
- **Comments:** anything after `;` or `#` on a line is ignored.
- **Architecture sections:** `#32BIT` / `#64BIT` headers select which block `--arch` loads.
  Patterns before any section apply to both.
- **Category sections:** `[name]` sets the namespace used for the following symbols in
  `offsets.h` (default `globals`).

Name suffixes select how a match is resolved:

| Suffix   | Meaning                                                                 |
|----------|-------------------------------------------------------------------------|
| `_PTR`   | Resolve a RIP-relative load (`mov`/`lea`/`cmp`/SSE) or `rel32` jmp/call. |
| `_CALL`  | Treat the match as a call and resolve the (nested) call target.         |
| `_OFF`   | Extract a struct member displacement (emitted as a raw offset).         |
| _(none)_ | Emit the match address itself.                                          |

See `patterns.sample.txt` for a worked example.

## Output

- **`offsets.h`** — module-relative RVAs grouped by category, e.g.

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

  RVAs are relative to the module base, so they remain valid across restarts (add the
  runtime module base to rebase). `_OFF` symbols are raw struct offsets.

- **`update.txt`** — a plain report by default, or a Cheat Engine table with `--ce`
  (`define(Name, "module"+RVA)` / `registersymbol(Name)`).

## How it works

1. Enable `SeDebugPrivilege`, locate the process by name or window class, and open it
   with `PROCESS_VM_READ`.
2. Enumerate the target module's committed, readable regions and coalesce adjacent ones.
3. Read each region with `NtReadVirtualMemory` (tolerating partial copies) and scan it in
   parallel with an AVX2 masked matcher that anchors on the rarest fixed byte, with a
   scalar fallback selected at runtime.
4. Resolve each match according to its suffix and convert addresses to module RVAs.
5. Write `offsets.h` and `update.txt`.

## Performance

- Each pattern anchors on its **rarest fixed byte** (a static frequency table), not the
  first one, so common bytes like `0x48` (REX.W) don't flood the prefilter. The matcher
  uses an AVX2 path chosen at runtime via `is_x86_feature_detected!` with a scalar fallback,
  and regions are scanned in parallel with rayon. Region buffers are read into uninitialized
  capacity to skip a redundant zeroing pass.
- Reads go through `NtReadVirtualMemory` directly — the lowest documented user-mode read
  primitive (`ReadProcessMemory` merely wraps it) — with one large read per coalesced region.
- Deliberately not used: `PssCaptureSnapshot` yields a consistent snapshot but its reads are
  throttled to ~30 MB/s, far too slow to scan a whole module; AVX-512 / Teddy multi-pattern
  prefilters were skipped because consumer AVX-512 support is inconsistent and Teddy lacks
  wildcard support, which the rare-byte AVX2 prefilter already covers.

Indicative throughput (`cargo run --release --example throughput`, 8 MiB code-like buffer):
the rarest-byte anchor scans at **~28 GB/s**, versus **~0.8 GB/s** when forced onto a common
byte like `0x48` — about a **35x** difference, which is exactly why the anchor heuristic
exists. `cargo bench` runs the criterion version with full statistics.

## License

MIT. See `LICENSE`.
