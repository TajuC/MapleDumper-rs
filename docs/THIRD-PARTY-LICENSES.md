# Third-party licenses

MapleDumper is MIT licensed (see `LICENSE`). It bundles and depends on third-party components listed
here.

## Vendored in this repository

### Monaco Editor
- Version: 0.52.2
- Location: `crates/maple-app/frontend/vs/` (see `crates/maple-app/frontend/vs/VENDOR.md`)
- Copyright: Microsoft Corporation
- License: MIT (https://github.com/microsoft/vscode/blob/main/LICENSE.txt)
- Source: https://github.com/microsoft/monaco-editor

The Monaco distribution is checked in as vendored, build-free assets and is marked `linguist-vendored`
so it is excluded from repository language statistics. Its per-file MIT headers are retained.

## Rust dependencies

The Rust dependency tree is pinned in `Cargo.lock` and gated by `deny.toml` (`cargo deny check`), which
restricts allowed licenses to a permissive set (MIT, Apache-2.0, BSD-2/3-Clause, ISC, Zlib, MPL-2.0,
Unicode, CC0-1.0, BSL-1.0). To regenerate the full per-crate attribution list with a toolchain present:

```
cargo install cargo-about
cargo about generate about.hbs > THIRD-PARTY-RUST.html
```

Notable direct dependencies and their licenses: `rayon`, `iced-x86`, `serde`, `clap`, `rusqlite`
(bundled SQLite, public domain), `tauri`, `windows-sys`, `blake3`, `rfd`, `criterion`, `proptest`, all
MIT or Apache-2.0 (or dual). SQLite itself (bundled by `rusqlite`) is in the public domain.
