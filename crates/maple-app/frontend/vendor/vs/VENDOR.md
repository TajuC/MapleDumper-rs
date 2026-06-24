# Vendored: Monaco Editor

This directory is a vendored copy of the Monaco Editor distribution, checked in as build-free assets
loaded directly by the desktop frontend.

| Field | Value |
|-------|-------|
| Component | Monaco Editor |
| Version | 0.52.2 |
| Source | https://github.com/microsoft/monaco-editor |
| Distribution | the `min/vs` (minified) build |
| License | MIT (Microsoft Corporation) |

## Why it is vendored

The desktop app is offline by design (a strict Content-Security-Policy blocks every remote origin), so
the editor is shipped in-tree rather than fetched at build or run time. These files are marked
`linguist-vendored` in `.gitattributes` so they do not skew repository language statistics, and they
are reviewed at the supply-chain level (version, source, license, integrity) rather than line by line.

## Updating

1. Download the matching `monaco-editor` release from the source above.
2. Replace the contents of this directory with its `min/vs` tree. Keep it here at
   `crates/maple-app/frontend/vendor/vs/`; the frontend loads it from `vendor/vs`, not the repo
   root, so do not recreate a top-level `vs/`.
3. Update the `Version` row here and the entry in `docs/THIRD-PARTY-LICENSES.md`.
4. Re-run the desktop app and the frontend render test (`node crates/maple-app/frontend_test.cjs`).
