# Contributing

Thanks for your interest in MapleDumper. This document covers how to build the
project, the quality bar every change must clear, and how to propose changes.

## Build and test

MapleDumper is a Rust workspace. The minimum supported toolchain is recorded in
`rust-toolchain.toml`.

```
cargo build --workspace
cargo test --workspace
```

The desktop app (`maple-app`) is a Tauri project; see `crates/maple-app` for its
prerequisites.

## Quality bar

Every change must pass the same gates CI enforces, before review:

```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

- Formatting is `rustfmt` with the settings in `rustfmt.toml`.
- Clippy runs with warnings denied. Do not silence a lint without a short
  comment explaining why.
- New behavior needs tests. The signature engine has a golden snapshot test that
  must stay byte-stable unless the change intentionally alters output, in which
  case explain why in the pull request.
- Tests that need the local MapleStory client corpus are marked `#[ignore]` and
  run with `cargo test -- --ignored`. They are not required in CI.

## Commits and pull requests

- Write commit subjects in the imperative mood, describing the change itself.
- Keep each pull request focused on a single concern.
- Fill in the pull request template and confirm the quality bar passes.

## Reporting bugs and requesting features

Open an issue using the templates under `.github/ISSUE_TEMPLATE`. For anything
with a security impact, follow `SECURITY.md` instead of opening a public issue.
