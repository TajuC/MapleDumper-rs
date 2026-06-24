# Security Policy

## Scope

MapleDumper is an offline reverse-engineering tool. It attaches to processes you
already control and makes no network requests. The most relevant security
concerns are memory safety while parsing untrusted binaries and the integrity of
the desktop app's local data.

## Trust boundaries and accepted risks

The desktop backend commands that open a binary (for example `inspect_pe` and
`generate_signature`) take filesystem paths the user selected through the app's
own file dialog, and pass them to a read-only, fuzz-tested PE parser. They are
not validated or canonicalised before use. This is an accepted risk, not an
oversight: the commands only ever read a file the operator already chose on a
machine they already control, they return derived metadata (architecture,
sections, a signature) rather than file contents, and the app's Content Security
Policy and window-only capabilities leave no channel to exfiltrate what is read.
Routing these through a shared path validator would add defence in depth but
crosses no new trust boundary, so it is tracked as a hardening nicety rather than
a fix.

## Release integrity and code signing

Release binaries are not Authenticode-signed. Signing is deferred deliberately,
not overlooked: a signature a verifier can trust needs a certificate from a
recognised certificate authority, and a self-signed certificate adds the ceremony
of signing without that trust. Until a real certificate is in place, release
integrity rests on artefacts a downloader verifies independently. Every release
attaches SHA-256 checksums (`SHA256SUMS.txt`), a CycloneDX SBOM, and a CLI binary
built with `cargo auditable` whose embedded dependency list is verifiable with
`cargo audit bin mapledumper.exe`. Signing the published binaries once a
certificate is available is an additive step that does not change this baseline.

## Change control

The default branch is protected: a change reaches `main` only through a pull
request whose required status checks (build, MSRV, dependency policy, frontend,
and the 32-bit build) all pass, and they are enforced for every contributor.
Administrator enforcement (`enforce_admins`) and required reviews are left off
while the project has a single maintainer; they are the obvious next controls if
that changes.

## Supported versions

Security fixes target the latest commit on the default branch.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability. Report it privately
through GitHub Security Advisories, using "Report a vulnerability" on the
repository Security tab.

Include the affected version or commit, a description of the issue, and a minimal
reproduction if you have one. You can expect an initial response within a few
days.
