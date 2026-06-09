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

## Supported versions

Security fixes target the latest commit on the default branch.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability. Report it privately
through GitHub Security Advisories, using "Report a vulnerability" on the
repository Security tab.

Include the affected version or commit, a description of the issue, and a minimal
reproduction if you have one. You can expect an initial response within a few
days.
