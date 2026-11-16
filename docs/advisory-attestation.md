# RustSec advisory attestation

Status: clean root-lockfile audit against a pinned current RustSec database;
not an SBOM, source review or legal opinion.

audited-at-utc: 2026-11-16T02:17:19Z
cargo-audit-version: 0.23.0
advisory-database-commit: 28d73fc95e5972af3403225a217def57dcaba3c4
advisory-database-commit-date: 2026-11-10T14:45:03+01:00
advisory-count: 1446
lockfile-sha256: 3582c67757bbad2e0160876d13daf5ce68a968e9bd697c0b3811e225a8e36911
dependency-count: 45
vulnerability-count: 0
warning-count: 0

The result was produced with `cargo audit 0.23.0 --no-fetch --json` after
checking out the exact advisory database commit above. No advisory is ignored.
The audit used no target filter and included the default informational warning
classes (`unmaintained`, `unsound`, and `notice`).

`scripts/check-advisory-attestation.sh` binds this evidence to the exact root
`Cargo.lock`; lockfile drift requires a new audit and attestation. CI additionally
runs `cargo audit --deny warnings` against the then-current database so a clean
pinned result cannot silently age into a release claim.

This covers the root coordinated-source lockfile only. It does not inspect
unlocked source contents, prove absence of undisclosed vulnerabilities, review
license compatibility, attest build artifacts or cover a future dependency
resolution.
