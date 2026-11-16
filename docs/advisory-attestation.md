# RustSec advisory attestation

Status: clean root-lockfile audit against a pinned current RustSec database;
not an SBOM, source review or legal opinion.

audited-at-utc: 2026-11-16T00:31:50Z
cargo-audit-version: 0.23.0
advisory-database-commit: 28d73fc95e5972af3403225a217def57dcaba3c4
advisory-database-commit-date: 2026-11-10T14:45:03+01:00
advisory-count: 1446
lockfile-sha256: cf5bf8709bc5b49f106ae8d57dfbb99fd64e9692fc4d605115bd06ac3b6ba567
dependency-count: 29
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
