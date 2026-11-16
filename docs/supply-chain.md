# Supply-chain profile

Status: exact locked source inventory, license-declaration baseline and current
root-lockfile RustSec attestation; not an SBOM or legal/source-content review.

`make check-supply-chain` compares the complete `Cargo.lock` package set with
`supply-chain-baseline.txt`, refuses Git sources, requires a checksum for every
registry package and resolves the locked graph offline. The inventory includes
the local Aegis and Keystone packages as well as Keystone's locked platform
dependencies.
The selected `aegis-unix-peer` adapter adds the pinned `nix` graph solely for
safe OS peer-credential retrieval; its direct dependency closure is enforced.
The standalone `aegis-daemon` adds the pinned `signal-hook` graph solely for
bounded SIGINT/SIGTERM ownership and accept-loop wakeup.
The optional `aegis-witness` production closure contains only
`keystone-storage`; concrete witness clients, credentials and transports remain
outside this source profile.

The same gate feeds complete locked offline Cargo metadata to Keystone's
dev-only verifier and compares every exact package license expression with
`license-baseline.txt`. A missing declaration or expression drift fails closed;
the accepted baseline remains Aegis-owned policy.

The lockfile-bound [advisory attestation](advisory-attestation.md) records a clean
audit against an exact RustSec database revision, and CI audits the current
database without ignored warnings. This detects unreviewed dependency drift,
incomplete registry provenance and known advisories at audit time. It does not
establish source/license compatibility,
artifact contents, signatures, reproducibility or provenance from a clean Cargo
home.
Those remain release blockers.
