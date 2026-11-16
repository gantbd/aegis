# Release readiness

Status: source-verifiable durable local authority profile published through the
qualified GitHub source channel; not ready for a network service, registry
publication or production deployment.

Established evidence is recorded in `docs/traceability.md`. Repository license
texts, exact license-declaration baselines and digest-pinned empty/live V1
fixtures and a lockfile-bound clean RustSec attestation are present. Current
blockers are future-version fixture exercise, source-content/legal review,
installer/service-manager packaging, remote credential profiles, concrete
rollback-witness mechanism qualification, sudden-power-loss qualification and
broader executable operator tooling.
The optimized in-memory operation budgets and opt-in 5,000-cycle service soak are
green. A 32-cycle clean-exit filesystem/process campaign is also green; none of
these establishes external-witness, sudden-power-loss or product-SLO evidence.

Passing `make check` establishes only the current source profile and explicitly
does not authorize publication.

