# Changelog

All notable Aegis changes will be recorded here. Released versions will follow
Semantic Versioning once a public distribution contract is selected.

## [Unreleased]

### Added

- Added a lockfile-bound RustSec advisory attestation and live CI advisory gate.
- Added `aegis-unix-peer`, a bounded OS effective-UID/GID authenticator with
  exact principal/admin mapping, fresh namespaced sessions, redacted diagnostics
  and real-daemon unknown-peer refusal evidence.
- Added an optimized reference-host performance gate for issue, authorization,
  revocation and recovery with declared p95/p99 engineering budgets.
- Added a 32-cycle two-process filesystem soak for lost revocation replies,
  recovery epoch fencing, stale-handle refusal and fresh issuance.
- Added repository MIT and Apache-2.0 license texts matching package metadata and
  made them mandatory release-contract artifacts.
- Added an exact locked-graph license-declaration baseline using Keystone's
  dev-only verifier; missing declarations and expression drift now fail closed.
- Added an opt-in 5,000-cycle authenticated-service lifecycle soak spanning
  issue, authorize, epoch revocation, stale-handle refusal and session teardown.
- Added an external canonical live-frontier V1 checkpoint fixture alongside the
  empty fixture so compatibility evidence includes issued and decided identity
  state.
- Added the optional mechanism-only `aegis-witness` adapter with exact
  checkpoint correspondence, fail-closed rollback/fork detection and
  publication fencing on witness uncertainty.
- Added deterministic bit-flip, byte-deletion and byte-insertion mutation over
  every public request, reply and session-handshake shape, requiring canonical
  re-encoding for every mutation that remains valid.
- Added the deterministic authority core, canonical checkpoint, durable host,
  private local adapter and embedded SDK facade.
- Added the production roadmap, pinned toolchain, CI workflow, security policy
  and threat/privacy model.
- Selected the global-epoch V1 lifecycle, principal/session rebinding contract and
  no-durable-ancestry profile, with a 59,049-program independent lifecycle model.
- Added transport-neutral protocol/client crates and a bounded service that owns
  session-local grant handles and redacted administrative read models.
- Added a canonical bounded wire codec and connection-bound local dispatch with
  explicit pre-dispatch versus outcome-unknown I/O failure.
- Added a private Unix listener with authenticated session handshake, deadlines,
  readiness/health counters, real-socket acceptance evidence and owned-path cleanup.
- Added exact expected-epoch guards for authority mutations, bounded multi-request
  connection sessions, embedded/local semantic correspondence, and capability-shaped
  mutation, administrative and read-only client facades.
- Selected fail-closed operator procedures for restart, backup custody,
  namespace rotation, uncertain outcomes and stale socket recovery.
- Adopted Keystone's sticky counter and duration accumulation laws for host
  signals without changing Aegis's public observation shape.
- Added a public-protocol-only continuity/non-amplification conformance suite
  spanning distinct authenticated sessions, revocation and durable recovery.
- Added a two-daemon-process public-client journey for lost revocation replies,
  recovery fencing, old-handle rejection and fresh issuance.
- Qualified Daimon's public-client authority mapping: the selected profile and
  every distinct tool require current `Daimon/Execute`, and epoch revocation
  blocks retained-result delivery without provider redispatch.

### Security

- Native grants remain non-cloneable and unserializable; durable recovery
  advances the authority epoch before releasing fresh decisions.

[Unreleased]: https://github.com/gantbd/aegis/commits/main

