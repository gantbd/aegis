# Aegis production roadmap

Status: pre-release; durable local authority, OS-peer-authenticated private service
and three public-client peer mappings qualified; remote credentials and a concrete
witness mechanism remain open.

Aegis is the federation's bounded authority engine. Production maturity means a
deployable, inspectable and recoverable authority service without turning Aegis
into an identity provider, credential vault, policy language or workflow engine.

## Current baseline

- Deterministic zero-runtime-dependency authority core.
- Closed six-action lattice, non-amplifying attenuation and caller-supplied time.
- Opaque non-cloneable grants and content-safe decision evidence.
- Canonical bounded checkpoint, retained allocation frontiers and mandatory
  recovery epoch fence.
- Receipt-gated durable host and exclusive private-directory local adapter.
- Bounded kernel effective-UID/GID mapping into Aegis principal, fresh session and
  administrator facts for the selected local Unix profile.
- Exhaustive action laws, finite recovery programs, fault/restart tests, WASI
  compilation and embedded SDK facade.

The authority core does not authenticate principals; the selected local adapter
authenticates only a kernel OS-account boundary. The baseline does not make grants
portable, detect rollback of an otherwise valid old store, expose a network
service, or qualify a production release. The optional witness adapter adds
fail-closed correspondence but no concrete external mechanism.

## Release gate A0 — contract and assurance closure

- [x] Reconcile requirements, specification, model and traceability with the
  implemented durable profile; replace `proposed` labels with exact statuses.
- [x] Maintain a concrete STRIDE/LINDDUN threat model and residual-risk ledger.
- [x] Pin the Rust toolchain and run `make check` in CI from a fresh checkout.
- [x] Add changelog, release policy, package compatibility baseline, locked supply
  inventory and
  release-readiness ledger with adversarial drift tests.
- [x] Add repository MIT and Apache-2.0 license texts matching package metadata.
- [x] Add digest-pinned empty and live-frontier V1 checkpoint fixtures.
- [x] Pin every locked package's declared license expression and reject missing
  declarations or graph/expression drift.
- [ ] Exercise the checkpoint corpus across future released versions.
- [x] Add a current RustSec advisory attestation bound to the exact root lockfile
  and a live CI audit that refuses vulnerabilities or warnings.
- [ ] Complete source-content and legal license-compatibility review.
- [x] Add deterministic public-wire parser mutation with canonical re-encode
  checks across every request, reply and handshake shape.
- [x] Expand the finite authority/recovery model to the selected 59,049-program
  five-step lifecycle domain.
- [x] Add an opt-in 5,000-cycle authenticated-service lifecycle soak covering
  issue, authorize, revoke, stale-handle refusal and session teardown.
- [x] Add an optimized reference-host performance gate with declared operation
  classes, p95/p99 engineering budgets and exact scope/non-SLO limitations.
- [x] Add a 32-cycle two-process filesystem campaign covering lost revocation
  replies, durable reopen, mandatory recovery fencing and fresh issuance.

Exit: one reviewed source-distribution contract, green offline gates and no
contradiction between claims, code and evidence.

## Release gate A1 — authority lifecycle closure

- [x] Decide and specify the V1 revocation profile: global epoch only, or bounded
  per-grant facts in addition to the epoch. Do not leave both implicit.
- [x] Define principal lifecycle and identity-rebinding behavior without storing
  credentials in the authority core.
- [x] Decide whether delegation ancestry is required for durable inspection; if
  selected, bound and persist it without making grants serializable.
- [x] Model delegation, expiry, revocation, recovery and identity exhaustion in
  one independent finite reference system.
- [x] Add bounded paged read models for authority epoch, active server-held grants,
  delegations and decision summaries without disclosing grant material.

Exit: the complete selected V1 authority lifecycle has closed semantics, canonical
recovery and independent model correspondence.

## Release gate A2 — native service product

- [x] Add `aegis-protocol`, `aegis-service`, `aegis-client` and `aegis-wire`.
- [x] Keep grants server-resident. Remote callers receive session-bound opaque
  references that are invalid after disconnect, reauthentication or epoch change.
- [x] Add a host authentication port accepting verified principal/session facts;
  credentials and token validation remain adapters outside the core.
- [x] Qualify one production local credential adapter: exact bounded effective
  UID/GID mappings from the connected Unix peer, fresh non-reusing Aegis session
  IDs and fail-closed unknown-peer/exhaustion behavior. Remote tokens, account
  lookup and hostile same-UID separation remain outside this profile.
- [x] Add a private local transport and daemon with bounded frames, deadlines,
  lifetime ownership, health/readiness and `not_sent` versus `outcome_unknown`.
- [x] Package the selected local profile as a standalone owner process with
  explicit namespace/peer/principal/session/role inputs, continuous serving,
  signal drain, create/open recovery and owned-socket cleanup.
- [x] Qualify that exact sovereign process under Workbench supervision in
  headless and interactive modes using the ordinary public client and
  Aegis-owned command/session guards, with clean drain and durable reopen.
  Workbench retains no grant handle, credential mapping, time, or authority
  policy.
- [x] Expose the private transport as a reusable public-client `ServicePort` with
  server-selected session binding and no service/engine types at the caller.
- [x] Preserve embedded/private-service semantic parity and exact authority-epoch guards.
- [x] Add bounded administrative and read-only client facades; MCP, if added, is a
  projection of the native protocol and carries no implicit authority.
- [x] Own exact-confirmation and same-connection authority command guards in
  `aegis-admin-command`; presentation and Workbench reuse this public-client
  boundary without acquiring command semantics.

Exit: embedded and local-daemon acceptance journeys exercise the same authority
contract, and no wire value can reconstruct or transfer a native grant.

## Release gate A3 — continuity and federation qualification

- [x] Define namespace rotation, backup/restore and operator recovery procedures.
- [x] Add an optional external rollback witness profile; keep its stronger claims
  distinct from the current trusted non-rollback directory profile. The adapter
  contract is qualified; concrete external mechanisms remain deployment-owned.
- [x] Qualify the first peer mappings before broader federation:
  - [x] Moira workflow administration maps the exact saga resource to
    `Moira/Administer` through public client/protocol contracts.
  - [x] Daimon execution requires current `Daimon/Execute` on the selected profile
    and every requested tool through Aegis's public client; epoch revocation blocks
    retained-result delivery without another provider call. One live authority
    also reauthorizes exact retained delivery across a lost reply and Daimon
    process reopen without another Chronos lookup or provider call, then grants
    exact-stream Hermes `Submit`/`Observe` so the integrated chain publishes and
    reads one Moira-owned result event.
  - [x] Hermes append authorization maps one exact stream to `Hermes/Submit`;
    independent Aegis and Hermes daemon processes prove append allowance and
    read denial when `Observe` is absent.
- [x] Prove the native public-service contract cannot amplify scopes or expiry,
  substitute authenticated sessions, or reuse decision summaries as bearer
  authority. Peer adapters retain mapping-specific qualification.
- [x] Run multi-process restart, revocation and lost-reply journeys through public
  clients rather than sibling engine internals.

Exit: one authenticated local deployment profile and three real peer integrations
are qualified with explicit continuity and residual-risk claims.

## Deliberate non-goals

- Password, OAuth, device or certificate verification in the authority core.
- Portable bearer grants or grant restoration after restart.
- Ambient organization policy, workflow orchestration or automatic approval.
- Distributed consensus, multi-writer authority or physical power-loss claims
  without separately selected profiles and evidence.

