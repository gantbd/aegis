# Traceability ledger

| Requirement | Planned implementation | Current evidence | Status |
| --- | --- | --- | --- |
| A1 identity separation | fixed-width distinct IDs, opaque grant, explicit decision evidence and authenticated-session facts | lifecycle model, service session/handle scenarios and kernel peer UID/GID mapping with fresh session allocation | Satisfied for selected local Unix credential profile; remote verification remains adapter-owned |
| A2 scopes | closed namespaces/actions and finite `ActionSetV1` lattice | bounded-lattice laws and authorization scenario | Satisfied for represented actions |
| A3 delegation | subset/expiry/depth-monotone attenuation; ancestry deliberately volatile | amplification scenarios and 59,049-program lifecycle model | Satisfied for selected no-durable-ancestry profile |
| A4 revocation | selected global epoch only; no per-grant facts | old-grant rejection across revoke/recover programs | Satisfied for V1 volatile and durable profiles |
| A5 opacity | private non-cloneable `GrantV1` construction | public API and validation-by-grant behavior | Satisfied for safe Rust API |
| A6 atomicity | validate before identity publication; exact expected epoch on authority mutations | refusal scenarios, stale-epoch no-mutation assertions and strict lint | Partial; broader saturation evidence open |
| A7 bounds | core scope/depth plus service session/grant/decision/page and peer-mapping ceilings | constructor, model, recovery, service capacity, daemon connection and credential-registry evidence | Satisfied through selected authenticated private local daemon |
| A8 explicit time | caller-supplied issue/attenuate/validate time | expiry/attenuation behavior | Satisfied |
| A9 privacy | opaque IDs and redacted grant/decision debug | redaction assertion | Satisfied for implemented surfaces |
| A11 public continuity | protocol-only conformance harness over distinct authenticated session profiles and durable reopen | issue denial, cross-session handle refusal, scope/expiry amplification refusal, wrong-resource denial, revocation, historical decision inspection, recovery epoch/session loss and canonical single-bit/byte wire mutation corpus | Satisfied for bounded native service; peer mappings remain separate |
| A12 rollback witness | optional checkpoint decorator plus independently provisioned exact revision/byte witness | older valid checkpoint, missing state, same-revision fork, skipped witness advancement, publication fencing and recovery refusal | Satisfied for adapter correspondence; concrete external mechanism claims remain separate |
| A13 peer mappings | peer-owned resource mapping through public session-bound clients | Moira exact-saga `Administer`; Daimon profile plus every distinct tool `Execute`; Hermes exact-stream `Submit`/`Observe` with wrong-action denial; deny/revocation without peer mutation or provider redispatch; one live authority gates discarded-reply Daimon reopen/reauthorizes retained delivery and then grants downstream one-event Hermes publication/readback; independent live Aegis/Hermes daemon qualification | Satisfied for Moira, Daimon and Hermes service/process integrations; production credentials remain deployment-owned |
| A14 current-session attribution | zero-payload read-only command resolves the exact request session and projects only its owner-retained principal | distinct live sessions return distinct owner principals; closed session refuses; canonical request/reply truncation and redacted Debug; capability-shaped client | Satisfied for exact current-session principal observation; cross-component identity equivalence and authority remain explicit nonclaims |

Release assurance additionally binds the exact 27-component root lockfile to a
clean RustSec audit at the database revision recorded in
`docs/advisory-attestation.md`. CI audits the then-current database with warnings
denied; this is known-advisory evidence, not source or legal review.

## Durable local qualification

- `tests/checkpoint_behavior.rs`: fixed golden layout, every truncation, version/
  namespace/limit/exhaustion refusals, private preparation, retained frontiers and
  old-grant rejection; 1,024 declared five-step recovery programs (finite scope).
- `tests/finite_authority_model.rs`: an independently implemented 59,049-program
  lifecycle model spanning issuance, attenuation, validation, expiry, epoch
  revocation, recovery and both allocation-frontier exhaustion states.
- `tests/action_laws.rs`: all 64 action sets and 64³ triples for distributive
  bounded-lattice laws, not completeness of arbitrary authority policy.
- `host/aegis-host/tests/durable_behavior.rs`: A4/A6/A7/A9/A10 receipt gate,
  every operation uncertain before/after commit, mandatory recovery fence,
  weak/wrong evidence, store errors, refusal identity and observation neutrality.
- `adapters/aegis-local/tests/local_delivery.rs`: actual filesystem restart,
  independent namespace expectation, lost revocation reply and subprocess exit.
- `tests/engine_boundary.rs` and WASI compile: zero core runtime dependencies;
  native effects remain in host/adapter packages. Non-cloneable grant doctest.

This closes A10 for the trusted exclusive local profile. No bearer restoration,
external rollback witness, credentials, remote service, physical power-loss or
unbounded-history proof is claimed. See the README's operating constraints.

`make soak` separately runs 5,000 fresh authenticated-service lifecycles through
issue, exact authorization, epoch revocation, stale-handle refusal and session
teardown. It is repeated service-state evidence only; durable filesystem/process
evidence is covered separately. `make performance` runs 64 optimized samples each
for issue, authorization, revocation and recovery under the provisional
reference-host p95/p99 budgets recorded in `docs/performance.md`; that synthetic
in-memory gate is not filesystem, daemon, witness or product-SLO evidence.
`make soak-process` adds 32 fresh two-daemon cycles through lost revocation reply,
clean process exit, durable reopen, mandatory epoch fencing, stale-handle refusal
and fresh issuance. It does not claim sudden power-loss or witness coverage.

## Native service boundary

`aegis-protocol`, `aegis-service`, `aegis-client` and `aegis-wire` establish transport-neutral
commands and server-owned session-local grant handles. Service tests prove that
another session cannot use a handle, disconnect destroys owned handles, epoch
revocation destroys every live handle, non-admin issuance/inspection refuses, and
bounded pages expose only redacted grant/delegation/decision summaries. Wire
codec tests cover every command/outcome, stale-epoch payload, truncation and bounds.
The separate `CurrentPrincipal` command accepts no identity input and returns
only the principal retained by the exact resolved session, including for a
non-administrator; an absent or closed session returns `UnknownSession`. This is
non-bearer attribution evidence, not authorization, credential disclosure,
principal enumeration or proof that another component identity is equivalent.
Mutation commands carry an exact expected epoch and refuse stale requests before
allocation or durable transition. Capability-shaped mutation, administration and
read-only clients keep page requests locally bounded. The local daemon qualifies
a real private Unix socket, authenticated handshake, bounded multi-request lifetime,
embedded/local issue-to-authorize correspondence, teardown, health and
outcome-unknown reply loss. The selected connector returns the negotiated session
and implements only the public `aegis-client::ServicePort`; session substitution
is rejected locally and post-send transport failure remains outcome unknown.
Executable supervision and remote credential adapters remain open. The selected
local Unix profile has exact kernel peer mapping and unknown-peer refusal evidence.

The real-socket acceptance suite also launches two daemon subprocesses over the
same private directory. The first issues and validates through `aegis-client`,
commits epoch revocation and loses the reply. The second process reopens the
store, commits recovery epoch 2, rejects the old grant handle, and issues and
validates a fresh exact-scope grant through the public client and wire. No
sibling engine API participates in the client path.

`aegis-conformance` depends only on `aegis-protocol`; a dependency gate rejects
authority, host, service, wire and local-runtime internals. The real durable
service runs its continuity/non-amplification suite through an explicit
service→host→store lifecycle handoff. That handoff exports no grant, session or
decision material.

## Operator continuity

`docs/operator-continuity.md` selects fail-closed restart, backup custody,
namespace rotation, uncertain-outcome reconciliation and exact stale-socket
procedures. The default restore path creates a fresh namespace because the local
profile cannot detect restoration of an older valid checkpoint. Same-namespace
restore remains prohibited in the default profile. It is available only through
the separately selected witness adapter plus qualified concrete external evidence.

## Optional rollback witness

`aegis-witness` decorates only `keystone-storage::CheckpointStore`; a dependency
gate rejects authority, host, service, transport and local-adapter internals. It
verifies absence or exact checkpoint correspondence before recovery and requires
durable witness advancement after the local commit but before host publication.
Tests reject an older valid checkpoint, missing state behind an anchor and a
same-revision byte fork. Witness uncertainty after local commit becomes an
indeterminate host result, fences live authority and refuses recovery while the
local checkpoint is ahead. The concrete external witness and its credentials,
cryptographic binding, availability and durability remain deployment evidence.

