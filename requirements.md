# Requirements

Status: selected V1 contract. Requirement-level implementation status is tracked
in `docs/traceability.md`; the volatile and exclusive local durable profiles are
implemented. The bounded private local-service profile is implemented; production
credential binding is qualified for one kernel effective-UID/GID local Unix
profile; an optional rollback-witness adapter contract is qualified while its
concrete external mechanism remains deployment-owned.
Moira administration and Daimon execution peer mappings are qualified through
public clients.

- **A1 — Identity separation:** principal identity, session identity, credentials,
  capability possession, and authorization decisions are distinct.
- **A2 — Scoped authority:** grants bind issuer, subject, actions, resources, engine
  namespace, epoch, issuance, and expiry.
- **A3 — Non-amplifying delegation:** delegated authority is a subset of the
  delegator's current authority and cannot outlive it.
- **A4 — Explicit revocation:** the selected V1 profile advances the global
  authority epoch; it has no per-grant revocation facts and does not rewrite
  historical attribution.
- **A5 — Opaque grants:** callers cannot construct, inspect secrets within, or
  transfer grants across engine instances by copying a public ID.
- **A6 — Atomic refusal:** invalid issuance, delegation, validation, or revocation
  leaves authoritative state unchanged.
- **A7 — Bounded state:** principals, sessions, grants, delegation depth, scopes,
  names, and retained revocation facts have explicit ceilings.
- **A8 — Explicit time:** issuance and validation receive caller-supplied time.
- **A9 — Privacy:** diagnostics expose decision classes and bounded aggregate facts,
  not grant material, credentials, or resource content.

- **A10 — Recovery fence:** a recovered authority retains allocation frontiers
  and commits a strictly advanced epoch before releasing any capability/decision.
  Recovery never deserializes live grants. Uncertain offered writes fence use.
- **A11 — Public continuity and non-amplification:** public service sessions
  cannot transfer grant handles, extend scope or expiry, substitute authenticated
  subjects, or use decision summaries as bearer authority. Revocation and
  recovery invalidate all live handles before new sessions are admitted.
- **A12 — Optional rollback correspondence:** a separately selected witness
  profile confirms exact checkpoint absence/load and durably advances after the
  local commit but before authority publication. Older, missing, forked or
  indeterminate witness evidence fails closed and conveys no authority.
- **A13 — Explicit peer mappings:** peer adapters map their exact bounded resources
  and actions through session-bound public clients, revalidate current authority,
  and retain no credential or transferable grant material.

The implemented durable local profile assumes trusted non-rollback storage and
an exclusively reserved namespace. It does not authenticate storage or detect
restoration of an older otherwise valid closed store.

Principal/session rebinding and the absence of durable ancestry are selected in
`docs/authority-lifecycle.md`. Open outside the first local profile: remote token
or certificate adapters, organization policy, multi-party approval, portable grant protocols, external
rollback-witness mechanism selection and host attestation. Opaque native grants intentionally have
no persistence/transport codec.

