# Roadmap

## Phase 0 — authority algebra

- [Complete for volatile profile] Close principal, action, resource, session,
  grant, and refusal vocabularies.
- [Complete] Specify and test subset, intersection, join, bounds, and attenuation
  laws for action scopes.
- Threat-model spoofing, confused deputy, grant replay, delegation amplification,
  epoch rollback, disclosure, and denial of service.

## Phase 1 — volatile core

- [Complete for volatile profile] Implement privileged issuance, validation,
  attenuation, expiry, and epoch revocation.
- Add exhaustive small-domain scope/delegation law tests.
- Add cross-engine, cross-session, expired, revoked, and capacity scenarios.

## Phase 2 — recovery and codec

- Define canonical checkpoint/grant-evidence formats.
- Fence recovered opaque capabilities under explicit namespace/epoch rules.
- Add parser robustness, corruption, and rollback tests.

## Phase 3 — integration

- Qualify Moira and Daimon first.
- Add Agora, Chronos, Hermes, and Vellum resource adapters.
- Keep credential verification and secret storage outside Aegis.

