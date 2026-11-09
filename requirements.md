# Requirements

Status: proposed.

- **A1 — Identity separation:** principal identity, session identity, credentials,
  capability possession, and authorization decisions are distinct.
- **A2 — Scoped authority:** grants bind issuer, subject, actions, resources, engine
  namespace, epoch, issuance, and expiry.
- **A3 — Non-amplifying delegation:** delegated authority is a subset of the
  delegator's current authority and cannot outlive it.
- **A4 — Explicit revocation:** revocation advances an authority epoch or records a
  bounded grant fact; it does not rewrite historical attribution.
- **A5 — Opaque grants:** callers cannot construct, inspect secrets within, or
  transfer grants across engine instances by copying a public ID.
- **A6 — Atomic refusal:** invalid issuance, delegation, validation, or revocation
  leaves authoritative state unchanged.
- **A7 — Bounded state:** principals, sessions, grants, delegation depth, scopes,
  names, and retained revocation facts have explicit ceilings.
- **A8 — Explicit time:** issuance and validation receive caller-supplied time.
- **A9 — Privacy:** diagnostics expose decision classes and bounded aggregate facts,
  not grant material, credentials, or resource content.

Open: credential adapters, principal lifecycle, organization policy, multi-party
approval, durable storage, grant codec, and host attestation profiles.

