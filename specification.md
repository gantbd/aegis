# Initial specification

The semantic transition is:

```text
(AuthorityState, CommandV1, ExplicitTime, CredentialFacts) ->
    (AuthorityState, Result<OutcomeV1, RefusalV1>)
```

Credential facts are trusted-boundary inputs, not claims that Aegis authenticated a
peer. Issuance and delegation publish opaque non-forgeable grant values only after
all scope, ancestry, capacity, time, and epoch checks pass.

Validation is total over admitted values. It checks engine instance, subject,
session binding when present, action, resource, epoch, expiry, revocation, and
delegation ancestry. A grant ID alone is never sufficient evidence.

The initial resource vocabulary will cover Agora participant/room actions, Chronos
task/worker actions, Vellum document actions, Moira workflow actions, Hermes stream
actions, and Daimon execution actions without importing those engines' state.

## Implemented volatile profile

`ActionSetV1` is a finite bounded lattice ordered by subset, with intersection as
meet, union as join, empty as bottom, and the closed action vocabulary as top.
Grant attenuation requires every child scope to be below a matching parent scope,
cannot extend expiry, and has bounded depth. Validation checks engine instance,
epoch, expiry, subject, optional session, resource, namespace, and action before
issuing redacted decision evidence. Epoch advancement invalidates all earlier
grants without rewriting historical decisions.

`Engine::issue` is intentionally a privileged adapter operation: this core does
not establish the caller's credentials. Grants have private construction and are
not cloneable, while a public identifier alone is never accepted by validation.
Persistence, credential adapters, and per-grant revocation remain open.

