# Selected V1 authority lifecycle

Status: selected contract for the volatile core and exclusive local durable host.

## Revocation

V1 has one revocation mechanism: the authority-wide epoch. There are no
per-grant revocation records, deny lists or durable grant facts. Advancing the
epoch invalidates every grant issued in an earlier epoch. Reopen always advances
and durably publishes the epoch before returning, so no pre-restart grant revives.

This profile deliberately trades revocation granularity for a closed bounded
recovery contract. A future per-grant profile would require a new checkpoint
version, explicit capacity/exhaustion behavior and separate compatibility evidence.
It cannot be inferred from the V1 grant identifier.

## Principal and session continuity

`PrincipalId` is a host-established stable subject reference scoped to one Aegis
authority namespace; it is not a credential, account name or globally meaningful
identity. `SessionId` identifies one host-authenticated continuity interval.
Credential verification and the mapping from credentials to these references are
outside the core.

Routine reauthentication creates a fresh session reference and fresh grants. A
host must not rebind an existing session reference to different credential facts.
If subject continuity becomes uncertain, an identifier is recycled, or a
credential compromise affects existing grants, the host advances the global epoch
before issuing replacements. Merely changing an external credential does not
mutate Aegis state or make an old session-bound grant valid for a new session.

## Delegation ancestry

V1 validates attenuation at creation time and carries only the resulting grant's
bounded delegation depth. Parent identifiers and ancestry are not persisted and
are not a durable inspection claim. Because global epoch revocation invalidates
parent and child together, recovery does not need ancestry to preserve revocation
semantics. Historical delegation audit belongs in an explicitly selected event or
audit integration, not in the authority checkpoint.

## Inspection boundary

The core exposes epoch and allocation frontiers. `aegis-service` additionally
holds a bounded catalogue of live opaque grant handles, delegation parent handles
and redacted decision summaries for authenticated administrative clients. That catalogue is
server-local, invalidated on disconnect/session replacement/epoch change, and is
not part of the V1 durable checkpoint. It must never make a grant reconstructible
from a read-model identifier.
