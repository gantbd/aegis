# Aegis

Aegis is a bounded authority engine for principals, scoped grants, delegation,
expiration, and revocation across the engine federation.

Aegis does not authenticate passwords, devices, OAuth tokens, or network peers.
Hosts establish credential facts; Aegis decides whether explicit bounded authority
evidence permits a requested action on a resource in the current epoch.

The repository contains a deterministic bounded authority core and a separate
exclusive local-filesystem delivery profile.
It issues opaque non-cloneable grants through a privileged host boundary,
validates bounded resource/action requests, emits redacted attributable decision
evidence, supports non-amplifying attenuation, and revokes prior grants by epoch.
The core alone neither authenticates credentials nor establishes durability. See
[requirements](requirements.md), [specification](specification.md), and the
[focused roadmap](docs/roadmap.md). The staged production program is tracked in
[ROADMAP.production.md](ROADMAP.production.md); [SECURITY.md](SECURITY.md) and the
[threat model](docs/threat-model.md) define current security claims and residual
risks. The [selected authority lifecycle](docs/authority-lifecycle.md) fixes V1 to
global epoch revocation and defines principal/session rebinding and ancestry rules.

## Development

```sh
make check
```

## SDK facade

`aegis-sdk-embedded` reexports the pure authority engine and its trusted host
boundary. It selects no credential verifier or persistence adapter; applications
must compose those authority-bearing choices explicitly.

## Native service boundary

`aegis-protocol`, `aegis-service`, `aegis-client` and `aegis-wire` define the transport-neutral
service contract. A selected authentication adapter supplies verified
principal/session facts; credentials never enter the authority core. Grants remain
server-owned behind session-local numeric handles that are invalid for other
sessions and are destroyed on disconnect or epoch change. Administrative status
and grant/delegation/decision pages are bounded and do not reconstruct grants.
`aegis-local-daemon` adds a mode-`0600` new-path Unix listener, authenticated
session handshake, bounded length-prefixed dispatch, I/O deadlines, readiness and
connection health, deterministic session teardown, and pre-dispatch versus
outcome-unknown failure. Its native `connect` function returns the server-selected
session plus an `aegis-client::ServicePort`, so peer adapters do not need to own
socket framing. See the [local daemon profile](docs/local-daemon.md).
`aegis-admin-command` owns exact-confirmation and same-connection guards for
authority-bearing commands. Presentation and product shells may reuse those
guards, but neither `aegis-tui` nor Workbench owns their semantics.
Its bounded `ManagedSessionV1` owner keeps reusable grants behind caller-chosen
128-bit operation names on one authenticated connection. Numeric service
handles never escape the owner. Issue and attenuation first observe the exact
expected epoch; every authority-bearing request requires a literal rendering
of its operation, bounds and scope; and any uncertain delivery or impossible
reply terminally fences the owner. Recovery is explicit abandonment: disconnect
destroys the session-local grants, then a caller may reconnect and deliberately
rebuild authority under new operation names. The manager does not claim durable
grant replay or lost-reply reconciliation.
`aegis-admin-session` wraps that manager in one bounded, closed NDJSON
application protocol for both standalone and aggregate shells. It accepts no
credentials or socket configuration and emits no numeric handles or transport
error text. See the [managed administration session](docs/admin-session.md).
`aegis-unix-peer` supplies the selected local credential adapter. It reads the
connected peer's effective UID/GID from the kernel, applies an exact bounded
deployment mapping, and allocates a fresh namespaced Aegis session identity.
See the [Unix peer credential profile](docs/unix-peer-credentials.md).
Each authenticated connection can execute a configured finite request sequence,
so opaque grant handles remain useful without becoming transferable. Authority
mutations require the caller's exact expected epoch and stale requests do not mutate.
Restart, namespace rotation, backup custody and fail-closed restore policy are in
the [operator continuity profile](docs/operator-continuity.md).
The optional [rollback witness profile](docs/rollback-witness.md) gates exact
checkpoint correspondence without changing the default local profile.
The test-only `aegis-conformance` crate provides a public-protocol-only suite for
session isolation, non-amplifying attenuation, revocation and durable recovery;
it carries no authenticator, grant material, peer mapping or runtime policy.
`applications/aegis-daemon` is the selected standalone owner shell. It accepts
explicit create/open mode, durable directory, socket, authority namespace,
kernel peer mapping, principal, session namespace, and administrator/principal
role. It installs a continuous shutdown-aware accept loop and owns signal-driven
socket cleanup without moving authentication or authority policy into a UI or
product host.

## Qualified peer mappings

Moira maps one exact saga resource to `Moira/Administer` through the public
session-bound client. Daimon's `daimon-aegis` adapter maps the selected profile
and every distinct requested tool to current `Daimon/Execute` decisions through
the same client contract. A real Aegis service journey proves allow and proves
epoch revocation blocks Daimon retained-result delivery without a second provider
call. Neither adapter receives credentials, exports grant material, or treats a
decision summary as reusable authority.

## First durable local profile

`host/aegis-host` gates opaque grants, validation evidence and epoch revocation
on a matching durable storage receipt. `adapters/aegis-local` supplies private
Unix directory storage with a lifetime OS writer lock. The core retains zero
runtime dependencies, no I/O, no implicit clock and no grant serialization.

Initialize explicitly with `aegis_local::create_new(new_leaf, namespace, limits)`.
The trusted host reserves that namespace for this authority store, authenticates
callers, supplies truthful time and serializes use. Restart with `open_existing`:
it validates the expected namespace, retains allocation frontiers, increments the
epoch and **commits the fence before returning**. Old grants never resume; obtain
new grants through fresh privileged issuance using `host.epoch()`. Decision
evidence is historical attribution, not a reusable bearer authorization token.

An uncertain mutation releases no success and fences all subsequent operations.
Drop/reopen explicitly; do not retry issuance automatically or infer whether a
lost reply was committed. Missing, corrupt or wrong-namespace state refuses;
it is never reset. A failed initial creation can leave an orphan directory for
operator inspection. No migration from volatile/unversioned state is provided.

Every successful native operation, including validation's decision allocation,
currently persists a fixed 64-byte host record before returning. Observe the
content-free operation/commit timing and refusal/fence signals before optimizing;
there is no batching, hard storage deadline or production latency guarantee.
The store synchronizes staged files and the containing directory, additionally
requesting file `F_FULLFSYNC` on macOS. Native tests exercise actual restart,
lost revocation receipts, abrupt process exit, and old-grant rejection.

Private storage is not a credential vault, cryptographic integrity guarantee or
rollback witness. Restoring an older valid closed store can defeat monotonicity
without an external witness. The optional `aegis-witness` adapter supplies the
fail-closed correspondence contract, but not an external mechanism. Under the
default profile, do not restore a backup under a reused authority
namespace: retire that authority and explicitly initialize a fresh namespace and
store, then reauthenticate/reissue. Replication, remote providers, physical
power-loss certification and remote credential integrations are outside this profile.

