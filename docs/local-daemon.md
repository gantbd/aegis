# Local daemon profile

Status: qualified bounded-session private Unix connection profile with a selected
OS peer-credential adapter and standalone owner application.

`aegis-local-daemon` binds only a new filesystem path and refuses replacement of
an existing entry. The created Unix socket is mode `0600`; the embedding launcher
owns trusted-parent selection and process identity. A selected authenticator maps
the accepted peer to verified principal/session facts before `aegis-service`
creates a session. Credentials never enter the wire protocol or authority core.
The selected `aegis-unix-peer` profile reads effective UID/GID from the connected
socket, applies an exact bounded mapping and allocates a fresh namespaced session.

The daemon sends a canonical session-opened handshake, applies finite read/write
timeouts, accepts a configured finite sequence of bounded length-prefixed requests,
requires every session handle to match the connection, writes bounded replies,
and destroys the service
session on every exit path. Input, framing and authentication failures happen
before dispatch. A failed write after service execution is `OutcomeUnknown`; the
caller must reconnect and inspect/reconcile rather than retrying an authority
mutation blindly.

The companion `connect` path performs the same bounded handshake and returns the
server-selected handle with a transport-neutral `aegis-client::ServicePort`.
Encoding failure occurs before send; request or reply I/O failure after dispatch
begins is `OutcomeUnknown`. A caller-supplied handle different from the negotiated
session is rejected locally. Peer adapters can therefore use the public client
without duplicating private socket framing or importing service internals.

Health is content-free and reports readiness, active/accepted/refused connections,
outcome-unknown replies and counter saturation. Drop removes the socket only when
its device/inode still match the entry created by this daemon, avoiding deletion
of a replacement path.

The real-socket acceptance test covers socket mode, authenticated handshake, an
issue-to-authorize journey using one server-held handle, correspondence with the
embedded engine's epoch/expiry result, session teardown, health and owned-path
cleanup. A separate transport test proves clean inter-frame EOF and the request
ceiling. A two-subprocess journey uses `aegis-client` over the canonical socket:
the first daemon loses a committed revocation reply, and the second reopens the
same directory, observes recovery epoch 2, rejects the old handle and validates
freshly issued authority. A separate daemon journey accepts the mapped kernel
peer and rejects an unknown peer before handshake or authority mutation. This is
not multi-user hostile-host or hostile same-UID defense, daemon installer or
remote-network profile. `aegis-daemon` supplies the local launch composition: it
requires canonical explicit authority, principal, session namespace and role
inputs, serves until SIGINT/SIGTERM, wakes a blocked accept without authenticating
the wake connection, and removes only its owned socket. It is independently
usable and may be supervised by Workbench; in either case Aegis remains the
authority and authentication owner.
