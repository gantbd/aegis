# Unix peer credential profile

Status: qualified for the selected private local Unix deployment profile.

`aegis-unix-peer` asks the operating system for the effective UID and GID of the
connected Unix-domain-socket peer. A bounded deployment-owned table maps that
exact pair to an Aegis principal and administrator fact. On every accepted
connection the adapter allocates a fresh 16-byte session identity from an
explicit eight-byte namespace plus a checked monotone counter.

The mapping is validated before use: its configured ceiling must be positive,
the table must be nonempty and within that ceiling, and duplicate peer pairs are
refused. Missing kernel evidence, unknown peers and session-counter exhaustion
fail closed before the daemon publishes its session handshake or dispatches an
authority command. Mapping and error `Debug` values disclose neither UID/GID nor
credential material.

The adapter supports Linux/Android peer credentials and `getpeereid` platforms
including macOS and the supported BSD family. Other Unix targets fail
authentication. The launcher still owns trusted-parent/socket placement, mapping
provisioning, account lifecycle and namespace uniqueness.

This profile authenticates an operating-system account boundary, not a person,
binary, container, remote machine or individual process among peers sharing the
same effective UID/GID. It supplies no passwords, tokens, certificates, account
lookup, executable attestation, revocation feed or protection from a malicious
kernel/root operator. Those profiles require separate adapters and evidence.
