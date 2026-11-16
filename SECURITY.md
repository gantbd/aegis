# Security policy

## Supported versions

Aegis has not made a production release. The `main` branch is the only line
currently considered for security fixes; historical snapshots and untagged
source archives are unsupported.

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a public issue, discussion, pull
request, chat room or fixture. Use GitHub private vulnerability reporting when
available, or contact the repository owner privately through their GitHub
profile to establish a confidential channel.

Include the affected revision, impact, preconditions and a minimal reproduction.
Do not attach real credentials, grant material, principal/session identifiers,
resource names or unredacted authority records.

## Security boundary

Aegis decides bounded authority from host-established identity facts. It is not
an identity provider, credential verifier, secret vault, sandbox or workflow
engine. The selected `aegis-unix-peer` adapter authenticates only the local OS
account boundary from kernel effective UID/GID; the host owns its exact mapping.
Native grants are process-local capabilities and are intentionally not
serialized. Hosts must select and configure authentication, protect durable state and prevent
decision evidence from being reused as bearer authority. The concrete
[threat model](docs/threat-model.md) records current trust boundaries, controls
and residual risks.

