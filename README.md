# Aegis

Aegis is the planned authority engine for principals, scoped grants, delegation,
expiration, and revocation across the engine federation.

Aegis does not authenticate passwords, devices, OAuth tokens, or network peers.
Hosts establish credential facts; Aegis decides whether explicit bounded authority
evidence permits a requested action on a resource in the current epoch.

The repository now contains a deterministic volatile authority reference core.
It issues opaque non-cloneable grants through a privileged host boundary,
validates bounded resource/action requests, emits redacted attributable decision
evidence, supports non-amplifying attenuation, and revokes prior grants by epoch.
It does not authenticate credentials or claim durable recovery. See
[requirements](requirements.md), [specification](specification.md), and the
[roadmap](docs/roadmap.md).

## Development

```sh
make check
```

