# Aegis threat and privacy model

Status: baseline for the current embedded, authenticated private-service and
exclusive local-directory profiles.

## Assets and trust boundaries

Protected assets are authority epochs and allocation frontiers, live opaque
grants, principal/session bindings, resource/action scopes, decision attribution,
checkpoint state and operational evidence. Trust boundaries exist between the
credential-establishing host and Aegis, unprivileged and privileged host calls,
the deterministic engine and durable host, the host and checkpoint adapter, and
the private directory and the surrounding operating system.

The current physical profile trusts the process host, existing parent directory,
current UID and non-rollback local storage. Same-UID compromise, restored old
but valid state, physical power loss, malicious kernels and credential-provider
failure are outside its protection claims. The selected local adapter trusts the
kernel's connected-peer effective UID/GID and a deployment-owned exact mapping;
it does not distinguish hostile processes running under the same account.

## STRIDE controls and residual risks

| Threat | Current control | Residual risk / required gate |
| --- | --- | --- |
| Principal or session spoofing | Service accepts typed verified facts; selected Unix adapter maps kernel effective UID/GID exactly and allocates a fresh session per accepted connection | Mapping provisioning, malicious kernels, remote credentials and hostile same-UID peers remain outside the profile |
| Grant fabrication or transfer | Private construction, non-cloneable native grant, engine/epoch binding | Compromised process memory can misuse live capabilities |
| Delegation amplification | Exhaustive action lattice, subset/expiry/depth validation and public-service non-amplification conformance | V1 deliberately has no durable ancestry or per-grant revocation; peer mappings still require exact-scope qualification |
| Revocation rollback | Mandatory recovery epoch advance committed before use | Restoring an older valid store is undetectable without external witness |
| Decision repudiation | Attributable bounded decision evidence; protocol summaries omit resource/subject/session/grant material and cannot enter authorization | Evidence is volatile historical attribution, not durable audit or bearer proof |
| Information disclosure | Redacted `Debug`, opaque IDs, content-free signals, private files | Filesystem metadata and plaintext checkpoint remain visible to trusted host/UID |
| Denial of service | Explicit capacities, checked counters, bounded frames/connections, I/O deadlines and refusal-before-publication | No principal fairness or supervised accept-loop profile yet |
| Durable-state tampering | Private modes, no-follow checks, pinned resources, canonical decoder | No cryptographic integrity against a privileged same-UID attacker |

## LINDDUN privacy considerations

Even redacted decisions can reveal that authority activity occurred. Epoch,
allocation and timing signals may permit linkability or usage inference. Exporters
must keep cardinality fixed, avoid principal/resource labels and treat authority
records and backups as sensitive plaintext. Grant or decision identifiers must
not be placed in general logs, metrics or crash reports.

## Security release gates

- Native grants remain unserializable and cannot cross a wire boundary.
- Any service authenticates the current session before disclosure or mutation.
- Protected operations use current authority, exact revision and bounded inputs.
- Indeterminate or weak durable evidence fences the live authority.
- Backup/restore cannot claim rollback safety until the optional witness adapter
  is paired with a concrete external mechanism whose durability is selected and tested.
- New peer mappings document exact resources/actions and prove no amplification.

