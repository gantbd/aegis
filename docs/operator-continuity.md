# Operator continuity profile

Status: selected procedure for the exclusive default local authority profile. It
does not select a concrete external witness or make default same-namespace
rollback safe; the optional witnessed profile is documented separately.

## Invariants

- One authority namespace has exactly one exclusive live directory and one
  credential-to-principal mapping authority.
- A namespace is never recycled. A retired namespace and its grants remain
  retired permanently.
- Live grants and connection handles are never backed up, restored, exported or
  reconstructed. Recovery always requires fresh sessions and issuance.
- `open_existing` is a mutating recovery operation: it advances and durably
  commits the epoch fence before returning.
- An old but well-formed checkpoint cannot be distinguished from the newest
  checkpoint by this profile. Same-namespace restore therefore requires the
  separately selected external-witness profile; otherwise rotate the namespace.

## Planned restart

1. Stop admission and let bounded connections drain. Record the current status
   epoch through the administrative client; do not record grant handles.
2. Stop the daemon and close the `DurableAuthority`. Confirm that no process owns
   the directory lock before moving or copying the directory.
3. Start with `open_existing`, the same expected namespace and the same or tighter
   validated limits. A successful open has already committed an epoch strictly
   greater than the stopped authority's epoch.
4. Start the listener on a new socket path, reconnect clients, inspect status and
   issue fresh session-bound grants. Never attempt to reuse old handles.

Failure to reopen is a hard stop. Do not create a replacement directory under the
same namespace, edit `checkpoint.bin`, relax the expected namespace, or infer
success from filesystem timestamps.

## Backup

Backups are sensitive plaintext continuity evidence, not capability backups.

1. Quiesce and stop the authority as for a planned restart. Online copying is not
   qualified, even though checkpoint publication uses atomic replacement.
2. Copy the complete private authority directory, including `.owner.lock` and
   `checkpoint.bin`, while preserving file types and private modes. A pending
   staging entry or any additional entry makes the source ineligible.
3. Bind the archive to the authority namespace, creation time, deployment ID and
   an operator-controlled integrity record outside the archive. These labels aid
   custody and selection; they are not a rollback witness.
4. Encrypt and access-control the archive as operationally sensitive state. Test
   media readability without opening the only retained copy as an authority.

Taking a backup does not authorize deleting the live directory or claiming that
the archive is current.

## Restore and namespace rotation

The default disaster-recovery action is namespace rotation, not an in-place
same-namespace restore:

1. Fence admission and stop every process that could hold the old authority or
   authenticate its sessions. Treat an uncertain revocation or storage outcome as
   fenced, not successful or failed.
2. Permanently retire the old namespace in the operator inventory and in every
   peer mapping. Preserve its directory/archive read-only for investigation.
3. Generate and reserve a fresh 16-byte namespace outside Aegis. Create a fresh
   authority at a new private directory with `create_new`; never rewrite the old
   checkpoint to carry the new namespace.
4. Update the credential adapter and exact peer resource/action mappings to the
   new namespace. Bring up the new socket, inspect epoch zero, and issue fresh
   grants only after those mappings agree.
5. Exercise one authenticated issue/authorize/refuse journey, then reopen once
   and verify the recovery fence before declaring the replacement ready.

Restoring an archive under its original namespace is prohibited by this profile.
It becomes permissible only when a qualified external witness proves the archive
revision/epoch is not older than the last accepted authority state and the restore
journey is covered by acceptance evidence.

## Uncertain outcomes and reconciliation

- Before-dispatch failures did not execute a command and may be retried after a
  fresh status read.
- `OutcomeUnknown` means execution may have committed. Reconnect before acting.
- For epoch revocation, read status: the observed epoch decides whether the
  requested transition occurred. A stale retry refuses with the actual epoch.
- For issue or attenuation, disconnect destroys the only returned server handle.
  A possibly committed allocation may remain consumed, but no handle is restored.
  Reconcile epoch/status and issue fresh authority deliberately.
- A fenced durable host is never cleared by a metric, cached reply or retry. Stop
  it and recover with `open_existing`, which publishes a fresh epoch fence.

## Socket and process recovery

The daemon refuses an existing socket path and removes only the exact socket inode
it created. If startup finds an existing entry, first prove the owning process is
dead and inspect that the entry is a socket in the trusted parent. Remove only
that exact stale socket; never recursively clean the authority directory or its
parent. A replacement file or changed inode is an incident, not cleanup input.

## Evidence to retain

Retain content-free deployment evidence: namespace identifier, software and
fixture versions, selected limits, start/stop times, recovery epoch before client
admission, backup custody metadata, rotation approvals and acceptance-test result.
Do not retain credentials, scope bodies, resources, native grants or session-local
handles in general logs.
