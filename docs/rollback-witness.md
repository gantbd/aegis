# Optional external rollback witness profile

Status: adapter contract and fail-closed correspondence qualified; concrete
external witness mechanisms remain deployment-owned and separately attestable.

The trusted local directory profile cannot distinguish the current checkpoint
from restoration of an older, otherwise valid directory. `aegis-witness` adds a
strict decorator around the selected `CheckpointStore`. The independent witness
is provisioned for exactly one Aegis namespace by deployment wiring; namespace
selection and witness credentials never enter the authority core.

Before creation or recovery, the witness confirms either true absence or the
exact loaded revision and bytes. A missing checkpoint behind an existing anchor
is rollback. An older revision is rollback. Different bytes at the same revision
are conflict. A checkpoint ahead of the known anchor is indeterminate and
requires operator reconciliation; it is never silently adopted.

After the local store returns an exact durable commit, the decorator advances
the witness with the exact revision and bytes. Aegis publishes the candidate only
after the witness returns `Confirmed`. Witness refusal, conflict, uncertainty or
I/O failure after the local commit fences the live authority because either side
may now be the durable winner. Recovery remains refused until an operator
reconciles the independent evidence.

`Confirmed` is a trusted assertion by the concrete witness adapter. This crate
does not supply remote storage, cryptography, credentials, quorum, monotonic
hardware or physical power-loss claims. Those properties must be established by
the selected external mechanism. The default `aegis-local` profile remains
unchanged and continues to prohibit same-namespace restore.
