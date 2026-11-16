# Deterministic soak profile

`make soak` runs 5,000 fresh authenticated Aegis service lifecycles. Every cycle
creates a receipt-gated in-memory authority, opens an administrator session,
issues a server-held grant, authorizes the exact action/resource, revokes the
epoch, proves the old handle is unknown and closes the session.

The fixed campaign is opt-in so ordinary correctness tests remain fast and
focused. It detects lifecycle-state accumulation, handle/epoch leakage and
repeated publication regressions in the selected service profile. It is not a
latency benchmark, filesystem/power-loss test, daemon/process soak, concurrency
proof, credential-adapter test or product SLO.

`make soak-process` runs 32 fresh two-process durable authority cycles. Each
cycle creates a private filesystem store in one daemon process, issues and uses
a grant, discards an epoch-revocation reply, exits, reopens in a second daemon
process, proves the epoch advanced through both revocation and recovery, refuses
the old session-local handle, and issues/authorizes a fresh grant. Every cycle
uses fresh paths and removes them only after both child processes exit and their
sockets are gone.

The process campaign passed on 2026-11-10 in 4.31 seconds on Darwin arm64. It is
repeatability evidence for clean process exit, receipt-gated filesystem commits,
lost-reply reconciliation and recovery fencing. It is not sudden power-loss,
kill-during-fsync, external rollback-witness, concurrent-client, long-duration,
resource-leak or product-availability evidence.
