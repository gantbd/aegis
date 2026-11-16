#![cfg(unix)]
use aegis_authority::{
    ActionSetV1, ActionV1, AuthorityEpoch, AuthorizationRequestV1, EngineId, EngineNamespaceV1,
    GrantDescriptorV1, Limits, LogicalTime, PrincipalId, RefusalV1, ResourceId, ResourceScopeV1,
};
use aegis_host::{DurableAuthority, HostError};
use keystone_storage::{Checkpoint, CheckpointStore, CommitOutcome, Revision};
use keystone_storage_directory::{DirectoryCheckpointStore, DirectoryErrorV1, LimitsV1};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "aegis-local-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> PathBuf {
        self.0.join("authority")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn namespace() -> EngineId {
    EngineId::new([1; 16])
}
fn descriptor(epoch: AuthorityEpoch) -> GrantDescriptorV1 {
    GrantDescriptorV1::new(
        PrincipalId::new([2; 16]),
        None,
        namespace(),
        epoch,
        LogicalTime(50),
        vec![ResourceScopeV1::new(
            EngineNamespaceV1::Daimon,
            ResourceId::new([3; 16]),
            ActionSetV1::top(),
        )],
    )
}
fn request() -> AuthorizationRequestV1 {
    AuthorizationRequestV1::new(
        PrincipalId::new([2; 16]),
        None,
        EngineNamespaceV1::Daimon,
        ResourceId::new([3; 16]),
        ActionV1::Execute,
    )
}

#[test]
fn filesystem_recovery_commits_fence_retains_frontiers_and_never_revives_old_grants() {
    let fixture = Fixture::new();
    let mut host = aegis_local::create_new(fixture.path(), namespace(), Limits::default()).unwrap();
    let grant = host
        .issue(descriptor(host.epoch().unwrap()), LogicalTime(1))
        .unwrap();
    let evidence = host.validate(&grant, &request(), LogicalTime(2)).unwrap();
    let revision = host.revision().unwrap();
    assert!(aegis_local::open_existing(fixture.path(), namespace(), Limits::default()).is_err());
    drop(host);
    let mut recovered =
        aegis_local::open_existing(fixture.path(), namespace(), Limits::default()).unwrap();
    assert_eq!(recovered.epoch().unwrap(), AuthorityEpoch(1));
    assert_eq!(recovered.revision(), Some(Revision(revision.0 + 1)));
    assert_eq!(recovered.signals().commits, 1);
    assert!(matches!(
        recovered.validate(&grant, &request(), LogicalTime(2)),
        Err(HostError::Domain(RefusalV1::Revoked))
    ));
    let fresh = recovered
        .issue(descriptor(recovered.epoch().unwrap()), LogicalTime(2))
        .unwrap();
    let decision = recovered
        .validate(&fresh, &request(), LogicalTime(2))
        .unwrap();
    assert_ne!(evidence.decision_id_bytes(), decision.decision_id_bytes());
    assert_eq!(
        (
            recovered.signals().next_grant,
            recovered.signals().next_decision
        ),
        (2, 2)
    );
    drop(recovered);
    let mut reopened =
        aegis_local::open_existing(fixture.path(), namespace(), Limits::default()).unwrap();
    assert_eq!(reopened.epoch().unwrap(), AuthorityEpoch(2));
    assert!(matches!(
        reopened.validate(&fresh, &request(), LogicalTime(2)),
        Err(HostError::Domain(RefusalV1::Revoked))
    ));
}

struct LoseReceipt(DirectoryCheckpointStore);
impl CheckpointStore for LoseReceipt {
    type Error = DirectoryErrorV1;
    fn load(&self, key: &str) -> Result<Option<Checkpoint>, Self::Error> {
        self.0.load(key)
    }
    fn compare_exchange(
        &mut self,
        key: &str,
        expected: Option<Revision>,
        bytes: &[u8],
    ) -> Result<CommitOutcome, Self::Error> {
        let result = self.0.compare_exchange(key, expected, bytes)?;
        // Keep the mandatory open fence; lose the next mutation receipt.
        if expected.is_some_and(|rev| rev.0 >= 2) && matches!(result, CommitOutcome::Committed(_)) {
            Ok(CommitOutcome::Indeterminate)
        } else {
            Ok(result)
        }
    }
}

#[test]
fn lost_revocation_receipt_fences_live_authority_and_recovery_never_reenables_it() {
    let fixture = Fixture::new();
    let mut host = aegis_local::create_new(fixture.path(), namespace(), Limits::default()).unwrap();
    let grant = host
        .issue(descriptor(host.epoch().unwrap()), LogicalTime(1))
        .unwrap();
    drop(host);
    let store =
        DirectoryCheckpointStore::open_existing(fixture.path(), LimitsV1::default()).unwrap();
    let mut host =
        DurableAuthority::open(LoseReceipt(store), namespace(), Limits::default()).unwrap();
    assert_eq!(host.revision(), Some(Revision(2)));
    assert!(matches!(host.revoke_epoch(), Err(HostError::Indeterminate)));
    assert!(matches!(
        host.validate(&grant, &request(), LogicalTime(2)),
        Err(HostError::Fenced)
    ));
    drop(host);
    let mut recovered =
        aegis_local::open_existing(fixture.path(), namespace(), Limits::default()).unwrap();
    assert_eq!(recovered.epoch().unwrap(), AuthorityEpoch(3));
    assert!(matches!(
        recovered.validate(&grant, &request(), LogicalTime(2)),
        Err(HostError::Domain(RefusalV1::Revoked))
    ));
}

#[test]
fn wrong_namespace_corrupt_or_missing_state_refuse_without_reset() {
    let fixture = Fixture::new();
    drop(aegis_local::create_new(fixture.path(), namespace(), Limits::default()).unwrap());
    let head = fixture.path().join("checkpoint.bin");
    let original = std::fs::read(&head).unwrap();
    assert!(
        aegis_local::open_existing(fixture.path(), EngineId::new([9; 16]), Limits::default())
            .is_err()
    );
    assert_eq!(std::fs::read(&head).unwrap(), original);
    std::fs::write(&head, b"corrupt").unwrap();
    assert!(aegis_local::open_existing(fixture.path(), namespace(), Limits::default()).is_err());
    std::fs::remove_file(head).unwrap();
    assert!(aegis_local::open_existing(fixture.path(), namespace(), Limits::default()).is_err());
    assert!(aegis_local::create_new(fixture.path(), namespace(), Limits::default()).is_err());
}

#[test]
fn known_invalid_configuration_creates_no_directory() {
    let fixture = Fixture::new();
    assert!(
        aegis_local::create_new(
            fixture.path(),
            namespace(),
            Limits {
                max_scopes_per_grant: 0,
                ..Limits::default()
            }
        )
        .is_err()
    );
    assert!(!fixture.path().exists());
}

#[test]
fn process_helper() {
    let Some(path) = std::env::var_os("AEGIS_TEST_STORE") else {
        return;
    };
    let mut host = aegis_local::open_existing(path, namespace(), Limits::default()).unwrap();
    assert_eq!(host.epoch().unwrap(), AuthorityEpoch(1));
    let grant = host
        .issue(descriptor(host.epoch().unwrap()), LogicalTime(1))
        .unwrap();
    host.validate(&grant, &request(), LogicalTime(2)).unwrap();
    std::process::exit(0); // Deliberately no Drop/lock cleanup.
}

#[test]
fn abrupt_process_exit_preserves_allocations_and_next_open_fences_the_previous_process() {
    let fixture = Fixture::new();
    let mut host = aegis_local::create_new(fixture.path(), namespace(), Limits::default()).unwrap();
    let old = host
        .issue(descriptor(host.epoch().unwrap()), LogicalTime(1))
        .unwrap();
    host.validate(&old, &request(), LogicalTime(2)).unwrap();
    drop(host);
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "process_helper", "--nocapture"])
        .env("AEGIS_TEST_STORE", fixture.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut recovered =
        aegis_local::open_existing(fixture.path(), namespace(), Limits::default()).unwrap();
    assert_eq!(recovered.epoch().unwrap(), AuthorityEpoch(2));
    assert_eq!(
        (
            recovered.signals().next_grant,
            recovered.signals().next_decision
        ),
        (2, 2)
    );
    assert!(matches!(
        recovered.validate(&old, &request(), LogicalTime(2)),
        Err(HostError::Domain(RefusalV1::Revoked))
    ));
}
