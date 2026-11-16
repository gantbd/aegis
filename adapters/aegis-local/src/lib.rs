//! Local Unix storage wiring; no secrets, identity-provider or credential logic.
//!
//! ```no_run
//! fn main() -> Result<(), aegis_local::LocalError> {
//!     use aegis_authority::{EngineId, Limits};
//!     let path = std::path::Path::new("/trusted-parent/new-authority");
//!     // The trusted host must reserve this namespace exclusively; not a credential.
//!     let namespace = EngineId::new([1; 16]);
//!     let host = aegis_local::create_new(path, namespace, Limits::default())?;
//!     drop(host);
//!     let recovered = aegis_local::open_existing(path, namespace, Limits::default())?;
//!     assert_eq!(recovered.epoch()?.0, 1); // Fence already committed.
//!     Ok(())
//! }
//! ```
#![forbid(unsafe_code)]
#[cfg(unix)]
mod local {
    use aegis_authority::{Engine, EngineId, Limits, persistence::CheckpointErrorV1};
    use aegis_host::{DurableAuthority, HostError, STORAGE_VALUE_BYTES_V1};
    use keystone_storage_directory::{DirectoryCheckpointStore, DirectoryErrorV1, LimitsV1};
    use std::path::Path;
    pub type LocalAuthority = DurableAuthority<DirectoryCheckpointStore>;
    pub type LocalError = HostError<DirectoryErrorV1>;
    const STORAGE: LimitsV1 = LimitsV1 {
        max_key_bytes: 64,
        max_value_bytes: STORAGE_VALUE_BYTES_V1,
    };

    pub fn create_new(
        path: impl AsRef<Path>,
        namespace: EngineId,
        limits: Limits,
    ) -> Result<LocalAuthority, LocalError> {
        Engine::try_new(namespace, limits)
            .map_err(|_| HostError::Checkpoint(CheckpointErrorV1::Disabled))?;
        let store =
            DirectoryCheckpointStore::create_new(path, STORAGE).map_err(HostError::Store)?;
        DurableAuthority::create_new(store, namespace, limits)
    }
    pub fn open_existing(
        path: impl AsRef<Path>,
        namespace: EngineId,
        limits: Limits,
    ) -> Result<LocalAuthority, LocalError> {
        let store =
            DirectoryCheckpointStore::open_existing(path, STORAGE).map_err(HostError::Store)?;
        DurableAuthority::open(store, namespace, limits)
    }
}
#[cfg(unix)]
pub use local::*;
