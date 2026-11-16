//! Stable, zero-authority facade for embedding Aegis.
//!
//! Credential verification and durable storage remain explicit host choices.

pub use aegis_authority as engine;
pub use aegis_host as host;
