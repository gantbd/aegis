//! OS-backed peer authentication for Aegis's selected local Unix profile.
//!
//! This adapter maps an effective UID/GID pair established by the kernel to
//! Aegis-owned principal and administrator facts. It does not interpret account
//! names, credentials, scopes or grants, and it never treats a UID as authority.

#![forbid(unsafe_code)]

use aegis_authority::{PrincipalId, SessionId};
use aegis_local_daemon::unix::Authenticator;
use aegis_service::AuthenticatedSessionV1;
use std::{collections::BTreeMap, os::unix::net::UnixStream};

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MappingV1 {
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub principal: PrincipalId,
    pub administrator: bool,
}

impl std::fmt::Debug for MappingV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MappingV1")
            .field("effective_identity", &"<redacted>")
            .field("principal", &self.principal)
            .field("administrator", &self.administrator)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationErrorV1 {
    InvalidLimit,
    Empty,
    Capacity,
    DuplicatePeer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationErrorV1 {
    CredentialUnavailable,
    UnknownPeer,
    SessionExhausted,
}

#[derive(Clone, Copy)]
struct PrincipalFactsV1 {
    principal: PrincipalId,
    administrator: bool,
}

/// Bounded exact peer registry plus a volatile, non-reusing session allocator.
pub struct UnixPeerAuthenticatorV1 {
    mappings: BTreeMap<(u32, u32), PrincipalFactsV1>,
    session_namespace: [u8; 8],
    next_session: u64,
}

impl UnixPeerAuthenticatorV1 {
    pub fn new(
        max_mappings: usize,
        mappings: Vec<MappingV1>,
        session_namespace: [u8; 8],
    ) -> Result<Self, ConfigurationErrorV1> {
        if max_mappings == 0 {
            return Err(ConfigurationErrorV1::InvalidLimit);
        }
        if mappings.is_empty() {
            return Err(ConfigurationErrorV1::Empty);
        }
        if mappings.len() > max_mappings {
            return Err(ConfigurationErrorV1::Capacity);
        }
        let mut retained = BTreeMap::new();
        for mapping in mappings {
            if retained
                .insert(
                    (mapping.effective_uid, mapping.effective_gid),
                    PrincipalFactsV1 {
                        principal: mapping.principal,
                        administrator: mapping.administrator,
                    },
                )
                .is_some()
            {
                return Err(ConfigurationErrorV1::DuplicatePeer);
            }
        }
        Ok(Self {
            mappings: retained,
            session_namespace,
            next_session: 0,
        })
    }

    pub fn mapping_count(&self) -> usize {
        self.mappings.len()
    }
}

impl Authenticator for UnixPeerAuthenticatorV1 {
    type Error = AuthenticationErrorV1;

    fn authenticate(&mut self, stream: &UnixStream) -> Result<AuthenticatedSessionV1, Self::Error> {
        let peer = peer_effective_ids(stream)
            .map_err(|()| AuthenticationErrorV1::CredentialUnavailable)?;
        let facts = self
            .mappings
            .get(&peer)
            .copied()
            .ok_or(AuthenticationErrorV1::UnknownPeer)?;
        let allocated = self.next_session;
        self.next_session = allocated
            .checked_add(1)
            .ok_or(AuthenticationErrorV1::SessionExhausted)?;
        let mut session = [0; 16];
        session[..8].copy_from_slice(&self.session_namespace);
        session[8..].copy_from_slice(&allocated.to_be_bytes());
        Ok(AuthenticatedSessionV1 {
            principal: facts.principal,
            session: SessionId::new(session),
            administrator: facts.administrator,
        })
    }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd"
))]
fn peer_effective_ids(stream: &UnixStream) -> Result<(u32, u32), ()> {
    nix::unistd::getpeereid(stream)
        .map(|(uid, gid)| (uid.as_raw(), gid.as_raw()))
        .map_err(|_| ())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_effective_ids(stream: &UnixStream) -> Result<(u32, u32), ()> {
    nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
        .map(|credentials| (credentials.uid(), credentials.gid()))
        .map_err(|_| ())
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "linux",
    target_os = "android"
)))]
fn peer_effective_ids(_: &UnixStream) -> Result<(u32, u32), ()> {
    Err(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actual_mapping() -> MappingV1 {
        MappingV1 {
            effective_uid: nix::unistd::geteuid().as_raw(),
            effective_gid: nix::unistd::getegid().as_raw(),
            principal: PrincipalId::new([7; 16]),
            administrator: true,
        }
    }

    #[test]
    fn kernel_peer_identity_maps_to_unique_redacted_aegis_sessions() {
        let (server, _client) = UnixStream::pair().unwrap();
        let mut authenticator =
            UnixPeerAuthenticatorV1::new(1, vec![actual_mapping()], [9; 8]).unwrap();
        let first = authenticator.authenticate(&server).unwrap();
        let second = authenticator.authenticate(&server).unwrap();
        assert_eq!(first.principal, PrincipalId::new([7; 16]));
        assert!(first.administrator);
        assert_ne!(first.session, second.session);
        assert!(!format!("{:?}", actual_mapping()).contains(&nix::unistd::geteuid().to_string()));
    }

    #[test]
    fn bounds_duplicates_unknown_peers_and_session_exhaustion_fail_closed() {
        let mapping = actual_mapping();
        assert!(matches!(
            UnixPeerAuthenticatorV1::new(0, vec![mapping], [0; 8]),
            Err(ConfigurationErrorV1::InvalidLimit)
        ));
        assert!(matches!(
            UnixPeerAuthenticatorV1::new(1, vec![], [0; 8]),
            Err(ConfigurationErrorV1::Empty)
        ));
        assert!(matches!(
            UnixPeerAuthenticatorV1::new(1, vec![mapping, mapping], [0; 8]),
            Err(ConfigurationErrorV1::Capacity)
        ));
        assert!(matches!(
            UnixPeerAuthenticatorV1::new(2, vec![mapping, mapping], [0; 8]),
            Err(ConfigurationErrorV1::DuplicatePeer)
        ));
        let (server, _client) = UnixStream::pair().unwrap();
        let mut unknown = UnixPeerAuthenticatorV1::new(
            1,
            vec![MappingV1 {
                effective_uid: mapping.effective_uid.wrapping_add(1),
                ..mapping
            }],
            [0; 8],
        )
        .unwrap();
        assert_eq!(
            unknown.authenticate(&server),
            Err(AuthenticationErrorV1::UnknownPeer)
        );
        let mut exhausted = UnixPeerAuthenticatorV1::new(1, vec![mapping], [0; 8]).unwrap();
        exhausted.next_session = u64::MAX;
        assert_eq!(
            exhausted.authenticate(&server),
            Err(AuthenticationErrorV1::SessionExhausted)
        );
    }
}
