#![forbid(unsafe_code)]

#[cfg(unix)]
mod unix {
    use aegis_authority::{EngineId, Limits, PrincipalId};
    use aegis_local_daemon::{ConnectionErrorV1, unix::DaemonErrorV1};
    use aegis_service::{Service, ServiceLimitsV1};
    use aegis_unix_peer::{MappingV1, UnixPeerAuthenticatorV1};
    use signal_hook::{
        consts::{SIGINT, SIGTERM},
        iterator::Signals,
    };
    use std::{
        error::Error,
        ffi::OsString,
        os::unix::net::UnixStream,
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::Duration,
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum OpenMode {
        Create,
        Open,
    }

    #[derive(Debug, Eq, PartialEq)]
    struct Config {
        mode: OpenMode,
        directory: PathBuf,
        socket: PathBuf,
        authority: [u8; 16],
        effective_uid: u32,
        effective_gid: u32,
        principal: [u8; 16],
        session_namespace: [u8; 8],
        administrator: bool,
    }

    impl Config {
        fn parse(values: impl IntoIterator<Item = OsString>) -> Result<Self, &'static str> {
            let mut values = values.into_iter();
            let mode = match text(values.next(), "MODE required")?.as_str() {
                "create" => OpenMode::Create,
                "open" => OpenMode::Open,
                _ => return Err("MODE must be create or open"),
            };
            let directory = values
                .next()
                .map(PathBuf::from)
                .ok_or("DIRECTORY required")?;
            let socket = values.next().map(PathBuf::from).ok_or("SOCKET required")?;
            let authority = parse_hex::<16>(values.next(), "AUTHORITY_HEX required")?;
            let effective_uid = parse_u32(values.next(), "EFFECTIVE_UID required")?;
            let effective_gid = parse_u32(values.next(), "EFFECTIVE_GID required")?;
            let principal = parse_hex::<16>(values.next(), "PRINCIPAL_HEX required")?;
            let session_namespace =
                parse_hex::<8>(values.next(), "SESSION_NAMESPACE_HEX required")?;
            let administrator = match text(values.next(), "ROLE required")?.as_str() {
                "administrator" => true,
                "principal" => false,
                _ => return Err("ROLE must be administrator or principal"),
            };
            if values.next().is_some() {
                return Err("unexpected argument");
            }
            Ok(Self {
                mode,
                directory,
                socket,
                authority,
                effective_uid,
                effective_gid,
                principal,
                session_namespace,
                administrator,
            })
        }
    }

    fn text(value: Option<OsString>, missing: &'static str) -> Result<String, &'static str> {
        value
            .ok_or(missing)?
            .into_string()
            .map_err(|_| "argument must be UTF-8")
    }

    fn parse_u32(value: Option<OsString>, missing: &'static str) -> Result<u32, &'static str> {
        let value = text(value, missing)?;
        if value.is_empty()
            || !value.bytes().all(|byte| byte.is_ascii_digit())
            || (value.len() > 1 && value.starts_with('0'))
        {
            return Err("identity must be canonical decimal u32");
        }
        value
            .parse()
            .map_err(|_| "identity must be canonical decimal u32")
    }

    fn parse_hex<const N: usize>(
        value: Option<OsString>,
        missing: &'static str,
    ) -> Result<[u8; N], &'static str> {
        let value = text(value, missing)?;
        if value.len() != N * 2
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("identifier must be canonical lowercase hexadecimal");
        }
        let mut output = [0; N];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            output[index] = (hex(pair[0])? << 4) | hex(pair[1])?;
        }
        Ok(output)
    }

    fn hex(value: u8) -> Result<u8, &'static str> {
        match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            _ => Err("identifier must be lowercase hexadecimal"),
        }
    }

    pub fn run() -> Result<(), Box<dyn Error>> {
        let config = Config::parse(std::env::args_os().skip(1)).map_err(usage)?;
        let authority_id = EngineId::new(config.authority);
        let authority = match config.mode {
            OpenMode::Create => {
                aegis_local::create_new(&config.directory, authority_id, Limits::default())
            }
            OpenMode::Open => {
                aegis_local::open_existing(&config.directory, authority_id, Limits::default())
            }
        }
        .map_err(|error| format!("authority startup refused: {error:?}"))?;
        let service = Service::new(authority, authority_id, ServiceLimitsV1::default())
            .ok_or("service limits refused")?;
        let authentication = UnixPeerAuthenticatorV1::new(
            1,
            vec![MappingV1 {
                effective_uid: config.effective_uid,
                effective_gid: config.effective_gid,
                principal: PrincipalId::new(config.principal),
                administrator: config.administrator,
            }],
            config.session_namespace,
        )
        .map_err(|error| format!("peer mapping refused: {error:?}"))?;
        let mut daemon = aegis_local_daemon::unix::Daemon::bind_new(
            &config.socket,
            service,
            authentication,
            aegis_wire::LimitsV1::default(),
            Duration::from_secs(5),
            32,
        )?;

        let stop = Arc::new(AtomicBool::new(false));
        let mut signals = Signals::new([SIGINT, SIGTERM])?;
        let signal_handle = signals.handle();
        let signal_stop = Arc::clone(&stop);
        let wake_path = config.socket.clone();
        let signal_thread = thread::Builder::new()
            .name("aegis-signal-owner".into())
            .spawn(move || {
                if signals.forever().next().is_some() {
                    signal_stop.store(true, Ordering::Release);
                    let _ = UnixStream::connect(wake_path);
                }
            })?;

        let result = serve(&mut daemon, &stop);
        signal_handle.close();
        let _ = signal_thread.join();
        result
    }

    fn serve<S, A>(
        daemon: &mut aegis_local_daemon::unix::Daemon<S, A>,
        stop: &AtomicBool,
    ) -> Result<(), Box<dyn Error>>
    where
        S: keystone_storage::CheckpointStore,
        S::Error: std::fmt::Debug,
        A: aegis_local_daemon::unix::Authenticator,
        A::Error: std::fmt::Debug,
    {
        while !stop.load(Ordering::Acquire) {
            match daemon.serve_until(stop) {
                Ok(()) => return Ok(()),
                Err(
                    DaemonErrorV1::Authentication(_)
                    | DaemonErrorV1::Session(_)
                    | DaemonErrorV1::Connection(
                        ConnectionErrorV1::BeforeDispatch(_)
                        | ConnectionErrorV1::Wire(_)
                        | ConnectionErrorV1::OutcomeUnknown(_),
                    ),
                ) => {}
                Err(error) => return Err(format!("daemon stopped: {error:?}").into()),
            }
        }
        Ok(())
    }

    fn usage(message: &'static str) -> String {
        format!(
            "{message}; usage: aegis-daemon create|open DIRECTORY SOCKET AUTHORITY_HEX EFFECTIVE_UID EFFECTIVE_GID PRINCIPAL_HEX SESSION_NAMESPACE_HEX administrator|principal"
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn configuration_is_closed_and_identifiers_are_canonical() {
            let config = Config::parse(
                [
                    "create",
                    "authority",
                    "aegis.sock",
                    "01010101010101010101010101010101",
                    "501",
                    "20",
                    "02020202020202020202020202020202",
                    "0303030303030303",
                    "administrator",
                ]
                .into_iter()
                .map(OsString::from),
            )
            .unwrap();
            assert_eq!(config.mode, OpenMode::Create);
            assert_eq!(config.authority, [1; 16]);
            assert_eq!(config.principal, [2; 16]);
            assert_eq!(config.session_namespace, [3; 8]);
            assert!(config.administrator);
            assert!(parse_hex::<16>(Some(OsString::from("01")), "missing").is_err());
            assert!(
                parse_hex::<16>(
                    Some(OsString::from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")),
                    "missing"
                )
                .is_err()
            );
        }
    }
}

#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    unix::run()
}

#[cfg(not(unix))]
fn main() {
    eprintln!("aegis-daemon requires Unix peer credentials and Unix sockets");
    std::process::exit(2);
}
