//! Bounded owner-side application protocol for reusable Aegis grants.
//!
//! The protocol is newline-delimited JSON, but presentation is deliberately
//! absent. Standalone and aggregate shells supply the authenticated public
//! client port and byte streams; this crate owns parsing, bounds, dispatch and
//! the response vocabulary.
#![forbid(unsafe_code)]

use std::io::{self, BufRead, Write};

use aegis_admin_command::{
    AttenuateGrantV1, AuthorizeGrantV1, IssueGrantV1, ManagedErrorV1, ManagedGrantV1,
    ManagedLimitsV1, ManagedSessionStateV1, ManagedSessionV1, OperationIdV1, action_name,
    engine_name, parse_action, parse_engine, parse_resource,
};
use aegis_client::ServicePort;
use aegis_protocol::{ScopeV1, SessionHandleV1};
use serde::{Deserialize, Serialize};

pub const PROTOCOL: &str = "aegis.admin-session.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LimitsV1 {
    pub max_commands: usize,
    pub max_line_bytes: usize,
    pub managed: ManagedLimitsV1,
}

impl Default for LimitsV1 {
    fn default() -> Self {
        Self {
            // Issue and attenuation each consume two daemon requests. The
            // selected daemon permits 32 requests per connection.
            max_commands: 16,
            max_line_bytes: 16 * 1024,
            managed: ManagedLimitsV1 {
                max_grants: 8,
                max_scopes_per_grant: 16,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndV1 {
    Eof,
    Closed,
    CommandLimit,
    Fenced,
}

#[derive(Debug)]
pub enum RunErrorV1 {
    InvalidLimits,
    Input(io::Error),
    Output(io::Error),
    Encode(serde_json::Error),
}

impl std::fmt::Display for RunErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidLimits => "invalid administration session limits",
            Self::Input(_) => "administration session input failed",
            Self::Output(_) => "administration session output failed",
            Self::Encode(_) => "administration session response encoding failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for RunErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidLimits => None,
            Self::Input(error) | Self::Output(error) => Some(error),
            Self::Encode(error) => Some(error),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum RequestV1 {
    Issue {
        version: u8,
        operation: String,
        expected_epoch: u64,
        now: u64,
        expires_at: u64,
        scopes: Vec<ScopeInputV1>,
        confirmation: String,
    },
    Attenuate {
        version: u8,
        operation: String,
        parent: String,
        expected_epoch: u64,
        now: u64,
        expires_at: u64,
        scopes: Vec<ScopeInputV1>,
        confirmation: String,
    },
    Authorize {
        version: u8,
        operation: String,
        now: u64,
        engine: String,
        resource: String,
        action: String,
        confirmation: String,
    },
    List {
        version: u8,
    },
    Close {
        version: u8,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeInputV1 {
    engine: String,
    resource: String,
    actions: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResponseV1 {
    version: u8,
    protocol: &'static str,
    complete: bool,
    terminal: bool,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    required_confirmation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant: Option<GrantOutputV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decision: Option<DecisionOutputV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grants: Option<Vec<GrantOutputV1>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GrantOutputV1 {
    operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent: Option<String>,
    epoch: u64,
    expires_at: u64,
    scope_count: usize,
    delegation_depth: u8,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DecisionOutputV1 {
    operation: String,
    epoch: u64,
    expires_at: u64,
    engine: &'static str,
    action: &'static str,
}

/// Serves one bounded authority manager over caller-supplied streams.
///
/// Invalid syntax and non-terminal refusals produce one response and leave the
/// manager ready. Transport uncertainty and impossible service replies produce
/// one terminal response and stop reading. No transport error text is emitted.
pub fn run<P: ServicePort, R: BufRead, W: Write>(
    session: SessionHandleV1,
    port: P,
    mut input: R,
    mut output: W,
    limits: LimitsV1,
) -> Result<EndV1, RunErrorV1> {
    if limits.max_commands == 0 || limits.max_line_bytes == 0 {
        return Err(RunErrorV1::InvalidLimits);
    }
    let mut manager = ManagedSessionV1::new(session, port, limits.managed)
        .map_err(|_| RunErrorV1::InvalidLimits)?;
    let mut line = Vec::new();
    for _ in 0..limits.max_commands {
        match read_bounded_line(&mut input, &mut line, limits.max_line_bytes)
            .map_err(RunErrorV1::Input)?
        {
            LineV1::Eof => return Ok(EndV1::Eof),
            LineV1::Overflow => {
                write_response(&mut output, ResponseV1::failure("line_limit", false, None))?;
                continue;
            }
            LineV1::Value => {}
        }
        let request = match serde_json::from_slice::<RequestV1>(&line) {
            Ok(request) if request.version() == 1 => request,
            Ok(_) => {
                write_response(
                    &mut output,
                    ResponseV1::failure("version_refused", false, None),
                )?;
                continue;
            }
            Err(_) => {
                write_response(
                    &mut output,
                    ResponseV1::failure("invalid_request", false, None),
                )?;
                continue;
            }
        };
        if matches!(request, RequestV1::Close { .. }) {
            write_response(&mut output, ResponseV1::closed())?;
            return Ok(EndV1::Closed);
        }
        let response = dispatch(&mut manager, request);
        let terminal = response.terminal;
        write_response(&mut output, response)?;
        if terminal || manager.state() == ManagedSessionStateV1::Fenced {
            return Ok(EndV1::Fenced);
        }
    }
    write_response(
        &mut output,
        ResponseV1::failure("command_limit", true, None),
    )?;
    Ok(EndV1::CommandLimit)
}

impl RequestV1 {
    const fn version(&self) -> u8 {
        match self {
            Self::Issue { version, .. }
            | Self::Attenuate { version, .. }
            | Self::Authorize { version, .. }
            | Self::List { version }
            | Self::Close { version } => *version,
        }
    }
}

fn dispatch<P: ServicePort>(manager: &mut ManagedSessionV1<P>, request: RequestV1) -> ResponseV1 {
    match request {
        RequestV1::Issue {
            operation,
            expected_epoch,
            now,
            expires_at,
            scopes,
            confirmation,
            ..
        } => {
            let Some(operation) = parse_operation(&operation) else {
                return ResponseV1::failure("invalid_request", false, None);
            };
            let Some(scopes) = parse_scopes(scopes) else {
                return ResponseV1::failure("invalid_request", false, None);
            };
            let request = IssueGrantV1 {
                operation,
                expected_epoch,
                now,
                expires_at,
                scopes,
            };
            match manager.issue(request, &confirmation) {
                Ok(grant) => ResponseV1::grant("issued", grant),
                Err(error) => managed_error(error),
            }
        }
        RequestV1::Attenuate {
            operation,
            parent,
            expected_epoch,
            now,
            expires_at,
            scopes,
            confirmation,
            ..
        } => {
            let (Some(operation), Some(parent), Some(scopes)) = (
                parse_operation(&operation),
                parse_operation(&parent),
                parse_scopes(scopes),
            ) else {
                return ResponseV1::failure("invalid_request", false, None);
            };
            let request = AttenuateGrantV1 {
                operation,
                parent,
                expected_epoch,
                now,
                expires_at,
                scopes,
            };
            match manager.attenuate(request, &confirmation) {
                Ok(grant) => ResponseV1::grant("attenuated", grant),
                Err(error) => managed_error(error),
            }
        }
        RequestV1::Authorize {
            operation,
            now,
            engine,
            resource,
            action,
            confirmation,
            ..
        } => {
            let (Some(operation), Some(engine), Some(resource), Some(action)) = (
                parse_operation(&operation),
                parse_engine(&engine),
                parse_resource(&resource),
                parse_action(&action),
            ) else {
                return ResponseV1::failure("invalid_request", false, None);
            };
            let request = AuthorizeGrantV1 {
                operation,
                now,
                engine,
                resource,
                action,
            };
            match manager.authorize(request, &confirmation) {
                Ok(decision) => ResponseV1 {
                    version: 1,
                    protocol: PROTOCOL,
                    complete: true,
                    terminal: false,
                    status: "authorized",
                    required_confirmation: None,
                    grant: None,
                    decision: Some(DecisionOutputV1 {
                        operation: operation_text(decision.operation),
                        epoch: decision.epoch,
                        expires_at: decision.expires_at,
                        engine: engine_name(decision.engine),
                        action: action_name(decision.action),
                    }),
                    grants: None,
                },
                Err(error) => managed_error(error),
            }
        }
        RequestV1::List { .. } => ResponseV1 {
            version: 1,
            protocol: PROTOCOL,
            complete: true,
            terminal: false,
            status: "current",
            required_confirmation: None,
            grant: None,
            decision: None,
            grants: Some(
                manager
                    .retained()
                    .into_iter()
                    .map(GrantOutputV1::from)
                    .collect(),
            ),
        },
        RequestV1::Close { .. } => unreachable!("close handled before dispatch"),
    }
}

fn managed_error<E>(error: ManagedErrorV1<E>) -> ResponseV1 {
    match error {
        ManagedErrorV1::ConfirmationMismatch { required } => {
            ResponseV1::failure("confirmation_refused", false, Some(required))
        }
        ManagedErrorV1::SessionFenced => ResponseV1::failure("session_fenced", true, None),
        ManagedErrorV1::OperationExists => ResponseV1::failure("operation_exists", false, None),
        ManagedErrorV1::OperationMissing => ResponseV1::failure("operation_missing", false, None),
        ManagedErrorV1::Capacity => ResponseV1::failure("capacity", false, None),
        ManagedErrorV1::StaleEpoch { .. } => ResponseV1::failure("stale_epoch", false, None),
        ManagedErrorV1::Transport { .. } => ResponseV1::failure("outcome_unknown", true, None),
        ManagedErrorV1::Refused { .. } => ResponseV1::failure("refused", false, None),
        ManagedErrorV1::InvalidReply { .. } => ResponseV1::failure("invalid_reply", true, None),
        ManagedErrorV1::InvalidLimits | ManagedErrorV1::InvalidRequest => {
            ResponseV1::failure("invalid_request", false, None)
        }
    }
}

impl ResponseV1 {
    const fn closed() -> Self {
        Self {
            version: 1,
            protocol: PROTOCOL,
            complete: true,
            terminal: true,
            status: "closed",
            required_confirmation: None,
            grant: None,
            decision: None,
            grants: None,
        }
    }

    fn grant(status: &'static str, grant: ManagedGrantV1) -> Self {
        Self {
            version: 1,
            protocol: PROTOCOL,
            complete: true,
            terminal: false,
            status,
            required_confirmation: None,
            grant: Some(grant.into()),
            decision: None,
            grants: None,
        }
    }

    fn failure(status: &'static str, terminal: bool, required: Option<String>) -> Self {
        Self {
            version: 1,
            protocol: PROTOCOL,
            complete: false,
            terminal,
            status,
            required_confirmation: required,
            grant: None,
            decision: None,
            grants: None,
        }
    }
}

impl From<ManagedGrantV1> for GrantOutputV1 {
    fn from(grant: ManagedGrantV1) -> Self {
        Self {
            operation: operation_text(grant.operation),
            parent: grant.parent.map(operation_text),
            epoch: grant.epoch,
            expires_at: grant.expires_at,
            scope_count: grant.scope_count,
            delegation_depth: grant.delegation_depth,
        }
    }
}

fn parse_scopes(scopes: Vec<ScopeInputV1>) -> Option<Vec<ScopeV1>> {
    scopes
        .into_iter()
        .map(|scope| {
            let engine = parse_engine(&scope.engine)?;
            let resource = parse_resource(&scope.resource)?;
            let actions = parse_actions(scope.actions)?;
            Some(ScopeV1 {
                engine,
                resource,
                actions,
            })
        })
        .collect()
}

fn parse_actions(actions: Vec<String>) -> Option<u8> {
    if actions.is_empty() {
        return None;
    }
    let mut bits = 0_u8;
    for value in actions {
        let action = parse_action(&value)?;
        let bit = 1 << action as u8;
        if bits & bit != 0 {
            return None;
        }
        bits |= bit;
    }
    Some(bits)
}

fn parse_operation(value: &str) -> Option<OperationIdV1> {
    parse_hex::<16>(value).map(OperationIdV1::new)
}

fn operation_text(operation: OperationIdV1) -> String {
    hex_text(operation.into_bytes())
}

fn parse_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut output = [0; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(output)
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn hex_text<const N: usize>(value: [u8; N]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

enum LineV1 {
    Eof,
    Value,
    Overflow,
}

fn read_bounded_line<R: BufRead>(
    input: &mut R,
    line: &mut Vec<u8>,
    limit: usize,
) -> io::Result<LineV1> {
    line.clear();
    let mut overflow = false;
    loop {
        let available = input.fill_buf()?;
        if available.is_empty() {
            return if line.is_empty() && !overflow {
                Ok(LineV1::Eof)
            } else if overflow {
                Ok(LineV1::Overflow)
            } else {
                Ok(LineV1::Value)
            };
        }
        let end = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if !overflow {
            let content_end = if available.get(end.wrapping_sub(1)) == Some(&b'\n') {
                end - 1
            } else {
                end
            };
            let remaining = limit.saturating_sub(line.len());
            if content_end > remaining {
                overflow = true;
            } else {
                line.extend_from_slice(&available[..content_end]);
            }
        }
        let ended = available.get(end.wrapping_sub(1)) == Some(&b'\n');
        input.consume(end);
        if ended {
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(if overflow {
                LineV1::Overflow
            } else {
                LineV1::Value
            });
        }
    }
}

fn write_response<W: Write>(output: &mut W, response: ResponseV1) -> Result<(), RunErrorV1> {
    serde_json::to_writer(&mut *output, &response).map_err(RunErrorV1::Encode)?;
    output.write_all(b"\n").map_err(RunErrorV1::Output)?;
    output.flush().map_err(RunErrorV1::Output)
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::VecDeque, io::Cursor, rc::Rc};

    use aegis_admin_command::{AttenuateGrantV1, AuthorizeGrantV1, IssueGrantV1};
    use aegis_protocol::{
        ActionV1, AuthorityStatusV1, CommandV1, DecisionHandleV1, DecisionSummaryV1,
        EngineNamespaceV1, GrantHandleV1, GrantSummaryV1, OutcomeV1, ReplyV1,
    };
    use serde_json::{Value, json};

    use super::*;

    struct Port {
        replies: VecDeque<Result<ReplyV1, &'static str>>,
        commands: Rc<RefCell<Vec<CommandV1>>>,
    }

    impl ServicePort for Port {
        type Error = &'static str;

        fn execute(
            &mut self,
            _: SessionHandleV1,
            command: CommandV1,
        ) -> Result<ReplyV1, Self::Error> {
            self.commands.borrow_mut().push(command);
            self.replies.pop_front().expect("scripted reply")
        }
    }

    fn status() -> Result<ReplyV1, &'static str> {
        Ok(ReplyV1::Accepted(OutcomeV1::Status(AuthorityStatusV1 {
            epoch: 4,
            active_grants: 0,
            retained_decisions: 0,
        })))
    }

    fn grant(
        handle: u64,
        parent: Option<u64>,
        expires_at: u64,
        depth: u8,
    ) -> Result<ReplyV1, &'static str> {
        Ok(ReplyV1::Accepted(OutcomeV1::GrantIssued(GrantSummaryV1 {
            handle: GrantHandleV1(handle),
            parent: parent.map(GrantHandleV1),
            epoch: 4,
            expires_at,
            scope_count: 1,
            delegation_depth: depth,
        })))
    }

    fn scope(actions: u8) -> ScopeV1 {
        ScopeV1 {
            engine: EngineNamespaceV1::Hermes,
            resource: [7; 16],
            actions,
        }
    }

    fn lines(output: Vec<u8>) -> Vec<Value> {
        String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn one_protocol_owns_named_issue_attenuation_authorization_and_close() {
        let parent = OperationIdV1::new([1; 16]);
        let child = OperationIdV1::new([2; 16]);
        let issue = IssueGrantV1 {
            operation: parent,
            expected_epoch: 4,
            now: 5,
            expires_at: 30,
            scopes: vec![scope(
                (1 << ActionV1::Observe as u8) | (1 << ActionV1::Delegate as u8),
            )],
        };
        let attenuation = AttenuateGrantV1 {
            operation: child,
            parent,
            expected_epoch: 4,
            now: 6,
            expires_at: 20,
            scopes: vec![scope(1 << ActionV1::Observe as u8)],
        };
        let authorization = AuthorizeGrantV1 {
            operation: child,
            now: 7,
            engine: EngineNamespaceV1::Hermes,
            resource: [7; 16],
            action: ActionV1::Observe,
        };
        let requests = [
            json!({
                "version": 1, "command": "issue",
                "operation": operation_text(parent), "expected_epoch": 4,
                "now": 5, "expires_at": 30,
                "scopes": [{"engine":"hermes", "resource": hex_text([7; 16]),
                    "actions":["observe", "delegate"]}],
                "confirmation": issue.confirmation()
            }),
            json!({
                "version": 1, "command": "attenuate",
                "operation": operation_text(child), "parent": operation_text(parent),
                "expected_epoch": 4, "now": 6, "expires_at": 20,
                "scopes": [{"engine":"hermes", "resource": hex_text([7; 16]),
                    "actions":["observe"]}],
                "confirmation": attenuation.confirmation()
            }),
            json!({"version": 1, "command": "list"}),
            json!({
                "version": 1, "command": "authorize",
                "operation": operation_text(child), "now": 7, "engine": "hermes",
                "resource": hex_text([7; 16]), "action": "observe",
                "confirmation": authorization.confirmation()
            }),
            json!({"version": 1, "command": "close"}),
        ];
        let input = requests
            .into_iter()
            .map(|value| serde_json::to_string(&value).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let commands = Rc::new(RefCell::new(Vec::new()));
        let port = Port {
            replies: vec![
                status(),
                grant(10, None, 30, 0),
                status(),
                grant(11, Some(10), 20, 1),
                Ok(ReplyV1::Accepted(OutcomeV1::Authorized(
                    DecisionSummaryV1 {
                        handle: DecisionHandleV1(99),
                        epoch: 4,
                        expires_at: 20,
                        engine: EngineNamespaceV1::Hermes,
                        action: ActionV1::Observe,
                    },
                ))),
            ]
            .into(),
            commands: Rc::clone(&commands),
        };
        let mut output = Vec::new();
        let end = run(
            SessionHandleV1(3),
            port,
            Cursor::new(input),
            &mut output,
            LimitsV1::default(),
        )
        .unwrap();

        assert_eq!(end, EndV1::Closed);
        let responses = lines(output);
        assert_eq!(responses.len(), 5);
        assert_eq!(responses[0]["status"], "issued");
        assert_eq!(responses[1]["status"], "attenuated");
        assert_eq!(responses[2]["grants"].as_array().unwrap().len(), 2);
        assert_eq!(responses[3]["status"], "authorized");
        assert_eq!(responses[4]["status"], "closed");
        assert_eq!(responses[4]["terminal"], true);
        let rendered = serde_json::to_string(&responses).unwrap();
        assert!(!rendered.contains("\"handle\""));
        assert!(!rendered.contains("99"));
        assert!(matches!(
            commands.borrow()[3],
            CommandV1::Attenuate {
                parent: GrantHandleV1(10),
                ..
            }
        ));
    }

    #[test]
    fn outcome_unknown_emits_terminal_response_and_does_not_read_another_command() {
        let operation = OperationIdV1::new([1; 16]);
        let issue = IssueGrantV1 {
            operation,
            expected_epoch: 4,
            now: 5,
            expires_at: 30,
            scopes: vec![scope(1 << ActionV1::Observe as u8)],
        };
        let input = format!(
            "{}\n{}\n",
            json!({
                "version":1, "command":"issue", "operation":operation_text(operation),
                "expected_epoch":4, "now":5, "expires_at":30,
                "scopes":[{"engine":"hermes", "resource":hex_text([7; 16]),
                    "actions":["observe"]}], "confirmation":issue.confirmation()
            }),
            json!({"version":1, "command":"list"})
        );
        let commands = Rc::new(RefCell::new(Vec::new()));
        let port = Port {
            replies: vec![status(), Err("lost")].into(),
            commands: Rc::clone(&commands),
        };
        let mut output = Vec::new();
        assert_eq!(
            run(
                SessionHandleV1(3),
                port,
                Cursor::new(input),
                &mut output,
                LimitsV1::default(),
            )
            .unwrap(),
            EndV1::Fenced
        );
        let responses = lines(output);
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0]["status"], "outcome_unknown");
        assert_eq!(responses[0]["terminal"], true);
        assert_eq!(commands.borrow().len(), 2);
    }

    #[test]
    fn oversized_line_is_drained_and_closed_schema_recovers_on_the_next_line() {
        let input = format!(
            "{}\n{}\n{}\n",
            "x".repeat(129),
            json!({"version":1, "command":"list", "credential":"forbidden"}),
            json!({"version":1, "command":"close"})
        );
        let port = Port {
            replies: VecDeque::new(),
            commands: Rc::new(RefCell::new(Vec::new())),
        };
        let mut output = Vec::new();
        let limits = LimitsV1 {
            max_line_bytes: 128,
            ..LimitsV1::default()
        };
        assert_eq!(
            run(
                SessionHandleV1(3),
                port,
                Cursor::new(input),
                &mut output,
                limits,
            )
            .unwrap(),
            EndV1::Closed
        );
        let responses = lines(output);
        assert_eq!(responses[0]["status"], "line_limit");
        assert_eq!(responses[1]["status"], "invalid_request");
        assert_eq!(responses[2]["status"], "closed");
    }

    #[test]
    fn command_ceiling_is_explicit_and_terminal() {
        let port = Port {
            replies: VecDeque::new(),
            commands: Rc::new(RefCell::new(Vec::new())),
        };
        let mut output = Vec::new();
        let limits = LimitsV1 {
            max_commands: 1,
            ..LimitsV1::default()
        };
        assert_eq!(
            run(
                SessionHandleV1(3),
                port,
                Cursor::new("{\"version\":1,\"command\":\"list\"}\n"),
                &mut output,
                limits,
            )
            .unwrap(),
            EndV1::CommandLimit
        );
        let responses = lines(output);
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["status"], "current");
        assert_eq!(responses[1]["status"], "command_limit");
        assert_eq!(responses[1]["terminal"], true);
    }
}
