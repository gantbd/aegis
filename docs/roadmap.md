# Roadmap

## Phase 0 — authority algebra

- [Complete for volatile profile] Close principal, action, resource, session,
  grant, and refusal vocabularies.
- [Complete] Specify and test subset, intersection, join, bounds, and attenuation
  laws for action scopes.
- Threat-model spoofing, confused deputy, grant replay, delegation amplification,
  epoch rollback, disclosure, and denial of service.

## Phase 1 — volatile core

- [Complete for volatile profile] Implement privileged issuance, validation,
  attenuation, expiry, and epoch revocation.
- [Complete for six-action algebra] Exhaustive distributive bounded-lattice laws;
  attenuation refusal scenarios remain separate, not a proof of arbitrary policy.
- Add cross-engine, cross-session, expired, revoked, and capacity scenarios.

## Phase 2 — recovery and codec

- [Complete] Fixed canonical state checkpoint; live grants deliberately excluded.
- [Complete] Durable recovery epoch fence and retained allocation frontiers.
- [Complete for first local profile] Parser/fault/restart/subprocess tests.
- [Qualified contract] Optional exact-checkpoint external witness decorator;
  concrete witness mechanisms and hostile-storage integrity remain unavailable.
- [Complete] Native durable host, local directory adapter and content-safe signals.

## Phase 3 — integration

- [Qualified] Expose the exact current Aegis session's owner-retained principal
  through a zero-payload, read-only, redacted public observation so peer
  adapters can derive attribution instead of trusting parallel configuration.
  Cross-component identity equivalence remains a separately qualified relation.
- [Qualified] Native public continuity/non-amplification contract through durable
  recovery, with protocol-only reusable conformance.
- [Qualified] Two-daemon-process public-client journey spanning lost revocation
  reply, durable reopen, old-handle rejection and fresh post-recovery authority.
- [Qualified] Moira exact saga `Administer` mapping through public Aegis client.
- [Qualified] Daimon profile and distinct-tool execution mapping through the
  public client; the local daemon now exposes a reusable public-client Unix port
  for process composition.
- [Qualified in a six-process chain] Durable Moira→Daimon execution obtains live Aegis
  profile/tool decisions alongside exact Chronos attempt validation before the
  provider is invoked. After a discarded reply, a fresh Daimon process obtains a
  fresh grant from the same live authority and returns the retained result without
  another Chronos lookup or provider call, then publishes one canonical result
  event through an independent Hermes daemon.
- [Qualified in two independent service processes] Hermes maps exact stream
  append to `Hermes/Submit` and denies read without `Observe` through public
  daemon traffic.
- Keep Agora, Chronos, and Vellum resource mappings in separately owned
  adapters or consuming-engine compositions. Qualify each mapping through
  Aegis's public client without importing its domain schema or making Aegis the
  integration owner.
- Keep credential verification and secret storage outside Aegis.

## Phase 4 — reusable administration surface and standalone CLI

- [Qualified] Define `aegis-tui` as a composable presentation over the public
  client. It owns bounded grant/revocation projection and exact confirmation
  state, but no terminal lifecycle, argument parsing, daemon startup, credential
  acquisition, global shortcuts, or process exit.
- [Qualified for the selected local profile] Provide a separate Aegis
  CLI/application composition root for interactive TUI
  administration, bounded inspect/revoke operations, and exact-confirmed
  same-connection authority journeys. A one-shot command must never export a
  session-local grant handle; reusable issue/attenuate management requires a
  separately specified long-lived session owner. Headless operation must not
  synthesize UI authority.
- [Qualified] Keep authority command guards under Aegis ownership. The TUI and
  Workbench may invoke `aegis-admin-command`, but presentation packages must not
  own or redefine confirmation, stale-state, or uncertainty semantics.
- [Qualified owner contract] `ManagedSessionV1` retains a bounded map from
  caller-chosen 128-bit operation names to private session-local grant handles,
  checks exact epoch and confirmation before issue/attenuation, returns only
  redacted grant/decision facts, and terminally fences after uncertain delivery
  or an impossible reply. A real public-service journey covers named parent,
  child and authorization use without handle export.
- [Qualified application contract] `aegis-admin-session` provides one bounded,
  closed NDJSON protocol over that manager, with explicit command/line ceilings,
  no credential or handle fields, one response per input, and immediate terminal
  stop after uncertainty.
- [Qualified application paths] Standalone Aegis and Workbench shells call that
  same parser/manager over the public client. Two separate shell processes
  against the selected owner daemon prove disconnect abandonment, an empty fresh
  name set and deliberate rebuild under a new operation ID. Durable grant replay
  and lost-reply reconciliation remain nonclaims.
- [Qualified for the selected local profile] Let Workbench reuse the same TUI
  and supervise Aegis's sovereign service process under one executable. Aegis
  remains the sole authority decision owner; Workbench passes explicit owner
  inputs, attaches the public client, and records lifecycle receipts only.
- [Qualified for the selected observation/administration profile] Standalone
  interactive/headless and Workbench interactive/headless paths preserve the
  same current-epoch, non-amplification, refusal, recovery, and lost-reply laws.
  The bounded issue → attenuation → authorization journey is qualified. The
  reusable manager, shared application contract, standalone and Workbench
  shells, and live reconnect/rebuild path are qualified.

Status: the standalone `aegis-daemon` now owns create/open recovery, exact
kernel-peer mapping, explicit principal/session/role facts, continuous serving
and signal drain. Workbench supervises that same owner process in interactive
and headless modes, attaches through the ordinary public client, records a
shutdown receipt and proves subsequent durable reopen. Workbench links no Aegis
engine, service, storage or authentication implementation.

