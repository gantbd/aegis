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
- Add Agora, Chronos, and Vellum resource adapters.
- Keep credential verification and secret storage outside Aegis.

## Phase 4 — reusable administration surface and standalone CLI

- Define `aegis-tui` as a composable presentation over the public client. It
  owns bounded grant/revocation projection and exact confirmation state, but no
  terminal lifecycle, argument parsing, daemon startup, credential acquisition,
  global shortcuts, or process exit.
- Provide a separate Aegis CLI/application composition root for interactive TUI
  administration, bounded inspect/revoke operations, and exact-confirmed
  same-connection authority journeys. A one-shot command must never export a
  session-local grant handle; reusable issue/attenuate management requires a
  separately specified long-lived session owner. Headless operation must not
  synthesize UI authority.
- Let Workbench reuse the same TUI and optionally host Aegis's service runtime
  under one executable. Aegis remains the sole authority decision owner; the
  host supplies authenticated facts and routes typed requests only.
- Qualify standalone interactive/headless and Workbench interactive/headless
  paths with the same current-epoch, non-amplification, refusal, recovery, and
  lost-reply laws. The bounded issue → attenuation → authorization journey is
  qualified; long-lived reusable grant management remains open.

Status: the standalone `aegis-daemon` now owns create/open recovery, exact
kernel-peer mapping, explicit principal/session/role facts, continuous serving
and signal drain. Workbench supervises that same owner process in interactive
and headless modes, attaches through the ordinary public client, records a
shutdown receipt and proves subsequent durable reopen. Workbench links no Aegis
engine, service, storage or authentication implementation.

