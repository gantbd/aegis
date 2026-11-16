#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

tree=$(cargo tree -p aegis-sdk-embedded --edges normal --depth 1 --locked --offline)
if [[ $(printf '%s\n' "$tree" | wc -l | tr -d ' ') != 3 ]] \
  || ! printf '%s\n' "$tree" | rg -q 'aegis-authority' \
  || ! printf '%s\n' "$tree" | rg -q 'aegis-host' \
  || printf '%s\n' "$tree" | rg -q 'aegis-local'; then
  printf '%s\n' "$tree" >&2
  echo 'Aegis embedded SDK escaped its engine-and-host closure' >&2
  exit 1
fi

echo 'Aegis embedded SDK dependency closure verified'

conformance=$(cargo tree -p aegis-conformance --edges normal --depth 1 --locked --offline)
if [[ $(printf '%s\n' "$conformance" | wc -l | tr -d ' ') != 2 ]] \
  || ! printf '%s\n' "$conformance" | rg -q 'aegis-protocol' \
  || printf '%s\n' "$conformance" | rg -q 'aegis-(authority|host|service|wire|local)'; then
  printf '%s\n' "$conformance" >&2
  echo 'Aegis conformance suite escaped its public-protocol closure' >&2
  exit 1
fi

echo 'Aegis conformance suite public-protocol dependency closure verified'

admin_command=$(cargo tree -p aegis-admin-command --edges normal --depth 1 --locked --offline)
if [[ $(printf '%s\n' "$admin_command" | wc -l | tr -d ' ') != 3 ]] \
  || ! printf '%s\n' "$admin_command" | rg -q 'aegis-client' \
  || ! printf '%s\n' "$admin_command" | rg -q 'aegis-protocol' \
  || printf '%s\n' "$admin_command" | rg -q 'aegis-(authority|host|service|wire|local)|keystone|ratatui|crossterm'; then
  printf '%s\n' "$admin_command" >&2
  echo 'Aegis command guard escaped its public-client closure' >&2
  exit 1
fi

echo 'Aegis command guard public-client closure verified'

witness=$(cargo tree -p aegis-witness --edges normal --depth 1 --locked --offline)
if [[ $(printf '%s\n' "$witness" | wc -l | tr -d ' ') != 2 ]] \
  || ! printf '%s\n' "$witness" | rg -q 'keystone-storage' \
  || printf '%s\n' "$witness" | rg -q 'aegis-(authority|host|service|wire|local)'; then
  printf '%s\n' "$witness" >&2
  echo 'Aegis rollback witness adapter escaped its mechanism-only boundary' >&2
  exit 1
fi

echo 'Aegis rollback witness mechanism-only dependency closure verified'

metadata=$(cargo metadata --no-deps --format-version 1 --locked --offline)
admin_session_dependencies=$(printf '%s\n' "$metadata" | node -e '
  let input = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", chunk => input += chunk);
  process.stdin.on("end", () => {
    const pkg = JSON.parse(input).packages.find(candidate => candidate.name === "aegis-admin-session");
    if (!pkg) process.exit(2);
    process.stdout.write(pkg.dependencies
      .filter(dependency => dependency.kind === null)
      .map(dependency => dependency.name)
      .sort()
      .join(","));
  });
')
expected_admin_session_dependencies='aegis-admin-command,aegis-client,aegis-protocol,serde,serde_json'
[[ "$admin_session_dependencies" == "$expected_admin_session_dependencies" ]] || {
  echo "Aegis administration session production dependencies: $admin_session_dependencies" >&2
  exit 1
}
echo 'Aegis administration session public-client application boundary verified'

daemon_dependencies=$(printf '%s\n' "$metadata" | node -e '
  let input = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", chunk => input += chunk);
  process.stdin.on("end", () => {
    const pkg = JSON.parse(input).packages.find(candidate => candidate.name === "aegis-local-daemon");
    if (!pkg) process.exit(2);
    process.stdout.write(pkg.dependencies
      .filter(dependency => dependency.kind === null)
      .map(dependency => dependency.name)
      .sort()
      .join(","));
  });
')
expected_daemon_dependencies='aegis-client,aegis-host,aegis-protocol,aegis-service,aegis-wire,keystone-framing,keystone-storage,keystone-unix-listener'
[[ "$daemon_dependencies" == "$expected_daemon_dependencies" ]] || {
  echo "Aegis local daemon production dependencies: $daemon_dependencies" >&2
  exit 1
}
echo 'Aegis local daemon public-client composition boundary verified'

peer=$(cargo tree -p aegis-unix-peer --edges normal --depth 1 --locked --offline)
if [[ $(printf '%s\n' "$peer" | wc -l | tr -d ' ') != 5 ]] \
  || ! printf '%s\n' "$peer" | rg -q 'aegis-authority' \
  || ! printf '%s\n' "$peer" | rg -q 'aegis-local-daemon' \
  || ! printf '%s\n' "$peer" | rg -q 'aegis-service' \
  || ! printf '%s\n' "$peer" | rg -q 'nix' \
  || printf '%s\n' "$peer" | rg -q 'aegis-(host|protocol|wire|client)|keystone'; then
  printf '%s\n' "$peer" >&2
  echo 'Aegis Unix peer authenticator escaped its credential-mapping closure' >&2
  exit 1
fi
echo 'Aegis Unix peer authenticator dependency closure verified'
