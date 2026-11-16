#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

for required in CHANGELOG.md CONTRIBUTING.md LICENSE-APACHE LICENSE-MIT README.md ROADMAP.production.md SECURITY.md requirements.md specification.md rust-toolchain.toml release/github-source.json docs/advisory-attestation.md docs/authority-lifecycle.md docs/compatibility.md docs/compatibility-baseline.txt docs/license-baseline.txt docs/local-daemon.md docs/performance.md docs/release-policy.md docs/release-readiness.md docs/soak.md docs/supply-chain.md docs/supply-chain-baseline.txt docs/threat-model.md docs/traceability.md docs/unix-peer-credentials.md; do
  [[ -s "$required" ]] || { echo "missing Aegis release-contract file: $required" >&2; exit 1; }
done
rg -q '^channel = "1\.95\.0"$' rust-toolchain.toml || { echo 'Aegis toolchain is not pinned' >&2; exit 1; }
while IFS= read -r manifest; do
  awk '/^\[package\]$/ {p=1; next} /^\[/ {p=0} p && /^publish = false$/ {ok=1} END {exit(ok ? 0 : 1)}' "$manifest" || { echo "$manifest permits publication" >&2; exit 1; }
done < <(find . -name Cargo.toml -type f -not -path './target/*' -not -path './.git/*' -print)
rg -q 'no registry or binary' docs/release-policy.md || { echo 'Aegis distribution refusal missing' >&2; exit 1; }
rg -q 'not ready for a' docs/release-readiness.md || { echo 'Aegis readiness refusal missing' >&2; exit 1; }
rg -q '"channel": "github-coordinated-source"' release/github-source.json || { echo 'Aegis GitHub source channel missing' >&2; exit 1; }
rg -q '"revision": "2e4faf10ec0a70805aa1db1555f93c77fcf0a1e4"' release/github-source.json || { echo 'Aegis Keystone source revision drifted' >&2; exit 1; }
rg -q '"remoteReachabilityQualified": false' release/github-source.json || { echo 'Aegis source profile claims unverified reachability' >&2; exit 1; }
rg -q '^performance:' Makefile || { echo 'Aegis performance gate missing' >&2; exit 1; }
rg -q '^soak-process:' Makefile || { echo 'Aegis process soak gate missing' >&2; exit 1; }
echo 'Aegis release contract denies registry and binary publication and pins the source profile'

