#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
task_dir=$(mktemp -d "${TMPDIR:-/tmp}/aegis-assurance-mutants.XXXXXX")
trap 'rm -f "$task_dir"/*; rmdir "$task_dir"' EXIT

awk '!/^package\|Cargo.toml\|/' docs/compatibility-baseline.txt > "$task_dir/compatibility.txt"
if AEGIS_COMPATIBILITY_BASELINE="$task_dir/compatibility.txt" bash scripts/check-compatibility-baseline.sh >"$task_dir/output" 2>&1; then
  echo 'Aegis compatibility gate accepted a missing-package mutant' >&2; exit 1
fi
sed 's/032bf307/132bf307/' docs/compatibility-baseline.txt > "$task_dir/compatibility.txt"
if AEGIS_COMPATIBILITY_BASELINE="$task_dir/compatibility.txt" bash scripts/check-compatibility-baseline.sh >"$task_dir/output" 2>&1; then
  echo 'Aegis compatibility gate accepted a fixture-digest mutant' >&2; exit 1
fi
sed 's/component|aegis-authority|0.0.1/component|aegis-authority|0.0.2/' docs/supply-chain-baseline.txt > "$task_dir/supply.txt"
if AEGIS_SUPPLY_BASELINE="$task_dir/supply.txt" bash scripts/check-supply-chain.sh >"$task_dir/output" 2>&1; then
  echo 'Aegis supply gate accepted a version-drift mutant' >&2; exit 1
fi
sed 's/license|aegis-authority|0.0.1|MIT OR Apache-2.0/license|aegis-authority|0.0.1|MIT/' docs/license-baseline.txt > "$task_dir/licenses.txt"
if AEGIS_LICENSE_BASELINE="$task_dir/licenses.txt" bash scripts/check-supply-chain.sh >"$task_dir/output" 2>&1; then
  echo 'Aegis supply gate accepted a license-expression mutant' >&2; exit 1
fi
sed 's/3582c677/4582c677/' docs/advisory-attestation.md > "$task_dir/advisory.md"
if AEGIS_ADVISORY_ATTESTATION="$task_dir/advisory.md" bash scripts/check-advisory-attestation.sh >"$task_dir/output" 2>&1; then
  echo 'Aegis advisory gate accepted a lockfile-digest mutant' >&2; exit 1
fi
echo 'Aegis assurance gates reject compatibility, supply, license and advisory mutants'
