#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

baseline=${AEGIS_SUPPLY_BASELINE:-docs/supply-chain-baseline.txt}
licenses=${AEGIS_LICENSE_BASELINE:-docs/license-baseline.txt}
label=Aegis

[[ -s "$baseline" ]] || { echo 'Aegis supply-chain baseline is missing' >&2; exit 1; }
[[ -s "$licenses" ]] || { echo 'Aegis license baseline is missing' >&2; exit 1; }
actual=$(mktemp "${TMPDIR:-/tmp}/aegis-supply.XXXXXX")
expected=$(mktemp "${TMPDIR:-/tmp}/aegis-supply-expected.XXXXXX")
trap 'rm -f "$actual" "$expected"' EXIT

awk -F '|' '$1 == "component" { print }' "$baseline" | LC_ALL=C sort > "$expected"
[[ -s "$expected" ]] || { echo 'Aegis supply inventory is empty' >&2; exit 1; }
awk '
  /^\[\[package\]\]$/ { if (name != "") print "component|" name "|" version; name=""; version=""; next }
  /^name = / { value=$0; sub(/^name = "/,"",value); sub(/"$/,"",value); name=value }
  /^version = / { value=$0; sub(/^version = "/,"",value); sub(/"$/,"",value); version=value }
  END { if (name != "") print "component|" name "|" version }
' Cargo.lock | LC_ALL=C sort > "$actual"
diff -u "$expected" "$actual" || { echo 'Aegis locked component inventory drifted' >&2; exit 1; }
rg -q '^source = "git\+' Cargo.lock && { echo 'Aegis lock contains a Git source' >&2; exit 1; }
awk '
  /^\[\[package\]\]$/ { if (registry && !checksum) exit 1; registry=0; checksum=0; next }
  /^source = "registry\+/ { registry=1 }
  /^checksum = "/ { checksum=1 }
  END { if (registry && !checksum) exit 1 }
' Cargo.lock || { echo 'Aegis registry component lacks a checksum' >&2; exit 1; }
cargo metadata --locked --offline --format-version 1 | node ../keystone/scripts/check-cargo-license-baseline.mjs "$licenses"
echo "$label supply profile closes over $(wc -l < "$expected" | tr -d ' ') locked components"
