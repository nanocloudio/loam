#!/usr/bin/env bash
# Capacity-profile matrix.
#
# A profile that is not built and exercised is a claim, not a
# capability. Loam has four — `minimal`, `embedded`, `node`,
# `server` — differing in arena capacity, key ceilings, session and
# member ceilings, and which optional tiers are compiled in at all.
# A module picks one with its manifest `[[variant]]`; the harness
# compiles the same sources under the same feature, so this runs the
# whole harness against each.
#
# What it catches, concretely: a test that hard-coded a 234-byte path
# (fine at the host ceiling of 1024, refused at the embedded ceiling of
# 160), another that drove 576 bindings through a 64-slot arena with
# no snapshot tier behind it, and a snapshot merge that wrote keys out
# of order once the arena was small enough to evict mid-merge. Each
# looked correct on the default profile and was wrong on a real device.
#
# `fluxor ci` runs the harness on its default feature (`node`); this
# covers the other three. Wired as `[ci.test] scripts` in fluxor.toml.
set -euo pipefail
cd "$(dirname "$0")/../../tests/harness"

log_dir="$(mktemp -d "${TMPDIR:-/tmp}/loam-profile-matrix-XXXXXX")"
fail=0

for p in minimal embedded server; do
  echo "profile_matrix: $p"
  if ! cargo test --quiet --no-default-features --features "$p" >"$log_dir/$p.log" 2>&1; then
    echo "  FAILED — see $log_dir/$p.log"
    tail -30 "$log_dir/$p.log" | sed 's/^/    /'
    fail=1
  else
    echo "  ok"
  fi
done

if ((fail)); then
  echo "profile_matrix: at least one profile does not hold"
  exit 1
fi
rm -rf "$log_dir"
echo "profile_matrix: ok — minimal, embedded and server pass the harness (node runs in fluxor ci)"
