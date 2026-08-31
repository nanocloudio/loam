#!/usr/bin/env bash
# Capacity-profile matrix.
#
# A profile that is not built and exercised is a claim, not a
# capability. Loam has four — `minimal`, `embedded`, `node`,
# `server` — differing in arena capacity, key ceilings and which
# optional tiers are compiled in at all. This runs the whole suite
# against each.
#
# What it catches, concretely: the first run of this matrix found a
# test that hard-coded a 234-byte path (fine at the host ceiling of
# 1024, refused at the embedded ceiling of 160) and another that
# drove 576 bindings through what became a 64-slot arena with no
# snapshot tier behind it. Both looked correct on the default
# profile and were wrong on a real device.
#
# `node` is the default when nothing is declared, so it is run
# without a flag — which also proves the fallback still resolves.
#
# Wired as `[ci.test] scripts` in fluxor.toml.
set -euo pipefail
cd "$(dirname "$0")/../.."

profiles=(minimal embedded server)
fail=0

echo "profile_matrix: node (default — no cfg, exercises the fallback)"
if ! cargo test --quiet >/tmp/loam_profile_node.log 2>&1; then
  echo "  FAILED — see /tmp/loam_profile_node.log"
  tail -30 /tmp/loam_profile_node.log | sed 's/^/    /'
  fail=1
else
  echo "  ok"
fi

for p in "${profiles[@]}"; do
  echo "profile_matrix: $p"
  if ! RUSTFLAGS="--cfg loam_profile=\"$p\"" \
       cargo test --quiet >"/tmp/loam_profile_$p.log" 2>&1; then
    echo "  FAILED — see /tmp/loam_profile_$p.log"
    tail -30 "/tmp/loam_profile_$p.log" | sed 's/^/    /'
    fail=1
  else
    echo "  ok"
  fi
done

if ((fail)); then
  echo "profile_matrix: at least one profile does not hold"
  exit 1
fi
echo "profile_matrix: ok — all four profiles pass the suite"
