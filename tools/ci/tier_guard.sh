#!/usr/bin/env bash
# Storage tier-boundary guard (rfc_storage_capability_symmetry §6).
#
# Loam is two tiers named by FENCE CLASS, kept separable so a later
# repo extraction of the mechanics tier is a `git mv`, not a rewrite:
#
#   mechanics/  — providers whose fences are single-node classes.
#                 May depend on fluxor only.
#   replicated/ — providers whose fences claim quorum. May depend on
#                 clustor, and may consume the mechanics tier
#                 DOWNWARD (it is that tier's first consumer).
#
# Enforced invariants:
#   1. every modules/common file lives in exactly one tier directory;
#   2. a mechanics-tier module never mounts modules/common/replicated/**
#      (no upward reach — that is what would weld the tiers together);
#   3. nothing in the mechanics tier (modules or common) mentions
#      clustor.
#
# Wired as `[ci.test] scripts` in fluxor.toml.
set -euo pipefail
cd "$(dirname "$0")/../.."

# Tier rosters. A NEW module must be added to exactly one list — the
# guard fails on unlisted modules rather than guessing its tier.
MECHANICS="admin_router block_allocator block_log body_e2e_probe body_store \
cache_manager io_scheduler namespace_router object_index telemetry_agg"
# loam_load_gen and loam_throughput_counter drive and measure the
# REPLICATED metadata plane: they speak loam_decision_wire, so they sit
# with the tier whose vocabulary they carry.
REPLICATED="body_fanout_router clustor_bridge ec_body_router \
loam_load_gen loam_throughput_counter metadata_e2e_probe \
placement_router raft_metadata_client"

fail=0

# (1) No loose files at the common root.
loose=$(find modules/common -maxdepth 1 -name '*.rs' | sort)
if [ -n "$loose" ]; then
  echo "tier_guard: unassigned modules/common files (assign to mechanics/ or replicated/):" >&2
  echo "$loose" >&2
  fail=1
fi

# Every module on disk is in exactly one roster, and carries a manifest.
for d in modules/app/*/; do
  m=$(basename "$d")
  in_mech=$(echo " $MECHANICS " | grep -c " $m " || true)
  in_repl=$(echo " $REPLICATED " | grep -c " $m " || true)
  if [ $((in_mech + in_repl)) -ne 1 ]; then
    echo "tier_guard: module '$m' is in $((in_mech + in_repl)) tier rosters — must be exactly 1" >&2
    fail=1
  fi
  if [ ! -f "$d/manifest.toml" ]; then
    echo "tier_guard: module '$m' has no manifest.toml" >&2
    fail=1
  fi
done

# ...and every rostered module is on disk. Checking only one direction
# lets a roster entry outlive the module it names, so the guard keeps
# reporting OK while silently covering nothing.
for m in $MECHANICS $REPLICATED; do
  if [ ! -d "modules/app/$m" ]; then
    echo "tier_guard: roster names '$m', which is not in modules/app/" >&2
    fail=1
  fi
done

# (2) The mechanics tier must not reach modules/common/replicated/**,
# from a module OR from a shared body. Scanning only modules/app leaves
# the shared bodies — where a cross-tier mount would do the most damage
# — unchecked.
for m in $MECHANICS; do
  if grep -rqE 'common/replicated/' "modules/app/$m/" 2>/dev/null; then
    echo "tier_guard: mechanics module '$m' mounts common/replicated/** (upward reach)" >&2
    grep -rnE 'common/replicated/' "modules/app/$m/" | head -3 >&2
    fail=1
  fi
done
if grep -rnE 'common/replicated/' modules/common/mechanics/ 2>/dev/null; then
  echo "tier_guard: modules/common/mechanics/ mounts common/replicated/** (upward reach, above)" >&2
  fail=1
fi

# (3) No clustor reach from the mechanics tier (modules or common).
mech_paths=""
for m in $MECHANICS; do mech_paths="$mech_paths modules/app/$m"; done
if grep -rniE '\bclustor\b' $mech_paths modules/common/mechanics/ 2>/dev/null | grep -v 'tier_guard'; then
  echo "tier_guard: clustor reference inside the mechanics tier (above)" >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "tier_guard: FAILED" >&2
  exit 1
fi
echo "tier_guard: OK ($(echo $MECHANICS | wc -w) mechanics, $(echo $REPLICATED | wc -w) replicated)"
