#!/usr/bin/env bash
# 3-node replicated loam metadata bring-up.
#
# Renders examples/linux/clustor_multi3.yaml per node and spawns three
# `fluxor run` processes — one full loam + replica graph each — then
# watches for the acceptance shape:
#
#   - exactly ONE node logs "[meta_e2e] PASS": correlation ids are
#     node-scoped (self_id in the high byte), so only the LEADER's
#     proposer can match the committed bind it proposed. The two
#     followers log "[meta_e2e] FAIL timeout" — their proposals
#     queue at their local (non-draining) raft proposals port;
#     follower→leader forwarding is the tracked follow-up.
#   - the three per-node WAL segments are BYTE-IDENTICAL: the
#     replicated log converged on every replica
#
# Usage: tools/e2e/multi3_bringup.sh [--keep]
#   --keep   leave the run dir + processes' logs in place
set -u

LOAM_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FLUXOR_CHECKOUT="${FLUXOR_CHECKOUT:-$LOAM_ROOT/../fluxor}"
RUN_DIR="$(mktemp -d /tmp/loam-multi3.XXXXXX)"
BASE_PORT=9290
HTTP_BASE=19290
WAIT_SECS=45

echo "[bringup] run dir: $RUN_DIR"

# ── 0. Pre-flight: no stale nodes from a previous run ─────────────
pkill -9 -f "loam-multi3-n[0-9].yaml" 2>/dev/null
pkill -9 -f "target/linux/loam-multi3-n" 2>/dev/null
sleep 1
if ss -tln 2>/dev/null | grep -qE ":(929[0-2]|1929[0-2]) "; then
  echo "[bringup] FATAL: ports 9290-9292/19290-19292 still bound (stale processes?)"
  ss -tlnp 2>/dev/null | grep -E ":(929[0-2]|1929[0-2]) "
  exit 1
fi

# ── 1. Check the modules are staged ───────────────────────────────
# `fluxor sync` stages every dependency's published modules alongside
# this project's own build output, so there is nothing to copy out of a
# sibling checkout. A missing module here means the tree is unsynced or
# unbuilt, which is worth saying plainly rather than discovering as a
# resolution failure three steps later.
STAGED="$LOAM_ROOT/target/fluxor/bcm2712/modules"
for m in consensus durability gateway peer_router \
         raft_metadata_client clustor_bridge metadata_e2e_probe; do
  if [ ! -f "$STAGED/$m.fmod" ]; then
    echo "[bringup] FATAL: $m.fmod not staged in $STAGED"
    echo "[bringup]   run: fluxor sync && fluxor modules build --target bcm2712"
    exit 1
  fi
done

# ── 2. Runtime prerequisites ──────────────────────────────────────
# clustor's wal writes wal/seg_* relative to the fluxor cwd, so
# every node needs its OWN working directory — three replicas
# sharing one segment file is silent data corruption. Each node dir
# symlinks the project structure fluxor needs and owns a real wal/.
for i in 0 1 2; do
  nd="$RUN_DIR/node$i"
  mkdir -p "$nd/wal"
  ln -s "$LOAM_ROOT/fluxor.toml" "$nd/fluxor.toml"
  ln -s "$LOAM_ROOT/fluxor.lock" "$nd/fluxor.lock"
  ln -s "$LOAM_ROOT/modules" "$nd/modules"
  ln -s "$LOAM_ROOT/target" "$nd/target"
  ln -s "$LOAM_ROOT/examples" "$nd/examples"
  : > "/tmp/loam-multi3-n$i-proposer.wal"
done

# ── 3. Render per-node configs ────────────────────────────────────
for i in 0 1 2; do
  fluxor render-template "$LOAM_ROOT/examples/linux/clustor_multi3.yaml" \
    --var SELF_ID="$i" \
    --var LISTEN_PORT=$((BASE_PORT + i)) \
    --var PEER0_PORT=$BASE_PORT \
    --var PEER1_PORT=$((BASE_PORT + 1)) \
    --var PEER2_PORT=$((BASE_PORT + 2)) \
    --var HTTP_PORT=$((HTTP_BASE + i)) \
    --var PROPOSER_WAL="/tmp/loam-multi3-n$i-proposer.wal" \
    > "$RUN_DIR/loam-multi3-n$i.yaml" || exit 1
done

# ── 4. Spawn the three nodes ──────────────────────────────────────
PIDS=()
for i in 0 1 2; do
  ( cd "$RUN_DIR/node$i" && \
    FLUXOR_INSTALL_ROOT="$FLUXOR_CHECKOUT" \
    setsid fluxor run "$RUN_DIR/loam-multi3-n$i.yaml" \
      > "$RUN_DIR/n$i.stdout" 2> "$RUN_DIR/n$i.stderr" ) &
  PIDS+=($!)
  echo "[bringup] node $i spawned (logs: $RUN_DIR/n$i.*)"
done

cleanup() {
  for pid in "${PIDS[@]}"; do
    kill -TERM "-$pid" 2>/dev/null
    kill -TERM "$pid" 2>/dev/null
  done
  # The setsid'd `fluxor run` gets its own session (group kill by
  # subshell pid misses it), and its fluxor-linux grandchild's argv
  # is the config.bin path, not the yaml — match BOTH patterns or
  # a leaked node squats on a peer port and wrecks the next run.
  pkill -TERM -f "loam-multi3-n[0-9].yaml" 2>/dev/null
  pkill -TERM -f "target/linux/loam-multi3-n" 2>/dev/null
  sleep 1
  pkill -9 -f "loam-multi3-n[0-9].yaml" 2>/dev/null
  pkill -9 -f "target/linux/loam-multi3-n" 2>/dev/null
}
trap cleanup EXIT

# ── 5. Watch for the acceptance shape ─────────────────────────────
deadline=$((SECONDS + WAIT_SECS))
pass_nodes=""
while [ $SECONDS -lt $deadline ]; do
  pass_nodes=""
  for i in 0 1 2; do
    if grep -q "meta_e2e] PASS" "$RUN_DIR/n$i.stdout" "$RUN_DIR/n$i.stderr" 2>/dev/null; then
      pass_nodes="$pass_nodes $i"
    fi
  done
  if [ -n "$pass_nodes" ]; then
    break
  fi
  sleep 1
done

# Let all three probes reach their verdicts.
sleep 4

echo "[bringup] ── results ──────────────────────────────────────"
pass_count=0
for i in 0 1 2; do
  status="silent"
  if grep -q "meta_e2e] PASS" "$RUN_DIR/n$i.stdout" "$RUN_DIR/n$i.stderr" 2>/dev/null; then
    status="PASS"
    pass_count=$((pass_count + 1))
  elif grep -q "meta_e2e] FAIL" "$RUN_DIR/n$i.stdout" "$RUN_DIR/n$i.stderr" 2>/dev/null; then
    status="$(grep -oh 'meta_e2e] FAIL [a-z]*' "$RUN_DIR/n$i.stdout" "$RUN_DIR/n$i.stderr" 2>/dev/null | head -1)"
  fi
  echo "[bringup] node $i: $status"
done

# Replication proof: every node's WAL segment must be non-empty and
# byte-identical to node 0's.
wal_ok=1
w0="$RUN_DIR/node0/wal/p0000_seg_00000001"
if [ ! -s "$w0" ]; then
  wal_ok=0
fi
for i in 1 2; do
  if ! cmp -s "$w0" "$RUN_DIR/node$i/wal/p0000_seg_00000001"; then
    wal_ok=0
  fi
done
if [ "$wal_ok" -eq 1 ]; then
  echo "[bringup] WAL parity: 3/3 replicas byte-identical ($(stat -c%s "$w0") bytes)"
else
  echo "[bringup] WAL parity: MISMATCH"
fi

if [ "$pass_count" -eq 1 ] && [ "$wal_ok" -eq 1 ]; then
  echo "[bringup] SUCCESS: the leader committed the loam bind through a real 3-node quorum; replicated log byte-identical on every node"
  rc=0
else
  echo "[bringup] FAILED: expected exactly 1 PASS (leader-attributed commit) + WAL parity (got pass=$pass_count wal_ok=$wal_ok)"
  echo "[bringup] logs kept at $RUN_DIR"
  trap - EXIT
  cleanup
  exit 1
fi

if [ "${1:-}" = "--keep" ]; then
  echo "[bringup] --keep: logs at $RUN_DIR"
  trap - EXIT
  cleanup
else
  rm -rf "$RUN_DIR"
fi
exit $rc
