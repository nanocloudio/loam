#!/usr/bin/env bash
# Composed-node gate: a public surface sitting on the replicated plane.
#
# Load enters as bind requests at the namespace surface, which proposes
# each one through the metadata plane rather than applying it; the
# commit comes back and only then does the surface answer its caller.
# Both halves are covered on their own — the surface by host tests, the
# plane by the load gate — and neither covers the join.
#
# Two properties are gated, and they are different claims:
#
#   plane:   proposed == committed + aborted
#   surface: emitted  == acknowledged + refused
#
# The first is the same conservation the load gate makes: a record the
# plane accepts is resolved or refused, never dropped. The second is
# the one only a composition can make — every request that entered the
# surface received exactly one answer. A surface that proposes and then
# loses track of what it proposed satisfies the first and fails the
# second, and its caller waits forever on a reply that will not come.
#
# Offered load beyond the surface's binding capacity (256 slots in a
# module build) is expected to come back as refusals: the plane commits
# the proposal, the arena has no room for it, and the surface says so.
# That is the behaviour to want under overload, and conservation is
# what makes it trustworthy — refusing is only correct if the caller is
# told. Run it above capacity deliberately to exercise that path; the
# default stays under it so the gate also proves binds land.
#
# This gate also stands in for something no host test can reach. The
# fault that held P1.1 up was a module that passed every host test and
# faulted on the first record once loaded as a module — position-
# dependent code the linker resolved to a fixed address. Only a real
# graph runs a module the way a module is run.
#
# Usage: tools/e2e/composed_node.sh [total] [inject_period] [batch]
set -euo pipefail
cd "$(dirname "$0")/../.."

TOTAL="${1:-200}"
INJECT_PERIOD="${2:-8}"
BATCH="${3:-1}"
RUN_SECONDS="${RUN_SECONDS:-120}"

GRAPH="examples/linux/composed_node.yaml"
RENDERED="target/loam_composed_node.yaml"
PROPOSER_WAL="target/loam-composed-node-proposer.wal"
LOG="target/loam_composed_node.log"

mkdir -p target

# A run must start from an empty substrate. Replayed entries would
# re-apply every binding, and the fresh requests would then come back
# as duplicates — a graph in perfect health reporting total refusal.
rm -rf wal "$PROPOSER_WAL" "$LOG"

sed -e "s|      total: .*|      total: $TOTAL|" \
    -e "s|      inject_period: .*|      inject_period: $INJECT_PERIOD|" \
    -e "s|      batch_per_step: .*|      batch_per_step: $BATCH|" \
    -e "s|wal_path: .*|wal_path: \"$PROPOSER_WAL\"|" \
    "$GRAPH" > "$RENDERED"

echo "[composed] offering $TOTAL bind requests at the namespace surface"
echo "[composed] (batch $BATCH every $INJECT_PERIOD ticks)"

hex() { printf '%d' "0x${1:-0}"; }
# No match is a normal state, not an error: the poll loop runs before
# the graph has logged anything. Under `set -e` + `pipefail` an
# unguarded grep here aborts the script at the first poll, killing the
# gate before it can reach the branch that reports why — which is how a
# config error reads as a gate that printed one line and stopped.
last_lg() { grep -o '\[loam-lg\][^"]*' "$LOG" 2>/dev/null | tail -1 || true; }
last_tp() { grep -o '\[loam-tp\][^"]*' "$LOG" 2>/dev/null | tail -1 || true; }
last_mp() { grep -o '\[loam-mp\][^"]*' "$LOG" 2>/dev/null | tail -1 || true; }

timeout "$RUN_SECONDS" fluxor run "$RENDERED" > "$LOG" 2>&1 &
runner=$!
# `fluxor run` spawns `fluxor-linux` as a child whose argv is the
# compiled config, not the YAML. Killing only the wrapper leaves that
# child stepping a graph and competing with whatever runs next.
reap() {
  kill "$runner" 2>/dev/null || true
  wait "$runner" 2>/dev/null || true
  pkill -f "loam_composed_node" 2>/dev/null || true
  sleep 1
  pkill -9 -f "loam_composed_node" 2>/dev/null || true
}
trap reap EXIT

deadline=$((SECONDS + RUN_SECONDS))
while [ "$SECONDS" -lt "$deadline" ]; do
  sleep 2
  lg=$(last_lg); tp=$(last_tp)
  [ -n "$lg" ] && [ -n "$tp" ] || continue
  e=$(hex "$(sed -n 's/.*E=\([0-9a-f]*\).*/\1/p' <<<"$lg")")
  c=$(hex "$(sed -n 's/.*C=\([0-9a-f]*\).*/\1/p' <<<"$tp")")
  a=$(hex "$(sed -n 's/.*A=\([0-9a-f]*\).*/\1/p' <<<"$tp")")
  if [ "$e" -ge "$TOTAL" ] && [ $((c + a)) -ge "$e" ]; then
    break
  fi
  kill -0 "$runner" 2>/dev/null || break
done
reap
trap - EXIT

if grep -q "SIGSEGV" "$LOG"; then
  echo "[composed] FAILED: the runtime faulted — see $LOG" >&2
  grep -n "SIGSEGV" "$LOG" | tail -3 >&2
  exit 1
fi

lg=$(last_lg); tp=$(last_tp); mp=$(last_mp)
if [ -z "$lg" ] || [ -z "$tp" ] || [ -z "$mp" ]; then
  echo "[composed] FAILED: the graph produced no reports — see $LOG" >&2
  tail -20 "$LOG" >&2
  exit 1
fi

emitted=$(hex "$(sed -n 's/.*E=\([0-9a-f]*\).*/\1/p' <<<"$lg")")
acked=$(hex "$(sed -n 's/.*C=\([0-9a-f]*\).*/\1/p' <<<"$tp")")
refused=$(hex "$(sed -n 's/.*A=\([0-9a-f]*\).*/\1/p' <<<"$tp")")
proposed=$(hex "$(sed -n 's/.* p=\([0-9a-f]*\).*/\1/p' <<<"$mp")")
committed=$(hex "$(sed -n 's/.* c=\([0-9a-f]*\).*/\1/p' <<<"$mp")")
aborted=$(hex "$(sed -n 's/.* a=\([0-9a-f]*\).*/\1/p' <<<"$mp")")

echo "[composed] surface: emitted=$emitted acknowledged=$acked refused=$refused"
echo "[composed] plane:   proposed=$proposed committed=$committed aborted=$aborted"

fail=0
if [ "$emitted" -eq 0 ]; then
  echo "[composed] FAILED: nothing was emitted in ${RUN_SECONDS}s" >&2
  fail=1
fi
if [ "$proposed" -eq 0 ]; then
  echo "[composed] FAILED: the surface acknowledged without proposing — it" >&2
  echo "[composed]   applied locally, which is the bug this graph exists to catch" >&2
  fail=1
fi
if [ "$committed" -eq 0 ]; then
  echo "[composed] FAILED: nothing committed; the plane refused everything" >&2
  fail=1
fi
if [ "$acked" -eq 0 ]; then
  # Conservation alone would be satisfied by a surface that refuses
  # every request, so it cannot be the only claim: a graph that binds
  # nothing at all is not a working graph.
  echo "[composed] FAILED: the surface bound nothing — every request refused" >&2
  fail=1
fi
if [ $((acked + refused)) -ne "$emitted" ]; then
  echo "[composed] FAILED: $((emitted - acked - refused)) request(s) entered the" >&2
  echo "[composed]   surface and were never answered" >&2
  fail=1
fi
if [ $((committed + aborted)) -ne "$proposed" ]; then
  echo "[composed] FAILED: $((proposed - committed - aborted)) proposal(s) lost" >&2
  echo "[composed]   in the plane" >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "[composed] see $LOG" >&2
  exit 1
fi

echo "[composed] OK — every request answered, every proposal resolved"
