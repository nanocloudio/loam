#!/usr/bin/env bash
# Metadata-plane load gate.
#
# Offers a bounded number of records into the replicated metadata plane
# and checks the one property that has to hold at any offered rate:
#
#   emitted == committed + aborted
#
# Every record the plane accepts off the channel is either resolved or
# refused. A shortfall means records were accepted and then dropped,
# which is invisible to a producer — it sees neither a result nor a
# refusal, so it waits out its own timeout and reports nothing wrong.
# That is the failure this gate exists to catch.
#
# The gate deliberately does NOT assert a rate. Offered load above what
# the plane sustains is expected to show up as refusals, and refusing is
# correct behaviour; what is never correct is losing the record. Rates
# are reported for the record, not gated on, so this stays meaningful on
# any machine.
#
# Usage: tools/e2e/metadata_load.sh [total] [inject_period] [batch]
set -euo pipefail
cd "$(dirname "$0")/../.."

TOTAL="${1:-2000}"
INJECT_PERIOD="${2:-4}"
BATCH="${3:-4}"
# Generous, because the gate breaks out the moment the run settles —
# a longer ceiling costs nothing on an idle machine and stops a busy
# one (four e2e scripts in the same CI phase) from reading as a
# failure of the plane rather than of the budget.
RUN_SECONDS="${RUN_SECONDS:-150}"

GRAPH="examples/linux/clustor_load.yaml"
RENDERED="target/loam_metadata_load.yaml"
PROPOSER_WAL="target/loam-metadata-load-proposer.wal"
LOG="target/loam_metadata_load.log"

mkdir -p target

# A run must start from an empty substrate. The replica's log is
# relative to the working directory, so a previous run's entries would
# otherwise replay at boot and the numbers would describe two runs.
rm -rf wal "$PROPOSER_WAL" "$LOG"

sed -e "s|total: 0 .*|total: $TOTAL|" \
    -e "s|inject_period: .*|inject_period: $INJECT_PERIOD|" \
    -e "s|batch_per_step: .*|batch_per_step: $BATCH|" \
    -e "s|wal_path: .*|wal_path: \"$PROPOSER_WAL\"|" \
    "$GRAPH" > "$RENDERED"

echo "[load] offering $TOTAL records (batch $BATCH every $INJECT_PERIOD ticks)"

hex() { printf '%d' "0x${1:-0}"; }
# No match is a normal state, not an error: the poll loop runs before
# the graph has logged anything. Under `set -e` + `pipefail` an
# unguarded grep here aborts the script at the first poll, killing the
# gate before it can reach the branch that reports why — which is how a
# config error reads as a gate that printed one line and stopped.
last_lg() { grep -o '\[loam-lg\][^"]*' "$LOG" 2>/dev/null | tail -1 || true; }
last_tp() { grep -o '\[loam-tp\][^"]*' "$LOG" 2>/dev/null | tail -1 || true; }

timeout "$RUN_SECONDS" fluxor run "$RENDERED" > "$LOG" 2>&1 &
runner=$!
# `fluxor run` spawns `fluxor-linux` as a child whose argv is the
# compiled config, not the YAML. Killing only the wrapper leaves that
# child running: it keeps stepping a graph, competing for the machine
# with whatever runs next, and the symptom lands on the innocent test.
reap() {
  kill "$runner" 2>/dev/null || true
  wait "$runner" 2>/dev/null || true
  pkill -f "loam_metadata_load" 2>/dev/null || true
  sleep 1
  pkill -9 -f "loam_metadata_load" 2>/dev/null || true
}
trap reap EXIT

# Stop as soon as the run has settled: everything offered has been
# emitted, and everything emitted has resolved one way or the other.
# Waiting out the full timeout after that only makes the gate slow.
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

# Last report from each module carries the since-boot totals.
lg=$(last_lg)
tp=$(last_tp)

if [ -z "$lg" ] || [ -z "$tp" ]; then
  echo "[load] FAILED: the graph produced no reports — see $LOG" >&2
  tail -20 "$LOG" >&2
  exit 1
fi

emitted=$(hex "$(sed -n 's/.*E=\([0-9a-f]*\).*/\1/p' <<<"$lg")")
refused=$(hex "$(sed -n 's/.*R=\([0-9a-f]*\).*/\1/p' <<<"$lg")")
committed=$(hex "$(sed -n 's/.*C=\([0-9a-f]*\).*/\1/p' <<<"$tp")")
aborted=$(hex "$(sed -n 's/.*A=\([0-9a-f]*\).*/\1/p' <<<"$tp")")

resolved=$((committed + aborted))
echo "[load] offered=$TOTAL emitted=$emitted refused=$refused"
echo "[load] committed=$committed aborted=$aborted resolved=$resolved"

fail=0
if [ "$emitted" -eq 0 ]; then
  echo "[load] FAILED: nothing was emitted in ${RUN_SECONDS}s; the plane never opened" >&2
  fail=1
fi
if [ "$committed" -eq 0 ]; then
  echo "[load] FAILED: nothing committed; the plane refused everything" >&2
  fail=1
fi
if [ "$resolved" -ne "$emitted" ]; then
  echo "[load] FAILED: $((emitted - resolved)) record(s) accepted and then lost" >&2
  echo "[load]   emitted=$emitted but committed+aborted=$resolved" >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "[load] see $LOG" >&2
  exit 1
fi

echo "[load] OK — every emitted record resolved"
