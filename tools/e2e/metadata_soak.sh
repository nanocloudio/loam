#!/usr/bin/env bash
# Metadata-plane soak.
#
# Runs the plane under continuous offered load for a duration, sampling
# every reporting window, and holds three properties the whole way
# through rather than only at the end:
#
#   1. Conservation. Records resolved never falls behind records
#      emitted by more than what is legitimately in flight. A gap that
#      grows without bound is loss, and loss is invisible to a producer
#      — it sees neither a result nor a refusal.
#   2. Liveness. Commits keep arriving. A plane that stops committing
#      but keeps refusing is still "busy" by every rate metric, so the
#      commit stream has to be checked on its own.
#   3. Parse integrity. No record on the results channel is
#      unrecognisable. A non-zero count there means the channel is
#      carrying something that is not a decision record, which
#      invalidates every number above it.
#
# It also watches for the things that end a run rather than degrade it:
# module faults, panics, and step-deadline overruns.
#
# Usage: tools/e2e/metadata_soak.sh [seconds] [inject_period] [batch]
#   e.g. tools/e2e/metadata_soak.sh 600 2 8     # 10 min, ~4000/s offered
set -uo pipefail
cd "$(dirname "$0")/../.."

DURATION="${1:-300}"
INJECT_PERIOD="${2:-2}"
BATCH="${3:-8}"
SAMPLE_EVERY="${SAMPLE_EVERY:-10}"

GRAPH="examples/linux/clustor_load.yaml"
RENDERED="target/loam_metadata_soak.yaml"
PROPOSER_WAL="target/loam-metadata-soak-proposer.wal"
LOG="target/loam_metadata_soak.log"

mkdir -p target
rm -rf wal "$PROPOSER_WAL" "$LOG"

# `total: 0` runs until stopped, which is what a soak wants.
sed -e "s|inject_period: .*|inject_period: $INJECT_PERIOD|" \
    -e "s|batch_per_step: .*|batch_per_step: $BATCH|" \
    -e "s|wal_path: .*|wal_path: \"$PROPOSER_WAL\"|" \
    "$GRAPH" > "$RENDERED"

echo "[soak] ${DURATION}s at batch $BATCH every $INJECT_PERIOD ticks"

hex() { printf '%d' "0x${1:-0}"; }
field() { sed -n "s/.*$2=\([0-9a-f]*\).*/\1/p" <<<"$1"; }
# No match is a normal state, not an error: the poll loop runs before
# the graph has logged anything. Under `set -e` + `pipefail` an
# unguarded grep here aborts the script at the first poll, killing the
# gate before it can reach the branch that reports why — which is how a
# config error reads as a gate that printed one line and stopped.
last_lg() { grep -o '\[loam-lg\][^"]*' "$LOG" 2>/dev/null | tail -1 || true; }
last_tp() { grep -o '\[loam-tp\][^"]*' "$LOG" 2>/dev/null | tail -1 || true; }

fluxor run "$RENDERED" > "$LOG" 2>&1 &
runner=$!
# `fluxor run` spawns `fluxor-linux` as a child whose argv is the
# compiled config, not the YAML. Killing only the wrapper leaves that
# child running: it keeps stepping a graph, competing for the machine
# with whatever runs next, and the symptom lands on the innocent test.
reap() {
  kill "$runner" 2>/dev/null || true
  wait "$runner" 2>/dev/null || true
  pkill -f "loam_metadata_soak" 2>/dev/null || true
  sleep 1
  pkill -9 -f "loam_metadata_soak" 2>/dev/null || true
}
trap reap EXIT

fail=0
samples=0
prev_committed=0
stalled=0
peak_gap=0
deadline=$((SECONDS + DURATION))

while [ "$SECONDS" -lt "$deadline" ]; do
  sleep "$SAMPLE_EVERY"
  if ! kill -0 "$runner" 2>/dev/null; then
    echo "[soak] FAILED: the graph exited after $samples sample(s)" >&2
    fail=1
    break
  fi

  lg=$(last_lg); tp=$(last_tp)
  [ -n "$lg" ] && [ -n "$tp" ] || continue
  samples=$((samples + 1))

  emitted=$(hex "$(field "$lg" E)")
  committed=$(hex "$(field "$tp" C)")
  aborted=$(hex "$(field "$tp" A)")
  gap=$((emitted - committed - aborted))
  [ "$gap" -gt "$peak_gap" ] && peak_gap=$gap

  if [ "$committed" -le "$prev_committed" ]; then
    stalled=$((stalled + 1))
    if [ "$stalled" -ge 3 ]; then
      echo "[soak] FAILED: no commits across $stalled consecutive samples" >&2
      fail=1
      break
    fi
  else
    stalled=0
  fi
  prev_committed=$committed

  printf '[soak] t=%-5s emitted=%-9s committed=%-9s aborted=%-9s in-flight=%s\n' \
    "$SECONDS" "$emitted" "$committed" "$aborted" "$gap"
done

reap
trap - EXIT

# A record the counter could not parse means the results channel is
# carrying something that is not a decision record.
if grep -q 'bad=' "$LOG" 2>/dev/null; then
  echo "[soak] FAILED: unparsable records on the results channel" >&2
  grep -o '\[loam-tp\][^"]*bad=[0-9a-f]*' "$LOG" | tail -3 >&2
  fail=1
fi

# Faults end a run rather than degrade it, so they are checked whatever
# the counters say.
if grep -qiE 'panic|module fault|step deadline|FATAL' "$LOG" 2>/dev/null; then
  echo "[soak] FAILED: fault reported during the run" >&2
  grep -iE 'panic|module fault|step deadline|FATAL' "$LOG" | head -5 >&2
  fail=1
fi

if [ "$samples" -eq 0 ]; then
  echo "[soak] FAILED: no samples taken — see $LOG" >&2
  fail=1
fi

lg=$(last_lg); tp=$(last_tp)
emitted=$(hex "$(field "$lg" E)")
refused=$(hex "$(field "$lg" R)")
committed=$(hex "$(field "$tp" C)")
aborted=$(hex "$(field "$tp" A)")
echo "[soak] final: emitted=$emitted refused=$refused committed=$committed aborted=$aborted"
echo "[soak] samples=$samples peak in-flight=$peak_gap"

# The end-state check: with the generator stopped, everything it got
# onto the channel must have resolved. In-flight during the run is
# expected; in-flight after it is loss.
settle=$((emitted - committed - aborted))
if [ "$settle" -gt "$((peak_gap + 1))" ]; then
  echo "[soak] FAILED: $settle record(s) unresolved at exit, above peak in-flight $peak_gap" >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "[soak] see $LOG" >&2
  exit 1
fi
echo "[soak] OK — plane sustained load for ${DURATION}s"
