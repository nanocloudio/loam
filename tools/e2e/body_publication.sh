#!/usr/bin/env bash
# Body-plane publication gate: which fence a real provider hands the
# store, and whether the artefact lands under it.
#
# The store negotiates its publication recipe from the filesystem
# provider's capability bitmap: an atomic replace where the provider
# offers one, a name fence where it offers only that, and a refusal
# where it offers neither. Host tests cover all three by presenting
# synthetic bitmaps. What they cannot cover is the bitmap a live
# provider actually returns — that is a property of the runtime the
# graph is loaded into, not of the store.
#
# So this gate runs the smoke graph and asserts two things a host test
# cannot: the tier the provider negotiated, and a content-addressed
# artefact on disk with no staging file left beside it. A store that
# silently fell back to the weaker recipe still passes the smoke check
# and fails here, which is the point.
#
# Usage: tools/e2e/body_publication.sh [expected-tier]
set -euo pipefail
cd "$(dirname "$0")/../.."
. tools/e2e/graph_run.sh

EXPECT="${1:-rename}"
RUN_SECONDS="${RUN_SECONDS:-60}"

ROOT="target/loam-body-publication"
RENDERED="target/loam_body_publication.yaml"
LOG="target/loam_body_publication.log"

mkdir -p target
# The store never creates its root, and a leftover artefact from an
# earlier run would satisfy the on-disk check without this run having
# published anything.
rm -rf "$ROOT" "$LOG"
mkdir -p "$ROOT"

sed -e "s|      root_dir: .*|      root_dir: \"$PWD/$ROOT\"|" \
    examples/linux/body_e2e.yaml > "$RENDERED"

echo "[body-pub] running the body-plane graph, expecting tier=$EXPECT"

timeout "$RUN_SECONDS" fluxor run "$RENDERED" > "$LOG" 2>&1 &
runner=$!
# `fluxor run` spawns `fluxor-linux` as a child whose argv names the
# compiled config. Killing only the wrapper leaves that child stepping.
reap() { reap_graph "loam_body_publication" "$runner"; }
trap reap EXIT

deadline=$((SECONDS + RUN_SECONDS))
while [ "$SECONDS" -lt "$deadline" ]; do
  sleep 1
  grep -q '\[body_e2e\] \(PASS\|FAIL\)' "$LOG" 2>/dev/null && break
  kill -0 "$runner" 2>/dev/null || break
done
reap
trap - EXIT

fail=0

reason=$(graph_fault_reason "$LOG")
if [ -n "$reason" ]; then
  echo "[body-pub] FAILED: $reason — see $LOG" >&2
  exit 1
fi

if ! grep -q '\[body_e2e\] PASS' "$LOG"; then
  echo "[body-pub] FAILED: the round trip did not complete" >&2
  fail=1
fi

tier=$(sed -n 's/.*\[body_store\] publish tier=\([a-z_]*\).*/\1/p' "$LOG" | tail -1)
if [ -z "$tier" ]; then
  echo "[body-pub] FAILED: the store never reported a publication tier" >&2
  fail=1
elif [ "$tier" != "$EXPECT" ]; then
  echo "[body-pub] FAILED: provider negotiated tier=$tier, expected $EXPECT" >&2
  echo "[body-pub]   a weaker tier means the provider's capability bitmap" >&2
  echo "[body-pub]   lost a bit the store depends on" >&2
  fail=1
else
  echo "[body-pub] tier=$tier"
fi

# Content-addressed name: 64 hex characters, nothing else.
published=$(find "$ROOT" -maxdepth 1 -type f -regextype posix-extended \
              -regex '.*/[0-9a-f]{64}' | wc -l)
staging=$(find "$ROOT" -maxdepth 1 -type f \
            \( -name '.pub_*' -o -name '.wip_*' \) | wc -l)

echo "[body-pub] artefacts=$published staging=$staging"

if [ "$published" -eq 0 ]; then
  echo "[body-pub] FAILED: the round trip passed but nothing was published" >&2
  fail=1
fi
if [ "$staging" -ne 0 ]; then
  echo "[body-pub] FAILED: a staging file outlived its publication" >&2
  find "$ROOT" -maxdepth 1 -type f \( -name '.pub_*' -o -name '.wip_*' \) >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "[body-pub] see $LOG" >&2
  exit 1
fi

echo "[body-pub] OK — published through the $tier fence, nothing left staged"
