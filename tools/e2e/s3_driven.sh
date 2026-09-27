#!/usr/bin/env bash
# The S3 connector, DRIVEN — one operation per record, against a real gateway.
#
# `examples/s3/linux.yaml` proves the crypto: a boot-time signed
# ListBuckets returns 200, so the signature was accepted. It cannot prove the
# connector is USABLE, because there is no way to ask it for a different object.
# This does: a PUT and a GET chosen at runtime, each signed with the payload
# hashed in, driven through `request_in` and answered on `response_out`.
#
# The peer is `loam-server --s3-listen` — loam's own S3 gateway, so both halves
# of the round trip are loam's and a failure is attributable without a third
# party. The blob is then read back with curl, INDEPENDENTLY of the connector,
# so a connector that reported success while storing nothing still fails here.
#
#   tools/e2e/s3_driven.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FLUXOR_ROOT="${FLUXOR_ROOT:-$ROOT/../fluxor}"
# The runtime this project already runs graphs with. `fluxor` provisions
# it into our own target dir from the store, which is what `fluxor run`
# executes; a sibling source tree's cargo output exists only if somebody
# happened to build fluxor from source there, and fluxor's own tooling
# removes it. Prefer ours, fall back to the sibling, and let the
# environment override either.
PROVISIONED="$ROOT/target/aarch64-unknown-linux-gnu/release/fluxor-linux"
SIBLING="$FLUXOR_ROOT/target/aarch64-unknown-linux-gnu/release/fluxor-linux"
if [ -n "${LOAM_LINUX_RUNTIME:-}" ]; then
  RUNTIME="$LOAM_LINUX_RUNTIME"
elif [ -x "$PROVISIONED" ]; then
  RUNTIME="$PROVISIONED"
else
  RUNTIME="$SIBLING"
fi
SERVER="$ROOT/target/aarch64-unknown-linux-gnu/release/loam-server"
GRAPH="examples/s3/driven.yaml"
# Rendered per run with the peer's address; `fluxor build` writes a
# graph's artefacts under target/linux/<stem>/.
RENDERED="target/loam_s3_driven.yaml"
BUILT="$ROOT/target/linux/loam_s3_driven"
BUCKET=registry
KEY="blobs/sha256-driven"
BODY="driven-through-the-graph"

WORK="$(mktemp -d /tmp/loam-s3-driven-XXXXXX)"
PIDS=""
cleanup() {
  for p in $PIDS; do kill "$p" 2>/dev/null || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "FAIL: $1" >&2; [ -f "$WORK/loam.log" ] && tail -20 "$WORK/loam.log" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "$1 is not on PATH"; }
need curl
need python3
need fluxor
# Build the peer on every run rather than using whatever binary is
# lying in target/. Nothing else in CI builds this release
# `loam-server`, so an existing one can be arbitrarily old, and a gate
# that drives a stale server tests code that no longer exists. cargo is
# a no-op when the binary is current, so the common case costs nothing.
(cd "$ROOT" && cargo build --quiet --release --bin loam-server \
   --target aarch64-unknown-linux-gnu) \
  || fail "could not build loam-server"
[ -x "$SERVER" ] || fail "no loam-server at $SERVER after building it"
[ -x "$RUNTIME" ] || fail "no fluxor-linux at $RUNTIME
  Provision it:  cd $ROOT && fluxor run examples/linux/composed_node.yaml
  or build it:   cd $FLUXOR_ROOT && cargo build --release --bin fluxor-linux \\
                   --no-default-features --features host-linux \\
                   --target aarch64-unknown-linux-gnu"

# ── the peer ──────────────────────────────────────────────────────────────
#
# Port 0, and the port read back from the server's own announcement. A
# fixed port with a connect probe for readiness proves only that
# SOMETHING listens there: if the port is already held, this server
# fails to bind and exits, the probe connects to whatever holds it, and
# the gate goes on testing a stranger. The announcement is printed only
# after this process has bound, so it cannot be answered by anyone else.
mkdir -p "$WORK/body"
"$SERVER" --s3-listen "127.0.0.1:0" \
  --ns-wal "$WORK/ns.wal" --obj-wal "$WORK/obj.wal" \
  --fleet "dir:$WORK/body" >"$WORK/loam.log" 2>&1 &
SERVER_PID=$!
PIDS="$PIDS $SERVER_PID"
S3_ADDR=""
for _ in $(seq 100); do
  S3_ADDR=$(sed -n 's/^\[loam-server\] s3 gateway on \([0-9.]*:[0-9]*\)$/\1/p' \
            "$WORK/loam.log" | head -1)
  [ -n "$S3_ADDR" ] && break
  kill -0 "$SERVER_PID" 2>/dev/null || fail "loam-server exited before binding"
  sleep 0.1
done
[ -n "$S3_ADDR" ] || fail "loam-server never announced its S3 gateway"
S3_PORT="${S3_ADDR##*:}"

# ── the graph ─────────────────────────────────────────────────────────────
# The connector is pointed at the address this run's server bound.
sed "s|authority: \"127\.0\.0\.1:[0-9]*\"|authority: \"$S3_ADDR\"|" \
  "$ROOT/$GRAPH" > "$ROOT/$RENDERED"
grep -q "authority: \"$S3_ADDR\"" "$ROOT/$RENDERED" \
  || fail "could not point $GRAPH at $S3_ADDR"
( cd "$ROOT" && fluxor build "$RENDERED" ) >/dev/null \
  || fail "fluxor build $RENDERED"

# An S3Request record. Built here rather than by a helper module so the test
# depends on the WIRE FORMAT and not on someone else's encoder — if the record
# layout drifts, this fails.
record() { # <op_hex> <cid> <bucket> <key> <body>
  python3 - "$@" <<'PY'
import sys, struct
op, cid, bucket, key, body = int(sys.argv[1],16), int(sys.argv[2]), sys.argv[3].encode(), sys.argv[4].encode(), sys.argv[5].encode()
rec = bytes([op]) + struct.pack('<I', cid) + struct.pack('<HHI', len(bucket), len(key), len(body)) + bucket + key + body
sys.stdout.buffer.write(rec)
PY
}

# Run one record through the graph and return the raw S3Response bytes.
drive() { # <record file> <out file>
  timeout 25 "$RUNTIME" --config "$BUILT/config.bin" \
    --modules "$BUILT/modules.bin" \
    <"$1" >"$2" 2>"$WORK/graph.log" || true
}

# Decode [op][cid:u32][status:u16][body_len:u32][body]
decode() { # <file> <field>
  python3 - "$1" "$2" <<'PY'
import sys, struct
raw = open(sys.argv[1],'rb').read()
if len(raw) < 11:
    print(""); sys.exit(0)
op = raw[0]; cid = struct.unpack('<I', raw[1:5])[0]
status = struct.unpack('<H', raw[5:7])[0]; blen = struct.unpack('<I', raw[7:11])[0]
f = sys.argv[2]
print({'op':op,'cid':cid,'status':status,'len':blen,
       'body':raw[11:11+blen].decode('utf-8','replace')}[f])
PY
}

fail_count=0
check() { # <label> <expected> <actual>
  if [ "$2" = "$3" ]; then echo "  ok   $1"; else echo "  FAIL $1: want '$2', got '$3'"; fail_count=1; fi
}

# ── PUT ───────────────────────────────────────────────────────────────────
record 51 4242 "$BUCKET" "$KEY" "$BODY" > "$WORK/put.bin"
drive "$WORK/put.bin" "$WORK/put.out"
check "PUT is answered 200"            200  "$(decode "$WORK/put.out" status)"
check "PUT echoes its correlation id"  4242 "$(decode "$WORK/put.out" cid)"
check "PUT carries no response body"   0    "$(decode "$WORK/put.out" len)"

# INDEPENDENT confirmation: the object is really in the store. A connector that
# reported 200 without storing anything passes every check above and fails this.
check "the object is readable by curl" "$BODY" \
  "$(curl -s "http://127.0.0.1:$S3_PORT/$BUCKET/$KEY")"

# ── GET ───────────────────────────────────────────────────────────────────
record 50 4343 "$BUCKET" "$KEY" "" > "$WORK/get.bin"
drive "$WORK/get.bin" "$WORK/get.out"
check "GET is answered 200"            200  "$(decode "$WORK/get.out" status)"
check "GET echoes its correlation id"  4343 "$(decode "$WORK/get.out" cid)"
check "GET returns the object bytes"   "$BODY" "$(decode "$WORK/get.out" body)"

# ── HEAD ──────────────────────────────────────────────────────────────────
record 52 4444 "$BUCKET" "$KEY" "" > "$WORK/head.bin"
drive "$WORK/head.bin" "$WORK/head.out"
check "HEAD is answered 200"           200 "$(decode "$WORK/head.out" status)"
check "HEAD carries no body"           0   "$(decode "$WORK/head.out" len)"

# ── DELETE, then GET is a miss ────────────────────────────────────────────
record 53 4545 "$BUCKET" "$KEY" "" > "$WORK/del.bin"
drive "$WORK/del.bin" "$WORK/del.out"
check "DELETE is answered 204"         204 "$(decode "$WORK/del.out" status)"

record 50 4646 "$BUCKET" "$KEY" "" > "$WORK/get2.bin"
drive "$WORK/get2.bin" "$WORK/get2.out"
check "GET after DELETE is 404"        404 "$(decode "$WORK/get2.out" status)"

# ── refusals ──────────────────────────────────────────────────────────────
# A well-formed record naming an op this connector does not perform is ANSWERED,
# not dropped — a caller must learn it was refused rather than time out.
record 5F 4747 "$BUCKET" "$KEY" "" > "$WORK/bad.bin"
drive "$WORK/bad.bin" "$WORK/bad.out"
check "an unknown op is answered 501"  501  "$(decode "$WORK/bad.out" status)"
check "the refusal keeps the cid"      4747 "$(decode "$WORK/bad.out" cid)"

echo
if [ "$fail_count" = 0 ]; then
  echo "PASS s3 driven — PUT/GET/HEAD/DELETE chosen at runtime, signed per request"
else
  echo "FAIL s3 driven" >&2
fi
exit "$fail_count"
