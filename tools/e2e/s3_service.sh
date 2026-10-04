#!/usr/bin/env bash
# The loam-s3 service bundle, run as an operator runs it:
#
#   fluxor run packaging/service/loam-s3/workload.toml --param …
#
# and driven from outside by curl (SigV4-signed by curl itself) and by
# wave's S3 traffic driver.
#
# Gates:
#   - the bundle refuses to run without a required parameter;
#   - an object's life: PUT (a single record and a streamed multi-megabyte
#     body), GET identical, HEAD's length, a range, the listing, a
#     conditional create refused when the key exists, DELETE, then 404;
#   - refusals: an unsigned request, a key whose capability does not
#     reach the bucket;
#   - wave's traffic driver passes (payload forms, multipart, listings,
#     concurrency) when a wave checkout is beside this one;
#   - what was written survives the service being stopped and run again
#     on the same write-ahead logs and body directory.
#
#   tools/e2e/s3_service.sh
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/service_lib.sh"

WAVE_ROOT="${WAVE_ROOT:-$ROOT/../wave}"
BUNDLE="packaging/service/loam-s3/workload.toml"

echo "s3_service: the loam-s3 bundle"

MESH=$(mesh_root "$W")
{
  echo "AKALPHA0000000000001 alpha-secret-key alpha/ $(mint "$W" --scope alpha/ read_state,send_command)"
  echo "AKBETA00000000000002 beta-secret-key beta/ $(mint "$W" --scope beta/ read_state,send_command)"
} >"$W/credentials"
mkdir -p "$W/bodies" "$W/spool"
PORT=$(free_port)

params=(--param "port=$PORT" --param "credentials=$W/credentials" --param "mesh_roots=$MESH"
  --param "ns_wal=$W/ns.wal" --param "obj_wal=$W/obj.wal" --param "body_dir=$W/bodies"
  --param "spool_dir=$W/spool" --param max_object_mib=64 --param part_min_kib=64)

# A required parameter left out is refused before anything runs.
if (cd "$ROOT" && timeout 120 fluxor run "$BUNDLE" --param "port=$PORT") >"$W/refused.log" 2>&1; then
  fail "the bundle ran without its required parameters"
fi
grep -q "credentials" "$W/refused.log" || fail "the refusal does not name the missing parameter"
pass "a missing required parameter is refused"

start() {
  graph_start "$W/run$1.log" "$BUNDLE" "${params[@]}"
  S3=$GRAPH_PID
  wait_log "$W/run$1.log" "s3_serve\] serving"
}
start 1

URL="http://127.0.0.1:$PORT"
A=(AKALPHA0000000000001 alpha-secret-key)
B=(AKBETA00000000000002 beta-secret-key)

# Wave's driver lists whole buckets, so it runs while they are empty.
if [ -f "$WAVE_ROOT/tools/e2e/s3_traffic.py" ]; then
  cat >"$W/traffic.json" <<EOF
{"region": "us-east-1", "max_object_mib": 64, "part_min_kib": 64,
 "alpha": {"key": "${A[0]}", "secret": "${A[1]}", "bucket": "alpha"},
 "beta": {"key": "${B[0]}", "secret": "${B[1]}", "bucket": "beta"}}
EOF
  timeout 600 python3 "$WAVE_ROOT/tools/e2e/s3_traffic.py" "127.0.0.1:$PORT" "$W/traffic.json" \
    >"$W/traffic.log" 2>&1 || {
    tail -20 "$W/traffic.log" >&2
    fail "wave's S3 traffic driver"
  }
  pass "wave's S3 traffic driver"
else
  echo "  note: no wave checkout at $WAVE_ROOT; its traffic driver was not run"
fi

head -c 1000 /dev/urandom >"$W/small"
head -c 3000000 /dev/urandom >"$W/large"
expect 200 "$(s3 "${A[@]}" -X PUT -T "$W/small" "$URL/alpha/docs/small")" "PUT a single-record object"
expect 200 "$(s3 "${A[@]}" -X PUT -T "$W/large" "$URL/alpha/docs/large")" "PUT a streamed 3 MB object"
expect 200 "$(S3_OUT="$W/large.back" s3 "${A[@]}" "$URL/alpha/docs/large")" "GET the streamed object"
cmp -s "$W/large" "$W/large.back" || fail "GET returned different bytes"
len=$(curl -s -I --aws-sigv4 "aws:amz:us-east-1:s3" --user "${A[0]}:${A[1]}" "$URL/alpha/docs/large" |
  tr -d '\r' | awk 'tolower($1)=="content-length:"{print $2}')
expect 3000000 "$len" "HEAD reports the length"
expect 206 "$(S3_OUT="$W/range" s3 "${A[@]}" -H "Range: bytes=1000-1999" "$URL/alpha/docs/large")" "a range"
cmp -s "$W/range" <(tail -c +1001 "$W/large" | head -c 1000) || fail "the range is not those bytes"
expect 200 "$(S3_OUT="$W/list" s3 "${A[@]}" "$URL/alpha?list-type=2&prefix=docs/")" "the listing"
grep -q "<Key>docs/large</Key>" "$W/list" && grep -q "<Key>docs/small</Key>" "$W/list" ||
  fail "the listing does not name both objects"
expect 412 "$(s3 "${A[@]}" -X PUT -H "If-None-Match: *" -T "$W/small" "$URL/alpha/docs/small")" \
  "a conditional create of an existing key"

expect 403 "$(curl -m 30 -s -o /dev/null -w "%{http_code}" "$URL/alpha/docs/small")" "an unsigned request"
expect 403 "$(s3 "${B[@]}" "$URL/alpha/docs/small")" "a key whose capability does not reach the bucket"

expect 204 "$(s3 "${A[@]}" -X DELETE "$URL/alpha/docs/small")" "DELETE"
expect 404 "$(s3 "${A[@]}" "$URL/alpha/docs/small")" "GET after DELETE"


echo "s3_service: stopped and run again on the same state"
graph_stop "$S3"
start 2
expect 200 "$(S3_OUT="$W/large.again" s3 "${A[@]}" "$URL/alpha/docs/large")" "GET after the restart"
cmp -s "$W/large" "$W/large.again" || fail "the object changed across the restart"
expect 404 "$(s3 "${A[@]}" "$URL/alpha/docs/small")" "a deleted object stays deleted"

echo "s3_service: ok"
