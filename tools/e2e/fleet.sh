#!/usr/bin/env bash
# The body plane across nodes: an S3 front whose bodies live on two
# loam-body nodes, each reached over its own mutually authenticated
# remote_channel session.
#
#   two loam-body graphs (packaging/mtls/loam-body), each a body_store
#   behind tls (server, client certificate required) and remote_channel
#
#   one router graph (tools/e2e/graphs/fleet_s3.yaml): http, s3_serve,
#   object_provider, admin_gate, admin_router, namespace_router,
#   object_index and body_fanout_router with replicas 2, its members
#   dialling the two nodes through remote_channel over tls
#
# Gates:
#   - bodies of every size the plane carries land on both nodes: a small
#     record, records larger than a channel's default ring, the largest
#     single record, and a streamed multi-megabyte object;
#   - what was written reads back identically;
#   - with one node down, reads are still served from the other and a
#     write is refused (two replicas are required), never acknowledged;
#   - once the node is back, its member redials and writes land on both
#     nodes again.
#
#   tools/e2e/fleet.sh
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/service_lib.sh"

echo "fleet: two body nodes behind one S3 front"

make_pki "$W/pki"
MESH=$(mesh_root "$W")
KEY=AKFLEET0000000000001
SEC=fleet-secret-key
echo "$KEY $SEC alpha/ $(mint "$W" --scope alpha/ read_state,send_command)" >"$W/credentials"

PORT_A=$(free_port)
PORT_B=$(free_port)
PORT_S3=$(free_port)
mkdir -p "$W/a" "$W/b" "$W/r/spool"

render() {
  python3 "$ROOT/tools/e2e/render_service.py" "$@"
}

start_body() { # <name> <port>
  render "$ROOT/packaging/mtls/loam-body/linux.yaml" "$W/body_$1.yaml" \
    ca="$W/pki/ca.pem" cert="$W/pki/server.der" key="$W/pki/server.key.der" \
    port="$2" body_dir="$W/$1"
  graph_start "$W/body_$1.log" "$W/body_$1.yaml"
  wait_log "$W/body_$1.log" "listening on port $2"
}

start_body a "$PORT_A"
BODY_A=$GRAPH_PID
start_body b "$PORT_B"

render "$ROOT/tools/e2e/graphs/fleet_s3.yaml" "$W/fleet.yaml" \
  port="$PORT_S3" credentials="$W/credentials" mesh_roots="$MESH" \
  spool_dir="$W/r/spool" ns_wal="$W/r/ns.wal" obj_wal="$W/r/obj.wal" \
  ca="$W/pki/ca.pem" cert="$W/pki/client.der" key="$W/pki/client.key.der" \
  member_a="localhost:$PORT_A" member_b="localhost:$PORT_B"
graph_start "$W/fleet.log" "$W/fleet.yaml"
wait_log "$W/fleet.log" "s3_serve\] serving"
wait_log "$W/fleet.log" "remote_channel\] session open" 2
pass "both members' sessions open"

URL="http://127.0.0.1:$PORT_S3/alpha"
put() { # <name> <bytes>
  head -c "$2" /dev/urandom >"$W/$1"
  s3 "$KEY" "$SEC" -X PUT -T "$W/$1" "$URL/$1"
}
on_both() { # <file>
  local d
  d=$(sha256sum "$W/$1" | cut -c1-64)
  [ -f "$W/a/$d" ] && [ -f "$W/b/$d" ] || fail "$1 is not on both nodes"
  cmp -s "$W/a/$d" "$W/$1" && cmp -s "$W/b/$d" "$W/$1" || fail "$1 differs on a node"
  pass "$1 on both nodes"
}
get_same() { # <name>
  local code
  code=$(S3_OUT="$W/$1.back" s3 "$KEY" "$SEC" "$URL/$1")
  expect 200 "$code" "GET $1"
  cmp -s "$W/$1" "$W/$1.back" || fail "GET $1 read back different bytes"
}

for size in 100 12000 61000 3000000; do
  expect 200 "$(put "o$size" "$size")" "PUT $size bytes"
done
for size in 100 12000 3000000; do
  on_both "o$size"
done
get_same o3000000
get_same o12000

echo "fleet: node A down"
graph_stop "$BODY_A"
get_same o3000000
code=$(put down 5000)
[ "$code" = 200 ] && fail "a write with one of two replicas down was acknowledged"
pass "a write with a replica down is refused ($code)"

echo "fleet: node A back"
start_body a "$PORT_A"
wait_log "$W/fleet.log" "remote_channel\] session open" 3
expect 200 "$(put again 70000)" "PUT after the member redialled"
on_both again
get_same o61000

echo "fleet: ok"
