#!/usr/bin/env bash
# The loam-node stack's exchange front, driven in-graph:
#
#   fluxor run examples/linux/storage_front.yaml --param …
#
# The example includes packaging/stack/loam-node.yaml by path and wires
# wave's `http` to the node's exports, so each HTTP request is an exchange
# the node's `object_exchange` answers through loam's `storage.object`
# provider, under the capability the front presents. curl drives it.
#
# Gates:
#   - PUT, then GET the exact bytes back, HEAD's length: the node's gate
#     granted the front's capability;
#   - a streamed object of many records (3 MB) round-trips;
#   - GET of an absent name is 404; DELETE is 204 and the name is then 404;
#   - the scope is the front's root: a listing names objects below it, and
#     a front scoped `beta/` over the same node sees none of `alpha/`'s
#     objects at the same targets, and writes its own beside them;
#   - a front whose scope its capability does not grant is refused by the
#     gate, and every request is 403;
#   - with a read-only capability a write is 403 while reads are served;
#   - a capability that does not chain to the node's mesh root is refused
#     by the gate, the front says so, and every request is 403;
#   - with no capability given, every request is 403;
#   - what a PUT states is kept: HEAD returns key-ref, retain-until and
#     legal-hold, DELETE and PUT over a retained or held object are 423,
#     PATCH extends and clears, shortening is 423, GET still reads, and a
#     restart of the node keeps all of it.
#
#   tools/e2e/storage_front.sh
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/service_lib.sh"

GRAPH="examples/linux/storage_front.yaml"

echo "storage_front: loam-node's exchange front"

MESH=$(mesh_root "$W")
RW=$(mint "$W" --scope alpha/ read_state,send_command)
RO=$(mint "$W" --scope alpha/ read_state)
BETA=$(mint "$W" --scope beta/ read_state,send_command)
mkdir -p "$W/foreign"
mesh_root "$W/foreign" >/dev/null
FOREIGN=$(mint "$W/foreign" --scope alpha/ read_state,send_command)

# front <run> <scope> <capability> [state] — run the example on the state
# of <state> (fresh, under <run>, by default); the port is left in PORT and
# the URL in URL.
front() {
  local run="$1" state="$W/${4:-$1}"
  PORT=$(free_port)
  URL="http://127.0.0.1:$PORT"
  mkdir -p "$state/bodies" "$state/spool"
  graph_start "$W/$run.log" "$GRAPH" --param "port=$PORT" --param "dir=$state" \
    --param "mesh_roots=$MESH" --param "scope=$2" --param "capability=$3"
  FRONT=$GRAPH_PID
  wait_log "$W/$run.log" "listening on port $PORT"
}

# req <curl args...> — echoes the status code.
req() {
  curl -m 60 -s -o "${OUT:-/dev/null}" -w "%{http_code}" "$@"
}

front rw alpha/ "$RW"

head -c 1000 /dev/urandom >"$W/small"
head -c 3000000 /dev/urandom >"$W/large"
expect 200 "$(req -X PUT --data-binary @"$W/small" "$URL/docs/small")" "PUT a single-record object"
expect 200 "$(OUT="$W/small.back" req "$URL/docs/small")" "GET it"
cmp -s "$W/small" "$W/small.back" || fail "GET returned different bytes"
pass "GET returned the exact bytes"
len=$(curl -m 30 -s -I "$URL/docs/small" | tr -d '\r' | awk 'tolower($1)=="content-length:"{print $2}')
expect 1000 "$len" "HEAD reports the length"

expect 200 "$(req -X PUT -T "$W/large" "$URL/docs/large")" "PUT a streamed 3 MB object"
expect 200 "$(OUT="$W/large.back" req "$URL/docs/large")" "GET the streamed object"
cmp -s "$W/large" "$W/large.back" || fail "the streamed object came back different"
pass "the streamed object came back exact"
expect 206 "$(OUT="$W/range" req -H "Range: bytes=1000-1999" "$URL/docs/large")" "a range"
cmp -s "$W/range" <(tail -c +1001 "$W/large" | head -c 1000) || fail "the range is not those bytes"

expect 404 "$(req "$URL/docs/absent")" "GET of an absent name"
expect 204 "$(req -X DELETE "$URL/docs/small")" "DELETE"
expect 404 "$(req "$URL/docs/small")" "GET after DELETE"

expect 200 "$(OUT="$W/list" req "$URL/?list")" "a listing"
[ "$(cat "$W/list")" = "docs/large" ] || fail "the listing is not the names below the scope: $(cat "$W/list")"
pass "the listing names docs/large, below the scope"

echo "storage_front: key reference, retention and legal hold"
UNTIL=$(( ($(date +%s) + 3600) * 1000 ))
# hdr <name> <url> — one response header's value from a HEAD.
hdr() {
  curl -m 30 -s -I "$2" | tr -d '\r' | awk -v h="$(echo "$1" | tr 'A-Z' 'a-z'):" 'tolower($1)==h{print $2}'
}
expect 200 "$(req -X PUT --data-binary @"$W/small" -H "key-ref: sealer-1" -H "retain-until: $UNTIL" "$URL/worm/a")" "PUT with retain-until and key-ref"
expect "$UNTIL" "$(hdr retain-until "$URL/worm/a")" "HEAD returns retain-until"
expect sealer-1 "$(hdr key-ref "$URL/worm/a")" "HEAD returns key-ref"
expect 423 "$(req -X DELETE "$URL/worm/a")" "DELETE of a retained object"
expect 423 "$(req -X PUT --data-binary @"$W/large" "$URL/worm/a")" "a streamed PUT over a retained object"
expect 423 "$(req -X PUT --data-binary @"$W/small" "$URL/worm/a")" "a single PUT over a retained object"
expect 423 "$(req -X PATCH -H "content-length: 0" -H "retain-until: $((UNTIL - 1))" "$URL/worm/a")" "PATCH that shortens"
expect 200 "$(req -X PATCH -H "content-length: 0" -H "retain-until: $UNTIL" "$URL/worm/a")" "PATCH naming the value held"
expect 200 "$(req -X PATCH -H "content-length: 0" -H "retain-until: $((UNTIL + 5000))" -H "legal-hold: on" "$URL/worm/a")" "PATCH that extends and holds"
expect "$((UNTIL + 5000))" "$(hdr retain-until "$URL/worm/a")" "the extension is reported"
expect on "$(hdr legal-hold "$URL/worm/a")" "the hold is reported"
expect 200 "$(OUT="$W/worm.back" req "$URL/worm/a")" "GET of a retained object"
cmp -s "$W/small" "$W/worm.back" || fail "the retained object came back different"
pass "the retained object reads back exact"
expect 404 "$(req -X PATCH -H "content-length: 0" -H "legal-hold: on" "$URL/worm/absent")" "PATCH of an absent name"
expect 200 "$(req -X PUT --data-binary @"$W/small" -H "legal-hold: on" "$URL/worm/held")" "PUT under a hold"
expect 423 "$(req -X DELETE "$URL/worm/held")" "DELETE of a held object"
expect 200 "$(req -X PATCH -H "content-length: 0" -H "legal-hold: off" "$URL/worm/held")" "PATCH clears the hold"
expect 204 "$(req -X DELETE "$URL/worm/held")" "DELETE once it is clear"
PAST=$(( ($(date +%s) - 3600) * 1000 ))
expect 200 "$(req -X PUT --data-binary @"$W/small" -H "retain-until: $PAST" "$URL/worm/past")" "PUT with a retention already passed"
expect 204 "$(req -X DELETE "$URL/worm/past")" "DELETE past its retention"

echo "storage_front: a restart keeps them"
graph_stop "$FRONT"
front rw2 alpha/ "$RW" rw
expect "$((UNTIL + 5000))" "$(hdr retain-until "$URL/worm/a")" "retain-until after a restart"
expect sealer-1 "$(hdr key-ref "$URL/worm/a")" "key-ref after a restart"
expect on "$(hdr legal-hold "$URL/worm/a")" "the hold after a restart"
expect 423 "$(req -X DELETE "$URL/worm/a")" "DELETE after a restart"
expect 200 "$(req -X PATCH -H "content-length: 0" -H "legal-hold: off" "$URL/worm/a")" "the hold clears after a restart"
expect 423 "$(req -X DELETE "$URL/worm/a")" "retention stands with the hold gone"
graph_stop "$FRONT"

echo "storage_front: a front scoped beta/ over the same node"
front beta beta/ "$BETA" rw
expect 404 "$(req "$URL/docs/large")" "alpha/'s object is not at the same target"
expect 200 "$(OUT="$W/list" req "$URL/?list")" "a listing"
[ ! -s "$W/list" ] || fail "beta/ lists alpha/'s names: $(cat "$W/list")"
pass "the listing is empty"
expect 200 "$(req -X PUT --data-binary @"$W/small" "$URL/docs/large")" "PUT its own docs/large"
graph_stop "$FRONT"
front alpha alpha/ "$RW" rw
expect 200 "$(OUT="$W/large.back" req "$URL/docs/large")" "alpha/'s docs/large, back under alpha/"
cmp -s "$W/large" "$W/large.back" || fail "beta/'s write reached alpha/'s object"
pass "beta/'s write left alpha/'s object as it was"
graph_stop "$FRONT"

echo "storage_front: a scope the capability does not grant"
front ungranted beta/ "$RW"
expect 403 "$(req -X PUT --data-binary @"$W/small" "$URL/docs/small")" "a write"
expect 403 "$(req "$URL/docs/large")" "a read"
wait_log "$W/ungranted.log" "store refused the capability"
pass "the front logged the refusal"
graph_stop "$FRONT"

echo "storage_front: a read-only front"
front ro alpha/ "$RO"
expect 403 "$(req -X PUT --data-binary @"$W/small" "$URL/docs/small")" "a write under a read capability"
expect 404 "$(req "$URL/docs/small")" "a read under it is served"
graph_stop "$FRONT"

echo "storage_front: a capability from another mesh root"
front foreign alpha/ "$FOREIGN"
expect 403 "$(req -X PUT --data-binary @"$W/small" "$URL/docs/small")" "a write"
expect 403 "$(req "$URL/docs/small")" "a read"
wait_log "$W/foreign.log" "store refused the capability"
pass "the front logged the refusal"
graph_stop "$FRONT"

echo "storage_front: no capability given"
front none "" ""
expect 403 "$(req -X PUT --data-binary @"$W/small" "$URL/docs/small")" "a write"
expect 403 "$(req "$URL/docs/small")" "a read"
graph_stop "$FRONT"

echo "storage_front: ok"
