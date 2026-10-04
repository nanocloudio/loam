#!/usr/bin/env bash
# A loam volume as an NBD block device:
#
#   a loam-admin node (packaging/mtls/loam-admin) holding the volume, made
#   with the `loam` applet;
#
#   the loam-nbd template (packaging/mtls/loam-nbd): nbd_serve over
#   loam_volume, which reaches the node over mutual TLS and holds the
#   volume's writer lease.
#
# Gates:
#   - the export reports the volume's size;
#   - a write across an extent boundary reads back identically, and the
#     applet reads the same bytes from the node once it is flushed;
#   - a flushed write survives the device being killed (-9) and run again;
#     a write never flushed is not visible after it;
#   - a FUA write is durable without a flush;
#   - a second device on the same volume is refused while the first holds
#     the lease;
#   - a device whose capability does not reach the volume never serves.
#
#   tools/e2e/nbd.sh
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/service_lib.sh"

NBD="python3 $ROOT/tools/e2e/nbd_client.py"
echo "nbd: a loam volume as an NBD device"

make_pki "$W/pki"
MESH=$(mesh_root "$W")
BODY_PLANE=$(body_plane_object)
{
  mint "$W" --scope tenant/ read_state,send_command
  mint "$W" --object "$BODY_PLANE" read_state,send_command
} >"$W/ops.cap"
{
  mint "$W" --scope other/ read_state,send_command
  mint "$W" --object "$BODY_PLANE" read_state,send_command
} >"$W/other.cap"

ADMIN=$(free_port)
mkdir -p "$W/node/bodies"
python3 "$ROOT/tools/e2e/render_service.py" "$ROOT/packaging/mtls/loam-admin/linux.yaml" \
  "$W/node.yaml" port="$ADMIN" mesh_roots="$MESH" ns_wal="$W/node/ns.wal" \
  obj_wal="$W/node/obj.wal" body_dir="$W/node/bodies" gc_interval=0 \
  ca="$W/pki/ca.pem" cert="$W/pki/server.der" key="$W/pki/server.key.der"
graph_start "$W/node.log" "$W/node.yaml"
wait_log "$W/node.log" "listening on port $ADMIN"

applet_env() {
  export FLUXOR_STORE="${FLUXOR_STORE:-${XDG_DATA_HOME:-$HOME/.local/share}/fluxor/store}"
  export FLUXOR_INSTALL_ROOT="${FLUXOR_INSTALL_ROOT:-$ROOT/../fluxor}"
  export HOME="$W/home" XDG_DATA_HOME="$W/home/data" XDG_STATE_HOME="$W/home/state"
  export FLUXOR_APPLETS="$W/home/applets.toml" FLUXOR_CA_BUNDLE="$W/pki/ca.pem"
}
mkdir -p "$W/home/.config/loam"
cp "$W/pki/client.der" "$W/pki/client.key.der" "$W/home/.config/loam/"
(applet_env && cd "$ROOT" && fluxor install packaging/cli/workload.toml) >"$W/install.log" 2>&1 ||
  fail "installing the applet"
loam() {
  (applet_env && timeout 120 fluxor exec loam -- --admin "localhost:$ADMIN" --capability "$W/ops.cap" "$@") \
    >"$W/out" 2>&1 || {
    cat "$W/out" >&2
    fail "loam $*"
  }
}
SIZE=1048576
# Short, so the gate waits out a killed writer's lease quickly.
LEASE_MS=5000
loam volume create tenant /vols/v0 "$SIZE" 32768
pass "the volume is created"

device() { # <name> <port> <capability> — run a device; its pid in GRAPH_PID
  python3 "$ROOT/tools/e2e/render_service.py" "$ROOT/packaging/mtls/loam-nbd/linux.yaml" \
    "$W/$1.yaml" port="$2" admin="localhost:$ADMIN" capability="$3" root=tenant \
    path=/vols/v0 cert="$W/pki/client.der" key="$W/pki/client.key.der" \
    block_size=4096 lease_ttl_ms=$LEASE_MS
  FLUXOR_CA_BUNDLE="$W/pki/ca.pem" graph_start "$W/$1.log" "$W/$1.yaml"
}

PORT=$(free_port)
device dev1 "$PORT" "$W/ops.cap"
DEV=$GRAPH_PID
wait_log "$W/dev1.log" "loam_volume\] ready"
expect "$SIZE" "$($NBD "127.0.0.1:$PORT" size)" "the export's size"

# 64 KiB at 28 KiB: across the 32 KiB extent boundary, block aligned.
head -c 65536 /dev/urandom >"$W/blk"
printf 'write 28672 %s\nflush\nread 28672 65536 %s\n' "$W/blk" "$W/blk.back" >"$W/s1"
$NBD "127.0.0.1:$PORT" script "$W/s1"
cmp -s "$W/blk" "$W/blk.back" || fail "a write across an extent boundary read back different"
pass "a write across an extent boundary reads back"
loam volume read tenant /vols/v0 28672 65536 "$W/blk.cli"
cmp -s "$W/blk" "$W/blk.cli" || fail "the node holds different bytes than were flushed"
pass "the applet reads the flushed bytes from the node"

# A second device on the same volume, while the first holds the lease.
PORT2=$(free_port)
device dev2 "$PORT2" "$W/ops.cap"
DEV2=$GRAPH_PID
wait_log "$W/dev2.log" "the volume has another writer"
pass "a second writer is refused while the lease is held"
graph_stop "$DEV2"

# Flushed, then killed; written without a flush, then killed.
head -c 4096 /dev/urandom >"$W/unflushed"
printf 'write 0 %s\n' "$W/unflushed" >"$W/s2"
$NBD "127.0.0.1:$PORT" script "$W/s2"
graph_stop "$DEV" KILL
pass "the device is killed (-9)"

# A writer is refused while a lease is held, and a killed device's lease
# is held until it runs out.
sleep $((LEASE_MS / 1000 + 2))
device dev3 "$PORT" "$W/ops.cap"
DEV=$GRAPH_PID
wait_log "$W/dev3.log" "loam_volume\] ready" 1 90
printf 'read 28672 65536 %s\nread 0 4096 %s\n' "$W/blk.again" "$W/head.again" >"$W/s3"
$NBD "127.0.0.1:$PORT" script "$W/s3"
cmp -s "$W/blk" "$W/blk.again" || fail "a flushed write did not survive the kill"
pass "a flushed write survives the kill"
cmp -s "$W/unflushed" "$W/head.again" && fail "a write never flushed became visible"
pass "a write never flushed is not visible after it"

head -c 8192 /dev/urandom >"$W/fua"
printf 'write 131072 %s fua\n' "$W/fua" >"$W/s4"
$NBD "127.0.0.1:$PORT" script "$W/s4"
loam volume read tenant /vols/v0 131072 8192 "$W/fua.cli"
cmp -s "$W/fua" "$W/fua.cli" || fail "a FUA write is not on the node"
pass "a FUA write is durable without a flush"
graph_stop "$DEV"

PORT3=$(free_port)
device dev4 "$PORT3" "$W/other.cap"
wait_log "$W/dev4.log" "no grant for the volume"
grep -q "loam_volume\] ready" "$W/dev4.log" && fail "a device without a grant became ready"
pass "a device whose capability does not reach the volume never serves"

echo "nbd: ok"
