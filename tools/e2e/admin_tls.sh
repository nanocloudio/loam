#!/usr/bin/env bash
# The admin plane over mutual TLS, driven by the `loam` operator applet:
#
#   the loam-admin template (packaging/mtls/loam-admin), rendered with a
#   CA, a server identity and a mesh root, and run with `fluxor run`;
#
#   the applet installed from packaging/cli/workload.toml into a private
#   HOME (its client identity under ~/.config/loam/) and run with
#   `fluxor exec loam -- …`.
#
# Gates:
#   - files: put, ls, get identical, a conditional create refused when the
#     path is bound, rm, get after rm refused;
#   - volumes: create, read back zeroes, delete;
#   - snapshots: create, restore under another root, export to a second
#     node (only what it lacks is sent), delete;
#   - refusals: a capability that does not reach the root, a client whose
#     certificate chains to a CA the node does not trust, a plaintext
#     connection;
#   - each refusal leaves the node serving.
#
#   tools/e2e/admin_tls.sh
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/service_lib.sh"

echo "admin_tls: the admin plane over mutual TLS, driven by the applet"

make_pki "$W/pki"
make_foreign_client "$W/foreign"
MESH=$(mesh_root "$W")
BODY_PLANE=$(body_plane_object)
{
  mint "$W" --scope tenant/ read_state,send_command
  mint "$W" --scope snap/ read_state,send_command
  mint "$W" --scope restored/ read_state,send_command
  mint "$W" --object "$BODY_PLANE" read_state,send_command
} >"$W/ops.cap"
mint "$W" --scope other/ read_state,send_command >"$W/other.cap"

node() { # <name> <port> — a loam-admin node with its own state
  mkdir -p "$W/$1/bodies"
  python3 "$ROOT/tools/e2e/render_service.py" "$ROOT/packaging/mtls/loam-admin/linux.yaml" \
    "$W/$1.yaml" port="$2" mesh_roots="$MESH" ns_wal="$W/$1/ns.wal" obj_wal="$W/$1/obj.wal" \
    body_dir="$W/$1/bodies" gc_interval=0 \
    ca="$W/pki/ca.pem" cert="$W/pki/server.der" key="$W/pki/server.key.der"
  graph_start "$W/$1.log" "$W/$1.yaml"
  wait_log "$W/$1.log" "listening on port $2"
}
PORT=$(free_port)
PORT2=$(free_port)
node n1 "$PORT"
node n2 "$PORT2"

# The applet, installed into a private HOME. The launcher resolves the
# CLI from the store, which the private HOME would otherwise hide.
install_applet() { # <home> <identity dir>
  mkdir -p "$1/.config/loam"
  cp "$2/client.der" "$1/.config/loam/client.der"
  cp "$2/client.key.der" "$1/.config/loam/client.key.der"
  (
    applet_env "$1"
    cd "$ROOT" && fluxor install packaging/cli/workload.toml
  ) >"$1/install.log" 2>&1 || {
    cat "$1/install.log" >&2
    fail "installing the applet"
  }
}
applet_env() { # <home>
  export FLUXOR_STORE="${FLUXOR_STORE:-${XDG_DATA_HOME:-$HOME/.local/share}/fluxor/store}"
  export FLUXOR_INSTALL_ROOT="${FLUXOR_INSTALL_ROOT:-$ROOT/../fluxor}"
  export HOME="$1" XDG_DATA_HOME="$1/data" XDG_STATE_HOME="$1/state"
  export FLUXOR_APPLETS="$1/applets.toml" FLUXOR_CA_BUNDLE="$W/pki/ca.pem"
}
loam_as() { # <home> <capability> <port> <args…> — the applet's exit code
  local home="$1" cap="$2" port="$3"
  shift 3
  (
    applet_env "$home"
    timeout 120 fluxor exec loam -- --admin "localhost:$port" --capability "$cap" "$@"
  ) >"$W/out" 2>&1
}
loam() { loam_as "$W/home" "$W/ops.cap" "$PORT" "$@"; }
ok() { # <what> <args…>
  local what="$1"
  shift
  loam "$@" || {
    cat "$W/out" >&2
    fail "$what"
  }
  pass "$what"
}
refused() { # <what> <args…>
  local what="$1"
  shift
  if loam "$@"; then
    cat "$W/out" >&2
    fail "$what was allowed"
  fi
  pass "$what is refused"
}

install_applet "$W/home" "$W/pki"

head -c 200000 /dev/urandom >"$W/f.bin"
ok "put" put tenant /docs/f.bin "$W/f.bin" --type application/octet-stream
ok "ls" ls tenant
grep -q "/docs/f.bin" "$W/out" || fail "ls does not name /docs/f.bin"
ok "get" get tenant /docs/f.bin "$W/f.back"
cmp -s "$W/f.bin" "$W/f.back" || fail "get returned different bytes"
refused "a conditional create of a bound path" put tenant /docs/f.bin "$W/f.bin" --if-absent
ok "rm" rm tenant /docs/f.bin
refused "get after rm" get tenant /docs/f.bin "$W/gone"

ok "volume create" volume create tenant /vols/v0 1048576 32768
ok "volume read" volume read tenant /vols/v0 0 65536 "$W/v.read"
cmp -s "$W/v.read" <(head -c 65536 /dev/zero) || fail "a new volume does not read as zeroes"
refused "a second volume at the same path" volume create tenant /vols/v0 1048576 32768
ok "volume delete" volume delete tenant /vols/v0

# An export moves each body whole, in one admin answer.
head -c 40000 /dev/urandom >"$W/a.bin"
ok "put for the snapshot" put tenant /docs/a.bin "$W/a.bin"
ok "snapshot create" snapshot create tenant snap "$W/snap.manifest"
ok "snapshot restore" snapshot restore "$W/snap.manifest" restored
ok "get the restored file" get restored /docs/a.bin "$W/a.back"
cmp -s "$W/a.bin" "$W/a.back" || fail "the restored file differs"
ok "export to a second node" export "$W/snap.manifest" tenant --to "localhost:$PORT2" --to-capability "$W/ops.cap"
loam_as "$W/home" "$W/ops.cap" "$PORT2" get tenant /docs/a.bin "$W/a.n2" || fail "get from the second node"
cmp -s "$W/a.bin" "$W/a.n2" || fail "the exported file differs on the second node"
pass "the export reads back on the second node"
ok "export again" export "$W/snap.manifest" tenant --to "localhost:$PORT2" --to-capability "$W/ops.cap"
grep -qx "sent 0" "$W/out" || {
  cat "$W/out" >&2
  fail "a second export sent bodies the node already has"
}
pass "a second export sends no bodies"
ok "snapshot delete" snapshot delete snap

if loam_as "$W/home" "$W/other.cap" "$PORT" ls tenant; then
  fail "a capability for other/ listed tenant"
fi
grep -q "forbidden" "$W/out" || {
  cat "$W/out" >&2
  fail "the refusal does not say the capability does not cover it"
}
pass "a capability that does not reach the root is refused"

# An install builds the bundle in place, with the identity it finds:
# the operator's applet is installed again after the foreign one.
install_applet "$W/foreign-home" "$W/foreign"
if loam_as "$W/foreign-home" "$W/ops.cap" "$PORT" ls tenant; then
  fail "a client from an untrusted CA was served"
fi
grep -q "connection could not be made, or closed" "$W/out" || {
  cat "$W/out" >&2
  fail "the untrusted client failed for another reason than its connection"
}
pass "a client certificate from an untrusted CA is refused"
install_applet "$W/home" "$W/pki"

reply=$(printf 'not tls\r\n\r\n' | timeout 10 nc -q 3 127.0.0.1 "$PORT" | head -c 64 | od -An -c | tr -d ' \n' || true)
case "$reply" in
  *[a-zA-Z]*ok* | *tenant*) fail "a plaintext connection was answered with data" ;;
esac
pass "a plaintext connection is not served"

ok "the node still serves after the refusals" ls tenant

echo "admin_tls: ok"
