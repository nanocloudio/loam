# Shared setup for the service gates (s3_service, admin_tls, nbd, fleet).
#
# Each gate runs loam's bundles the way an operator does — `fluxor run`
# of a workload manifest with `--param` values, or a template under
# packaging/mtls/ rendered with its values — and drives them from outside
# with real clients: curl, the `loam` applet, an NBD client. Everything
# a gate creates lives under one work directory; every graph it starts
# is stopped by its own process tree, never by a name pattern, so sibling
# graphs on the same machine are never touched.
#
# Source after setting nothing; the caller gets ROOT, W and the helpers.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=graph_run.sh
. "$ROOT/tools/e2e/graph_run.sh"

W="$(mktemp -d "${TMPDIR:-/tmp}/loam-e2e.XXXXXX")"
GRAPH_PIDS=()

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

pass() {
  echo "  ok: $*"
}

# _descendants <pid> — every process under <pid>, deepest first.
_descendants() {
  local c
  for c in $(pgrep -P "$1" 2>/dev/null); do
    _descendants "$c"
    echo "$c"
  done
}

# graph_start <log> <fluxor run args...> — echoes nothing; the graph's
# wrapper pid is appended to GRAPH_PIDS and left in GRAPH_PID.
graph_start() {
  local log="$1"
  shift
  (cd "$ROOT" && exec fluxor run "$@") >"$log" 2>&1 &
  GRAPH_PID=$!
  GRAPH_PIDS+=("$GRAPH_PID")
  # Stopped by graph_stop, which waits for it; the shell need not report it.
  disown "$GRAPH_PID"
}

# graph_stop <pid> [signal] — stop a graph and everything under it, and
# wait until it is gone (its sockets released).
graph_stop() {
  local pid="$1" sig="${2:-TERM}" procs waited=0
  procs="$(_descendants "$pid") $pid"
  # shellcheck disable=SC2086
  kill -s "$sig" $procs 2>/dev/null || true
  for p in $procs; do
    while kill -0 "$p" 2>/dev/null; do
      waited=$((waited + 1))
      [ "$waited" -gt 50 ] && kill -9 "$p" 2>/dev/null
      sleep 0.1
    done
  done
}

_stop_all() {
  local pid
  for pid in "${GRAPH_PIDS[@]}"; do
    graph_stop "$pid"
  done
  if [ -z "${LOAM_E2E_KEEP:-}" ]; then
    rm -rf -- "${W:?}"
  else
    echo "work directory kept: $W"
  fi
}
trap _stop_all EXIT

# wait_log <log> <pattern> [count] [seconds] — until <log> holds <count>
# lines matching <pattern>; fails naming the log otherwise.
wait_log() {
  local log="$1" pat="$2" want="${3:-1}" secs="${4:-120}" i n
  for ((i = 0; i < secs * 4; i++)); do
    n=$(grep -c -- "$pat" "$log" 2>/dev/null || true)
    [ "${n:-0}" -ge "$want" ] && return 0
    sleep 0.25
  done
  tail -20 "$log" >&2
  fail "no '$pat' in $log after ${secs}s${GRAPH_FAULT:+ ($(graph_fault_reason "$log"))}"
}

# make_pki <dir> — a CA, and a server and a client identity it signed,
# each as PEM and DER (`<name>.der`, `<name>.key.der`). Both name
# localhost / 127.0.0.1.
make_pki() {
  local d="$1" n
  mkdir -p "$d"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$d/ca.key" -out "$d/ca.pem" -days 2 -subj "/CN=loam-e2e-ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n' >"$d/ext"
  for n in server client; do
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -keyout "$d/$n.key" -out "$d/$n.csr" -subj "/CN=loam-$n" 2>/dev/null
    openssl x509 -req -in "$d/$n.csr" -CA "$d/ca.pem" -CAkey "$d/ca.key" \
      -CAcreateserial -days 2 -out "$d/$n.pem" -extfile "$d/ext" 2>/dev/null
    openssl x509 -in "$d/$n.pem" -outform DER -out "$d/$n.der"
    openssl ec -in "$d/$n.key" -outform DER -out "$d/$n.key.der" 2>/dev/null
  done
}

# make_foreign_client <dir> — a client identity from a CA nobody trusts.
make_foreign_client() {
  local d="$1"
  make_pki "$d"
}

# mesh_root <dir> — writes <dir>/root.seed and echoes the mesh root.
mesh_root() {
  head -c 32 /dev/urandom >"$1/root.seed"
  fluxor modules keygen --key "$1/root.seed" 2>/dev/null | tail -1
}

# mint <dir> <--scope s|--object hex> <perms> — one capability chain,
# valid from a minute ago for a day.
mint() {
  local now
  now=$(date +%s)
  fluxor modules cap mint --key "$1/root.seed" "$2" "$3" --perms "$4" \
    --not-before $((now - 60)) --not-after $((now + 86400)) 2>/dev/null | tail -1
}

# body_plane_object — the object the body plane's capabilities name.
body_plane_object() {
  printf 'loam.body-plane\0' | sha256sum | cut -c1-32
}

# s3 <key> <secret> <curl args...> — a SigV4-signed request; echoes the
# status code.
s3() {
  local key="$1" sec="$2"
  shift 2
  curl -m 60 -s -o "${S3_OUT:-/dev/null}" -w "%{http_code}" \
    --aws-sigv4 "aws:amz:us-east-1:s3" --user "$key:$sec" "$@"
}

# expect <want> <got> <what>
expect() {
  [ "$2" = "$1" ] || fail "$3: expected $1, got $2"
  pass "$3 ($2)"
}
