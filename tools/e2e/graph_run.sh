# Shared teardown for the graph gates.
#
# Every gate here runs a `fluxor run` wrapper whose child is a
# `fluxor-linux` process holding a listening socket on the platform's
# default port. The gates run back to back, so a child that outlives
# its gate does not merely linger — it owns the port the next gate
# needs, and that gate comes up with a dead network for reasons its own
# output cannot explain.
#
# Killing is asynchronous: `pkill` returns once the signal is queued,
# not once the process is gone and its socket released. Waiting for the
# pattern to actually disappear is what makes the gates independent.

# reap_graph <pattern> <wrapper_pid>
#
# Stops the wrapper and its graph child, and does not return until no
# process matches <pattern>.
reap_graph() {
  local pattern="$1" wrapper="$2" waited=0

  kill "$wrapper" 2>/dev/null || true
  wait "$wrapper" 2>/dev/null || true
  pkill -f "$pattern" 2>/dev/null || true

  # Give the child its chance to exit on TERM, then insist.
  while pgrep -f "$pattern" >/dev/null 2>&1; do
    waited=$((waited + 1))
    if [ "$waited" -gt 20 ]; then
      pkill -9 -f "$pattern" 2>/dev/null || true
    fi
    # Ten seconds of resisting SIGKILL means uninterruptible I/O, not a
    # process this script can do anything about. Say so and stop waiting
    # — the diagnostic is the value, and blocking here would only move
    # the stall into the gate's teardown. reap also runs from an EXIT
    # trap, where a non-zero return has nowhere useful to go.
    if [ "$waited" -gt 100 ]; then
      echo "[reap] a process matching '$pattern' outlived SIGKILL" >&2
      return 0
    fi
    sleep 0.1
  done
}

# A graph that stops writing to its log has stopped stepping. Every
# counter read after that point is a snapshot of the moment it stopped,
# and the gates compare counters from two different modules — so a graph
# that dies between one module's report and the next reads as records
# accepted and then lost. That is the most alarming message these gates
# can print, and it would be describing a stall.
GRAPH_STALL_POLLS="${GRAPH_STALL_POLLS:-10}"

_graph_log_size=""
_graph_quiet_polls=0

# graph_stalled <log>
#
# True once <log> has not grown for GRAPH_STALL_POLLS consecutive calls.
# Call it once per poll from the settle loop.
graph_stalled() {
  local size
  size=$(wc -c < "$1" 2>/dev/null || echo 0)
  if [ "$size" = "$_graph_log_size" ]; then
    _graph_quiet_polls=$((_graph_quiet_polls + 1))
  else
    _graph_log_size="$size"
    _graph_quiet_polls=0
  fi
  [ "$_graph_quiet_polls" -ge "$GRAPH_STALL_POLLS" ]
}

# graph_fault_reason <log>
#
# Echoes why the run is not worth reading counters from, or nothing.
# A failed bind means the graph came up without the network it was
# composed with — usually the previous gate's child still holding the
# port — and none of its numbers describe the system under test.
graph_fault_reason() {
  if grep -q "SIGSEGV" "$1" 2>/dev/null; then
    echo "the runtime faulted — SIGSEGV"
  elif grep -q "bind() failed" "$1" 2>/dev/null; then
    grep -m1 -o "bind() failed.*" "$1"
  fi
}

# free_port
#
# Echoes a port nothing is listening on right now.
#
# The graphs name a port so an example runs as written, but a gate does
# not own the machine: sibling projects run their own fluxor graphs, and
# a fixed port is a fixed collision. A gate that loses the bind comes up
# with no network and reports whatever its counters happened to reach —
# which is why this is worth taking out of the graph's hands.
free_port() {
  python3 -c 'import socket
s = socket.socket()
s.bind(("", 0))
print(s.getsockname()[1])
s.close()'
}
