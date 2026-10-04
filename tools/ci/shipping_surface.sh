#!/usr/bin/env bash
# The shipping surface carries no cargo dependency.
#
# What ships is `.fmod` PIC modules, built from `modules/` and the fluxor
# SDK, composed into graphs that `fluxor run` and `fluxor exec` run. A
# device running them needs no cargo, no crate and no Linux build host.
# The one crate in the tree is the test harness (tests/harness), which
# mounts the same sources the modules do and ships nothing.
#
# Structural, not behavioural: this asserts what the runtime cannot
# reach, which no passing test would reveal. The cheapest way to lose the
# property is a crate added "just for a helper" that modules start
# mounting from.
set -uo pipefail
cd "$(dirname "$0")/../.."

failed=0
ok() { echo "  ok: $1"; }
no() {
  echo "  FAIL: $1" >&2
  failed=1
}

# 1. No crate but the harness, and no host source tree.
crates=$(find . -name Cargo.toml -not -path './target/*' -not -path './deps/*' \
  -not -path './tests/harness/Cargo.toml' | tr '\n' ' ')
[ -z "$crates" ] && ok "no cargo crate but the test harness" || no "cargo crates: $crates"
[ ! -d src ] && [ ! -d crates ] && ok "no host source tree" || no "src/ or crates/ exists"

# 2. Nothing declares a binary.
bins=$(find . -name Cargo.toml -not -path './target/*' -not -path './deps/*' \
  -exec grep -l '\[\[bin\]\]' {} + 2>/dev/null | tr '\n' ' ')
[ -z "$bins" ] && ok "nothing builds a cargo binary" || no "[[bin]] in: $bins"

# 3. Modules mount only shared sources and the fluxor SDK: every #[path]
#    and include! resolves under modules/common or target/fluxor.
roots=$(grep -rhoE '(#\[path = "|include!\(")[^"]+"' modules --include=*.rs |
  sed -E 's/^(#\[path = "|include!\(")//; s/"$//' | sed 's|^\(\.\./\)*||' |
  cut -d/ -f1 | sort -u | tr '\n' ' ')
case "$roots" in
  "common target " | "target common ") ok "modules mount only modules/common and the fluxor SDK" ;;
  *) no "modules mount from unexpected roots: '$roots'" ;;
esac

# 4. The harness is mounted by nothing that ships.
reach=$(grep -rlE '(#\[path|include!).*tests/' modules --include=*.rs | tr '\n' ' ')
[ -z "$reach" ] && ok "no module mounts test code" || no "modules mounting tests/: $reach"

# 5. No script builds or runs a crate: the gates drive built artefacts.
#    (The harness itself runs under `cargo test`.) Comment lines are
#    allowed, and this gate names what it forbids.
execs=$(grep -nE 'cargo (run|build|install)' tools/ci/*.sh tools/e2e/*.sh Makefile 2>/dev/null |
  grep -v 'shipping_surface' | grep -vE '^[^:]*:[0-9]+: *#' | wc -l)
[ "$execs" = 0 ] && ok "no script builds or runs a crate" || no "$execs script line(s) build or run a crate"

# 6. modules/common holds sources and nothing else.
strays=$(find modules/common -type f -not -name '*.rs' | head -3 | tr '\n' ' ')
[ -z "$strays" ] && ok "modules/common holds only sources" || no "non-source files in modules/common: $strays"

# 7. The operator applet and every module a bundle runs are built, and
#    the applet is a real PIC object rather than a stub.
fmods=target/fluxor/bcm2712/modules
sz=$(stat -c %s "$fmods/loam_cli.fmod" 2>/dev/null || echo 0)
[ "$sz" -gt 4096 ] && ok "loam_cli.fmod is built ($sz bytes)" ||
  no "loam_cli.fmod is ${sz} bytes — run 'fluxor modules build --all'"
missing=""
for m in admin_gate admin_router namespace_router object_index body_store \
  body_fanout_router object_provider loam_volume loam_cli; do
  [ -s "$fmods/$m.fmod" ] || missing="$missing $m"
done
[ -z "$missing" ] && ok "every module the bundles run is built" || no "not built:$missing"

if [ "$failed" = 0 ]; then
  echo "shipping_surface: ok"
else
  echo "shipping_surface: FAILED" >&2
fi
exit "$failed"
