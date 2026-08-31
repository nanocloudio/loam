#!/usr/bin/env bash
# Limit-register guard.
#
# The register in docs/limit_register.md is only worth keeping if it
# cannot fall behind the source. Two invariants:
#
#   1. EVERY ceiling-shaped constant in modules/ appears in the
#      register. A ceiling that exists in source but not here is a
#      ceiling nobody has decided a value for on either deployment
#      class — the drift that lets a wire accept a key wider than
#      the arena can store.
#
#   2. NO capacity constant outside loam_limits.rs is selected by
#      `cfg(target_os)`. Profile selection lives in exactly one file;
#      a second one is drift that makes the register's per-profile
#      columns a lie.
#
# Wired as `[ci.test] scripts` in fluxor.toml.
set -euo pipefail
cd "$(dirname "$0")/../.."

REGISTER=docs/limit_register.md
LIMITS=modules/common/mechanics/loam_limits.rs
fail=0

[[ -f $REGISTER ]] || { echo "limit_guard: missing $REGISTER"; exit 1; }
[[ -f $LIMITS ]] || { echo "limit_guard: missing $LIMITS"; exit 1; }

# ── (1) every ceiling-shaped const is registered ──────────────────
#
# Ceiling-shaped means the name says it bounds something: MAX_*, or a
# *_MAX / *_CAP / *_SLOTS / *_SESSIONS / *_PER_STEP suffix. The match
# is on the shape rather than on a prefix, so a name like NS_SUB_MAX
# cannot slip past it. Opcode, status, error, magic and offset
# constants are not ceilings and are excluded by shape, not by an
# allowlist that would need maintaining.
missing=()
while IFS= read -r name; do
  # A row is present if the symbol appears in the register, either
  # bare (`MAX_BODY`) or module-qualified (`loam_wire::MAX_STRING`).
  grep -qE "\`([A-Za-z0-9_]+::)?${name}\`|\`[^\`]*\b${name}\b[^\`]*\`" "$REGISTER" \
    || missing+=("$name")
done < <(
  grep -rhoE '^[[:space:]]*(pub )?const (MAX_[A-Z0-9_]+|[A-Z0-9_]+_(MAX|CAP|SLOTS|SESSIONS|PER_STEP))[[:space:]]*:' \
    --include='*.rs' modules/ \
  | sed -E 's/.*const ([A-Z0-9_]+)[[:space:]]*:.*/\1/' \
  | sort -u
)

if ((${#missing[@]})); then
  echo "limit_guard: ceiling(s) in modules/ with no row in $REGISTER:"
  printf '  %s\n' "${missing[@]}"
  echo "  Add a row naming the symbol, its source, its value per"
  echo "  profile, and what binds instead — or rename the constant if"
  echo "  it is not really a ceiling."
  fail=1
fi

# ── (2) profile selection lives in exactly one file ───────────────
strays=$(grep -rln 'cfg(target_os = "none")' --include='*.rs' modules/ \
         | grep -v "^${LIMITS}$" || true)
if [[ -n $strays ]]; then
  echo "limit_guard: cfg(target_os) outside $LIMITS:"
  printf '  %s\n' $strays
  echo "  Move the profiled value into the register's one selector."
  fail=1
fi

# ── (3) the register's own invariant, restated ────────────────────
#
# Accepted implies storable: the wires must derive their key ceilings
# from the register rather than declaring their own number. A literal
# integer assigned to MAX_STRING is exactly the drift that makes a
# wire accept a key the arena cannot store.
literal=$(grep -rnE '^[[:space:]]*pub const MAX_STRING[[:space:]]*:[^=]*=[[:space:]]*[0-9]' \
          --include='*.rs' modules/ || true)
if [[ -n $literal ]]; then
  echo "limit_guard: a wire declares its own key ceiling:"
  echo "$literal" | sed 's/^/  /'
  echo "  Derive it from super::limits instead."
  fail=1
fi

if ((fail)); then
  exit 1
fi
echo "limit_guard: ok — every ceiling registered, one profile selector"
