#!/usr/bin/env bash
# Shadow-checkout guard (standards/test-tracking.md §7): tests/ and
# examples/ are shadow-tracked (.git-shadow/), so a runner holding only
# the primary repo has zero files there — `cargo test --tests` (the
# pic_* PIC harness suites) would pass vacuously and the s3_driven e2e
# would have no graph to boot. Hard-fail instead. Wired as
# `[ci.test] scripts` in fluxor.toml (CI phase 3.5).
set -euo pipefail
cd "$(dirname "$0")/../.."
fail=0
for d in tests examples; do
  if [ -z "$(ls -A "$d" 2>/dev/null)" ]; then
    echo "shadow_guard: $d/ is empty or absent — the shadow-tracked tree is" >&2
    echo "not materialised on this machine (standards/test-tracking.md §7)." >&2
    fail=1
  fi
done
exit "$fail"
