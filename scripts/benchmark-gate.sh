#!/usr/bin/env bash
# Copyright The Ratify Authors.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# benchmark-gate.sh fails when a benchmark regresses beyond a threshold.
#
# It compares two raw `go test -bench` result files using benchstat and then
# inspects the "vs base" delta column. Any statistically-significant increase
# (worse sec/op, B/op, or allocs/op) above THRESHOLD_PCT fails the gate.
#
# Usage:
#   scripts/benchmark-gate.sh <base.txt> <head.txt> [threshold_pct]
#
# Environment:
#   THRESHOLD_PCT  Maximum allowed regression percentage (default: 20).
#   EXCLUDE_PATTERN  Extended regex of benchmark row names to exclude from the
#                    gate (e.g. observability-only benchmarks). Excluded rows
#                    still appear in the printed comparison but never fail the
#                    gate. Default: "ValidateArtifact".

set -euo pipefail

BASE_FILE="${1:?usage: benchmark-gate.sh <base.txt> <head.txt> [threshold_pct]}"
HEAD_FILE="${2:?usage: benchmark-gate.sh <base.txt> <head.txt> [threshold_pct]}"
THRESHOLD_PCT="${3:-${THRESHOLD_PCT:-20}}"
EXCLUDE_PATTERN="${EXCLUDE_PATTERN:-ValidateArtifact}"

if ! command -v benchstat >/dev/null 2>&1; then
  echo "benchstat not found on PATH. Install with: go install golang.org/x/perf/cmd/benchstat@latest" >&2
  exit 2
fi

COMPARISON="$(benchstat "${BASE_FILE}" "${HEAD_FILE}")"

echo "## Benchmark comparison (threshold: +${THRESHOLD_PCT}%)"
echo '```'
echo "${COMPARISON}"
echo '```'

# Parse the "vs base" delta column. benchstat prints deltas like "+21.34%" or
# "-5.10%"; "~" means the change was not statistically significant. We flag any
# positive delta (a regression for sec/op, B/op and allocs/op) above threshold.
# Rows whose name matches EXCLUDE_PATTERN are skipped (non-gating signals).
regressions="$(
  awk -v threshold="${THRESHOLD_PCT}" -v exclude="${EXCLUDE_PATTERN}" '
    # Match a positive delta: either a finite "+12.34%" or "+Inf%". benchstat
    # emits +Inf% when the base metric is 0 and the head metric is > 0 (e.g.
    # allocs/op going from 0 to non-zero), which is always a real regression.
    match($0, /[+]([0-9]+(\.[0-9]+)?|Inf)%/) {
      # Skip the geomean aggregate row: it is a summary across all benchmarks
      # (including excluded ones), not an individual result to gate on.
      if ($1 == "geomean") {
        next
      }
      if (exclude != "" && $1 ~ exclude) {
        next
      }
      delta = substr($0, RSTART + 1, RLENGTH - 2)
      if (delta == "Inf") {
        print "  - " $1 ": +Inf% (limit +" threshold "%)"
        next
      }
      pct = delta + 0
      if (pct > threshold) {
        print "  - " $1 ": +" pct "% (limit +" threshold "%)"
      }
    }
  ' <<<"${COMPARISON}"
)"

if [[ -n "${regressions}" ]]; then
  echo ""
  echo "Benchmark regressions detected:" >&2
  echo "${regressions}" >&2
  exit 1
fi

echo ""
echo "No benchmark regressions above +${THRESHOLD_PCT}%."
