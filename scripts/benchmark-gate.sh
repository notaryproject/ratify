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
# "-5.10%"; "~" means the change was not statistically significant.
#
# The gate is unit-aware: benchstat groups results by metric and prints the unit
# in each section's "vs base" header (e.g. sec/op, B/op, allocs/op, MB/s). For
# "lower-is-better" units (anything ending in /op) a positive delta is a
# regression; for "higher-is-better" throughput units (ending in /s, e.g. MB/s
# from b.SetBytes) a negative delta is the regression instead. Rows whose name
# matches EXCLUDE_PATTERN are skipped (non-gating signals).
regressions="$(
  awk -v threshold="${THRESHOLD_PCT}" -v exclude="${EXCLUDE_PATTERN}" '
    # Track the current metric/unit from each section'"'"'s "vs base" header so we
    # know which direction counts as a regression for the rows that follow.
    /vs base/ {
      unit = ""
      for (i = 1; i <= NF; i++) {
        if ($i ~ /\/(op|s)$/) {
          unit = $i
          break
        }
      }
      # Throughput units (MB/s, B/s, op/s) are better when higher.
      higher_is_better = (unit ~ /\/s$/)
      next
    }
    # Match a signed delta: a finite "+12.34%"/"-5.10%" or "+Inf%"/"-Inf%".
    # benchstat emits +Inf% when the base metric is 0 and the head metric is > 0
    # (e.g. allocs/op going from 0 to non-zero).
    match($0, /[+-]([0-9]+(\.[0-9]+)?|Inf)%/) {
      # Skip the geomean aggregate row: it is a summary across all benchmarks
      # (including excluded ones), not an individual result to gate on.
      if ($1 == "geomean") {
        next
      }
      if (exclude != "" && $1 ~ exclude) {
        next
      }
      sign = substr($0, RSTART, 1)
      delta = substr($0, RSTART + 1, RLENGTH - 2)
      # A regression is an increase for lower-is-better units and a decrease for
      # higher-is-better units; the opposite direction is an improvement.
      if (higher_is_better) {
        if (sign != "-") {
          next
        }
      } else {
        if (sign != "+") {
          next
        }
      }
      label = (unit != "") ? $1 " (" unit ")" : $1
      if (delta == "Inf") {
        print "  - " label ": " sign "Inf% (limit " threshold "%)"
        next
      }
      pct = delta + 0
      if (pct > threshold) {
        print "  - " label ": " sign pct "% (limit " threshold "%)"
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
