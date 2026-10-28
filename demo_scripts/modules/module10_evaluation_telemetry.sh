#!/usr/bin/env bash
# =============================================================================
# CTRR — Module 10: Evaluation & Telemetry (~50% complete)
# =============================================================================
# WHAT THIS DEMO MEANS: the highest-leverage design decision in the whole
# project — every intermediate value from a live run is logged, so tuning
# the policy later is "re-score a saved trace in milliseconds," not
# "re-run the VM experiment." Reuses the trace already produced by the
# Section 0.2 end-to-end attack run — run that first if /tmp/ctrr-trace.jsonl
# doesn't exist yet.
#
# WHAT THE OUTPUT MEANS:
#   wc -l / head -3        -> raw JSONL schema: one object per event, with
#                              every raw + derived value and the fused score
#   replay --hard 0.95      -> stricter policy replayed OFFLINE against the
#                              SAME recorded trace, no filesystem re-run.
#                              Expected: 0 triggers (stays SUSPECT the whole
#                              time, never escalates at this threshold)
#   replay (default policy) -> should match the LIVE run exactly: 1 trigger,
#                              at the same tick / same % into the trace
#
# This is the concrete answer to "aren't your thresholds arbitrary?" —
# they're swept and compared against a fixed, reproducible recorded trace,
# not hand-picked per demo run.
#
# KNOWN GAP: no benign-workload harness yet (tar/restic/ffmpeg/git/rsync/
# build), no ground-truth ATTACK_START/ATTACK_END markers in the trace, no
# Phase-4 experiment matrix (FP/FN table, detection latency, overhead).
# These are Phase 4 work, explicitly scoped for after this demo.
# =============================================================================
set -uo pipefail
# Repo root, found from this script's own location so a fresh clone works anywhere.
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TRACE=/tmp/ctrr-trace.jsonl
cd "$PROJECT_ROOT" || { echo "Set PROJECT_ROOT at the top of this script."; exit 1; }

if [ ! -s "$TRACE" ]; then
  echo "No trace found at $TRACE — run the Section 0.2 attack demo first"
  echo "(demo_00_end_to_end_1window.sh, or demo_00a/00b) to generate one."
  exit 1
fi

echo "### Raw trace ###"
wc -l "$TRACE"
head -3 "$TRACE"

echo
echo "### Replay under a STRICTER policy (offline, same trace) — expect 0 triggers ###"
python tools/replay_trace.py "$TRACE" --hard 0.95 --quiet

echo
echo "### Replay under the actual demo policy — should match the live run exactly ###"
python tools/replay_trace.py "$TRACE" --quiet
