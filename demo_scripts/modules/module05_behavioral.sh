#!/usr/bin/env bash
# =============================================================================
# CTRR — Module 5: Behavioral Extraction (100% complete)
# =============================================================================
# WHAT THIS DEMO MEANS: the other three signals besides entropy — write
# rate, extension-change uniformity, directory spread — each independently
# scored in [0,1], each robust to a single benign action on its own.
#
# WHAT THE OUTPUT MEANS:
#   27 passing tests covering: sliding-window eviction, ceiling clamping,
#   exclusion of non-CLOSE_WRITE events, and active_signals() — the exact
#   function the quorum gate (Module 7) reads to decide "how many
#   independent signals are currently lit up."
#
# For a LIVE number instead of a test result, re-run the Section 0.2
# end-to-end demo and read the rate= / ext= fields printed on the
# [SUSPECT] / [TRIGGER] lines — that's this module's live output.
# =============================================================================
set -uo pipefail
# Repo root, found from this script's own location so a fresh clone works anywhere.
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT" || { echo "Set PROJECT_ROOT at the top of this script."; exit 1; }

python -m pytest tests/test_extractor.py -k "Rate or Extension or Spread or SubScores" -v
