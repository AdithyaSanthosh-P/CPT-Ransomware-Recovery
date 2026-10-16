#!/usr/bin/env bash
# =============================================================================
# CTRR — Module 4: Entropy Extraction (~90% complete)
# =============================================================================
# WHAT THIS DEMO MEANS: empirical justification for the project's central
# design decision — score entropy DELTA vs. per-path baseline, not absolute
# entropy — with real numbers, not just an assertion.
#
# WHAT THE OUTPUT MEANS: walk through the 4 scenarios in bench_entropy.md.
#   - A benign compressed file already sits near max entropy. An
#     absolute-entropy detector false-positives on it.
#   - The DELTA signal stays near zero for that same file, because the
#     file's own baseline is already high.
#   - A ransomware overwrite shows a large delta from a low baseline —
#     that gap is the signal the project actually scores on.
#   - The unit-test run at the bottom is the same claim as a pass/fail gate.
# =============================================================================
set -uo pipefail
PROJECT_ROOT="/home/adi/Desktop/Projects/CPTR"
cd "$PROJECT_ROOT" || { echo "Set PROJECT_ROOT at the top of this script."; exit 1; }

echo "### Entropy benchmark (4 scenarios) ###"
python experiments/bench_entropy.py

echo
echo "### Benchmark report ###"
cat experiments/results/bench_entropy.md

echo
echo "### Entropy extractor unit tests ###"
python -m pytest tests/test_extractor.py -k Entropy -v
