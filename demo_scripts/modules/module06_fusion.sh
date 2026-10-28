#!/usr/bin/env bash
# =============================================================================
# CTRR — Module 6: Fusion Engine (~85% complete)
# =============================================================================
# WHAT THIS DEMO MEANS: proves the weighted-sum policy — pure function, no
# runtime ML, fully auditable — actually separates benign from malicious
# sub-score inputs.
#
# WHAT THE OUTPUT MEANS (expected values):
#   Benign edit        -> ~0.0575  (low across all four signals)
#   Compression (zip)   -> ~0.2775  (entropy alone is elevated, but nothing
#                                    else is, so fusion keeps it well below
#                                    threshold — the "isn't zip suspicious?"
#                                    rebuttal in one number)
#   Ransomware attack   -> ~0.772   (all four signals elevated together)
#
# Weights (entropy=0.40, rate=0.30, extension=0.15, spread=0.15) are named
# constants in src/ctrr/scorer.py, not hidden model weights — point this
# out if asked "isn't this just ML with extra steps?"
# =============================================================================
set -uo pipefail
# Repo root, found from this script's own location so a fresh clone works anywhere.
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT" || { echo "Set PROJECT_ROOT at the top of this script."; exit 1; }

python -c "
from ctrr.extractor import SubScores
from ctrr.scorer import fuse

print('Benign edit       ->', fuse(SubScores(entropy=0.05, rate=0.10, extension=0.0,  spread=0.05)))
print('Compression (zip)  ->', fuse(SubScores(entropy=0.60, rate=0.10, extension=0.0,  spread=0.05)))
print('Ransomware attack  ->', fuse(SubScores(entropy=0.88, rate=1.00, extension=0.20, spread=0.60)))
"
