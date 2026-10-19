#!/usr/bin/env bash
# =============================================================================
# CTRR -- Demo part 4: the SAME recorded traces replayed under P0 and P2
# =============================================================================
# P0 = Shannon-delta entropy + hand-written scores (what the live monitor uses)
# P2 = Model A probability in the entropy slot + Model B probability in the
#      behavioural slot, weights 0.5 / 0.5
# The arbiter (accumulator, thresholds, typed quorum, cooldown) is identical.
# Only the sub-scores feeding fuse() differ, so any difference in the outcome
# comes from the inputs, not from retuning.
#
# Traces are DEVELOPMENT-seed (seed 1) runs recorded earlier, so this demo
# does not touch the held-out seeds 4-8. Nothing is re-recorded: the monitor
# is not running, this is pure offline re-scoring.
#
# Usage:  bash demo_scripts/demo_04_replay_p0_vs_p2.sh [RUN_DIR ...]
#   RUN_DIR defaults to three runs under experiments/results/batch-dev:
#   attack-baseline-s1, attack-layout_nested-s1, benign-unzip_flat-s1
# =============================================================================
set -uo pipefail
PROJECT_ROOT="/home/adi/Desktop/Projects/CPTR"
cd "$PROJECT_ROOT" || exit 1
source .venv/bin/activate

RUNS=("$@")
if [ ${#RUNS[@]} -eq 0 ]; then
  B=experiments/results/batch-dev
  RUNS=("$B/attack-baseline-s1" "$B/attack-layout_nested-s1" "$B/benign-unzip_flat-s1")
fi

python - "${RUNS[@]}" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, "experiments")
import joblib
from _runs import ROOT, load_runs
from compare_policies import run_outcome, MODELS

ma = joblib.load(MODELS / "model_a_rf.joblib")["model"]
mb = joblib.load(MODELS / "model_b_logreg.joblib")["model"]

def show(o):
    if not o["triggered"]:
        return "no TRIGGER"
    if "files_before" not in o:
        return "TRIGGER (benign run: false trigger)"
    return (f"TRIGGER after {o['latency_ms']:.0f} ms, "
            f"{o['files_before']} files overwritten ({o['files_before_pct']:.0f}% of corpus)")

for d in sys.argv[1:]:
    d = Path(d)
    # load_runs globs <dir>/*/config.json, so give it the parent and pick the run
    run = next(r for r in load_runs(d.parent) if r["dir"].name == d.name)
    c = run["config"]
    print("=" * 70)
    print(f"{d.name}   ({c['kind']}, mode={c['name']}, corpus={c['corpus_files']} files)")
    print("=" * 70)
    for p in ("P0", "P2"):
        o = run_outcome(run, p, ma, mb)
        if c["kind"] == "benign":
            print(f"  {p}: " + ("FALSE TRIGGER" if o["triggered"] else "no TRIGGER (correct)"))
        else:
            print(f"  {p}: {show(o)}")
    print()
PY
