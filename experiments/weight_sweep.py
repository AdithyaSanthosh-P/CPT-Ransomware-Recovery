"""
experiments/weight_sweep.py
===========================
Sensitivity of policy P2 to the Model A / Model B fusion weights, replayed on
saved DEVELOPMENT traces only (seeds 1-3).  Nothing is re-run and the
held-out seeds are not read.

  python experiments/weight_sweep.py --runs experiments/results/batch-dev --label dev

fused = w_A * P(Model A) + (1 - w_A) * P(Model B); thresholds, decay, typed
quorum and cooldown are the live ones and do not change.  P2's 0.5/0.5 is the
midpoint of this sweep.

Caveats
  * Model B was trained on these dev runs, so its probabilities here are
    in-sample and flatter every row.  The sweep shows how SENSITIVE the
    outcome is to the weights, not which weights generalise.
  * An undetected attack run counts as the whole corpus lost (60/60).
"""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path

import joblib

from _runs import ROOT, load_runs
import replay_trace as R
from compare_policies import MODELS, run_outcome

OUT = ROOT / "experiments" / "results"
GRID = (0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=Path, required=True)
    ap.add_argument("--label", required=True)
    a = ap.parse_args()
    ma = joblib.load(MODELS / "model_a_rf.joblib")["model"]
    mb = joblib.load(MODELS / "model_b_logreg.joblib")["model"]
    runs = load_runs(a.runs)
    att = [r for r in runs if r["config"]["kind"] == "attack"]
    ben = [r for r in runs if r["config"]["kind"] == "benign"]
    corpus = att[0]["config"]["corpus_files"]
    saved = dict(R._P2_WEIGHTS)
    rows = []
    try:
        for wa in GRID:
            R._P2_WEIGHTS.update(_WEIGHT_ENTROPY=wa, _WEIGHT_RATE=round(1 - wa, 6))
            ao = [run_outcome(r, "P2", ma, mb) for r in att]
            bo = [run_outcome(r, "P2", ma, mb) for r in ben]
            lost = [o["files_before"] if o["triggered"] else corpus for o in ao]
            det = [o for o in ao if o["triggered"]]
            rows.append({
                "w_A": wa, "w_B": round(1 - wa, 6),
                "detected": len(det), "attack_runs": len(att),
                "median_files_lost_all": statistics.median(lost),
                "median_latency_ms_detected": round(statistics.median(o["latency_ms"] for o in det), 1) if det else None,
                "false_triggers": sum(o["triggered"] for o in bo), "benign_runs": len(bo),
                "missed_modes": sorted({r["config"]["name"] for r, o in zip(att, ao) if not o["triggered"]}),
            })
    finally:
        R._P2_WEIGHTS.clear(); R._P2_WEIGHTS.update(saved)
    cmd = f"python experiments/weight_sweep.py --runs {a.runs} --label {a.label}"
    (OUT / f"weight_sweep_{a.label}.json").write_text(json.dumps({"command": cmd, "rows": rows}, indent=2) + "\n")
    L = [f"# P2 weight sweep ({a.label} traces)", "", f"Command: `{cmd}`", "",
         "fused = w_A x Model A + w_B x Model B, thresholds and typed quorum unchanged. "
         "Dev traces only; Model B was trained on them, so every row is flattered (sensitivity, not generalisation). "
         f"Files lost counts a miss as {corpus}/{corpus}.", "",
         "| w_A | w_B | detected | median files lost (all runs) | median latency ms (detected) | false triggers | modes with a miss |",
         "|---|---|---|---|---|---|---|"]
    for r in rows:
        L.append(f"| {r['w_A']} | {r['w_B']} | {r['detected']}/{r['attack_runs']} | {r['median_files_lost_all']} | "
                 f"{r['median_latency_ms_detected']} | {r['false_triggers']}/{r['benign_runs']} | "
                 f"{', '.join(r['missed_modes']) or '-'} |")
    L.append("")
    (OUT / f"weight_sweep_{a.label}.md").write_text("\n".join(L))
    print("\n".join(L))


if __name__ == "__main__":
    main()
