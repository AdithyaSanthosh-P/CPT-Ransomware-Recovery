"""
experiments/compare_policies.py
===============================
Replay recorded runs under policies P0, P1, P2 and tabulate per-run outcomes.

  python experiments/compare_policies.py --runs experiments/results/batch-dev --label dev

P0  Shannon delta + hand-written scores, weights 0.40/0.30/0.15/0.15
P1  Model A probability in the entropy slot
P2  Model A + Model B probabilities, weights 0.5/0.5
(see tools/replay_trace.py).  The arbiter, thresholds and typed quorum are
the same in all three and are NOT retuned per policy.

Judged per run, not per tick.  For each policy:
  detection rate      attack runs with a TRIGGER at or after ATTACK_START
  latency             ATTACK_START -> TRIGGER tick, median over detected runs
  files before        distinct files with a write tick in the attack window up
                      to and including the TRIGGER tick (files already
                      overwritten when the snapshot is requested), median,
                      and as a percent of the corpus
  false triggers      benign runs with any TRIGGER
Monitor CPU overhead is measured live (config.json), not by replay, so it is
the same for every policy: monitor CPU seconds / wall seconds.

Held-out seeds (4-8) must be evaluated once, after the models and policy are
fixed.  The script records the seeds it saw; do not iterate on them.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
from collections import defaultdict
from pathlib import Path

import joblib

from _runs import ROOT, load_runs
import replay_trace as R

MODELS = ROOT / "experiments" / "data" / "models"
OUT = ROOT / "experiments" / "results"


def run_outcome(run, policy, ma, mb):
    ticks = run["ticks"]
    s = R.replay(ticks, quiet=True, policy=policy, model_a=ma, model_b=mb)
    ft = s["first_trigger_tick"]
    out = {"triggered": ft is not None}
    if run["window"] is None or ft is None:
        return out
    start, _ = run["window"]
    t_ts = ticks[ft]["mono_ts"]
    if t_ts < start:
        out["triggered"] = False          # before the attack began: not a detection
        out["false_trigger_before_attack"] = True
        return out
    in_win = [t for t in ticks[: ft + 1] if t["label"] == 1]
    files = len({t["path"] for t in in_win})
    out.update(latency_ms=(t_ts - start) / 1e6, files_before=files,
               files_before_pct=100.0 * files / run["config"]["corpus_files"])
    return out


def med(xs):
    return round(statistics.median(xs), 1) if xs else None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=Path, required=True)
    ap.add_argument("--label", required=True, help="output suffix, e.g. dev or heldout")
    ap.add_argument("--model-b", default="logreg", choices=("logreg", "tree_depth3"))
    a = ap.parse_args()

    ma = joblib.load(MODELS / "model_a_rf.joblib")["model"]
    mb = joblib.load(MODELS / f"model_b_{a.model_b}.joblib")["model"]
    runs = load_runs(a.runs)
    per_run = []
    for run in runs:
        c = run["config"]
        row = {"run": f"{c['kind']}-{c['name']}-s{c['seed']}", "kind": c["kind"],
               "name": c["name"], "seed": c["seed"], "split": c["split"],
               "cpu_fraction": c["monitor_cpu_seconds"] / c["wall_seconds"]}
        for p in R.POLICIES:
            row[p] = run_outcome(run, p, ma, mb)
        per_run.append(row)

    agg = {}
    for p in R.POLICIES:
        att = [r for r in per_run if r["kind"] == "attack"]
        ben = [r for r in per_run if r["kind"] == "benign"]
        det = [r[p] for r in att if r[p]["triggered"]]
        agg[p] = {
            "attack_runs": len(att), "detected": len(det),
            "detection_rate": round(len(det) / len(att), 3) if att else None,
            "median_latency_ms": med([d["latency_ms"] for d in det]),
            "median_files_before": med([d["files_before"] for d in det]),
            "median_files_before_pct": med([d["files_before_pct"] for d in det]),
            "benign_runs": len(ben), "false_triggers": sum(r[p]["triggered"] for r in ben),
        }
    by_mode = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    for r in per_run:
        if r["kind"] == "attack":
            for p in R.POLICIES:
                by_mode[r["name"]][p][0] += r[p]["triggered"]
                by_mode[r["name"]][p][1] += 1
    cpu = {k: round(statistics.mean(r["cpu_fraction"] for r in per_run if r["kind"] == k), 3)
           for k in ("attack", "benign") if any(r["kind"] == k for r in per_run)}

    result = {
        "command": f"python experiments/compare_policies.py --runs {a.runs} --label {a.label}"
                   f" --model-b {a.model_b}",
        "git_commit": subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                                     capture_output=True, text=True).stdout.strip(),
        "seeds": sorted({r["seed"] for r in per_run}), "split": sorted({r["split"] for r in per_run}),
        "aggregate": agg, "by_attack_mode": {m: {p: f"{v[0]}/{v[1]}" for p, v in d.items()}
                                              for m, d in by_mode.items()},
        "monitor_cpu_fraction_mean": cpu, "runs": per_run,
    }
    (OUT / f"policy_comparison_{a.label}.json").write_text(json.dumps(result, indent=2) + "\n")
    md = render(result)
    (OUT / f"policy_comparison_{a.label}.md").write_text(md)
    print(md)


def render(r) -> str:
    L = [f"# Policy comparison ({', '.join(r['split'])} seeds {r['seeds']})", "",
         f"Command: `{r['command']}`  |  code at {r['git_commit']}  |  per-run data: JSON", "",
         "| policy | detected / attack runs | median latency ms | median files overwritten before snapshot | % of corpus | false triggers / benign runs |",
         "|---|---|---|---|---|---|"]
    for p, a in r["aggregate"].items():
        L.append(f"| {p} | {a['detected']}/{a['attack_runs']} | {a['median_latency_ms']} | "
                 f"{a['median_files_before']} | {a['median_files_before_pct']} | "
                 f"{a['false_triggers']}/{a['benign_runs']} |")
    L += ["", "## Detections by attack mode", "", "| mode | P0 | P1 | P2 |", "|---|---|---|---|"]
    for m, d in r["by_attack_mode"].items():
        L.append(f"| {m} | {d['P0']} | {d['P1']} | {d['P2']} |")
    L += ["", f"Monitor CPU (live, mean CPU seconds / wall seconds): {r['monitor_cpu_fraction_mean']}", ""]
    return "\n".join(L)


if __name__ == "__main__":
    main()
