"""
experiments/model_b.py
======================
Model B: "does this window of file activity look like an attack?"

Inputs per tick: the rate, extension and spread sub-scores already in the
trace (never absolute time).  Label: 1 if the tick falls between the
simulator's ATTACK_START and ATTACK_END markers, else 0 (every tick of a
benign workload, and ticks of an attack run outside the window, are 0).

  python experiments/model_b.py --train experiments/results/batch-dev

Training data: development seeds only, and NOT the held-out attack mode
(rename_random).  Held-out seeds (4-8) are evaluated once, in
compare_policies.py, after this script has fixed the models.  Models:
logistic regression (used by policy P2) and a depth-3 decision tree.  No
hyper-parameter search.

Limits
  * Ticks within one run are near-duplicates and strongly autocorrelated, so
    per-tick scores here are descriptive; the claim-bearing numbers are
    per-run (compare_policies.py).
  * Attack ticks all come from the simulator, whose rate/rename/spread
    behaviour is our model of ransomware, not measured ransomware.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_recall_fscore_support
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier, export_text

from _runs import ROOT, load_runs

HELDOUT_MODE = "rename_random"
FEATURES = ["rate", "extension", "spread"]
OUT = ROOT / "experiments" / "results"
MODELS = ROOT / "experiments" / "data" / "models"


def tick_matrix(runs):
    X, y = [], []
    for r in runs:
        for t in r["ticks"]:
            X.append([t[f] for f in FEATURES])
            y.append(t["label"])
    return np.array(X), np.array(y)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", type=Path, required=True, help="batch results dir (dev seeds)")
    a = ap.parse_args()
    runs = load_runs(a.train)
    assert all(r["config"]["split"] == "dev" for r in runs), "training data must be dev seeds only"
    train = [r for r in runs if not (r["config"]["kind"] == "attack"
                                     and r["config"]["name"] == HELDOUT_MODE)]
    X, y = tick_matrix(train)

    models = {
        "logreg": make_pipeline(StandardScaler(),
                                LogisticRegression(max_iter=1000, class_weight="balanced")),
        "tree_depth3": DecisionTreeClassifier(max_depth=3, class_weight="balanced", random_state=0),
    }
    summary = {"train_dir": str(a.train), "excluded_mode": HELDOUT_MODE, "features": FEATURES,
               "train_runs": len(train), "train_ticks": int(len(y)), "train_positive_ticks": int(y.sum()),
               "train_set_fit": {}}
    MODELS.mkdir(parents=True, exist_ok=True)
    for n, m in models.items():
        m.fit(X, y)
        p, r, f, _ = precision_recall_fscore_support(y, m.predict(X), average="binary", zero_division=0)
        summary["train_set_fit"][n] = {"precision": round(float(p), 3), "recall": round(float(r), 3),
                                       "f1": round(float(f), 3)}
        joblib.dump({"model": m, "features": FEATURES}, MODELS / f"model_b_{n}.joblib")
    lr = models["logreg"][-1]
    summary["logreg_coefficients_standardised"] = dict(zip(FEATURES, [round(float(c), 3) for c in lr.coef_[0]]))
    summary["tree"] = export_text(models["tree_depth3"], feature_names=FEATURES)
    (OUT / "model_b_fit.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
