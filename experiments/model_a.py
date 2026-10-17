"""
experiments/model_a.py
======================
Model A: "is this file's content encrypted?"  Train on NapierOne, compare with
the current Shannon-delta rule on held-out sequence numbers.

  python experiments/model_a.py            # writes experiments/results/model_a.{json,md}

Data (experiments/data/napierone/, from tools/fetch_napierone.py)
  positives : the seven ransomware subsets (DHARMA MAZE NETWALKER NOTPETYA
              PHOBOS RYUK SODINOKIBI), every file labelled "encrypted"
  negatives : the original document/image subsets (DOC DOCX XLS XLSX PDF PPTX
              JPG) and the archive subsets (ZIP-DEFLATE GZIP 7ZIP-LZMA)
Features come from the 4 KiB head + 4 KiB mid sample the extractor already
reads (src/ctrr/features.py).

Split: by NapierOne sequence number.  An original, its archives and its
encrypted copies share a number, so each number goes entirely to train or
entirely to test; otherwise the same document would sit on both sides.  The
test set is scored once, after the models are fixed (no tuning on it).
Models use scikit-learn defaults except where stated; there is no
hyper-parameter search, so there is nothing to overfit to the test set.

Baseline: the Shannon rule as the live system uses it.  For an encrypted file
with an original of the same sequence number and type, delta = H(encrypted) -
H(original); the rule says "encrypted" when delta/4 > 0.1, the same 0.1
"active signal" level the quorum uses (_QUORUM_SIGNAL_THRESHOLD).  Files with
no original available get no baseline prediction and are excluded from the
baseline columns (counted in `n`).

Limits stated up front
  * Baseline negatives: an unchanged original has delta 0 against itself, so
    the rule is right on every original by construction.  Its false-positive
    behaviour is shown on a separate, constructed scenario: an archive written
    over a plaintext document of the same sequence number (baseline = that
    document).  Model A does not need a baseline.
  * NapierOne labels a whole family "encrypted"; some family files have a
    plaintext head or mid window (see the low 5th percentile of entropy in the
    per-family recall), so recall below 1.0 is partly label noise, not
    necessarily model error.
  * One dataset, one collection method: nothing here says the model transfers
    to ransomware outside these seven families (see the held-out-family table).
"""

from __future__ import annotations

import json
import random
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))
from ctrr.extractor import _read_sample  # noqa: E402
from ctrr.features import FEATURE_NAMES, sample_features  # noqa: E402

DATA = ROOT / "experiments" / "data" / "napierone"
OUT = ROOT / "experiments" / "results"
FAMILIES = ["DHARMA", "MAZE", "NETWALKER", "NOTPETYA", "PHOBOS", "RYUK", "SODINOKIBI"]
ORIGINALS = ["DOC", "DOCX", "XLS", "XLSX", "PDF", "PPTX", "JPG"]
ARCHIVES = ["ZIP-DEFLATE", "GZIP", "7ZIP-LZMA"]
SPLIT_SEED = 20261017
TEST_FRACTION = 0.3
SHANNON_ACTIVE = 0.1 * 4.0      # live rule: delta/_ENTROPY_DELTA_MAX > 0.1
_KEY = re.compile(r"^(\d+)-([A-Za-z0-9]+)")


def _key(name: str):
    m = _KEY.match(name)
    return (int(m.group(1)), m.group(2).lower()) if m else None


def load() -> list[dict]:
    rows = []
    for subset in FAMILIES + ORIGINALS + ARCHIVES:
        for p in sorted((DATA / subset).iterdir()):
            k = _key(p.name)
            sample = _read_sample(str(p)) if k else None
            if sample is None:
                continue
            rows.append({
                "subset": subset, "seq": k[0], "ftype": k[1],
                "label": 1 if subset in FAMILIES else 0,
                "group": ("family" if subset in FAMILIES else
                          "archive" if subset in ARCHIVES else "original"),
                "feat": sample_features(sample), "name": p.name,
            })
    return rows


def split_by_seq(rows):
    seqs = sorted({r["seq"] for r in rows})
    rng = random.Random(SPLIT_SEED)
    rng.shuffle(seqs)
    test_seqs = set(seqs[: int(len(seqs) * TEST_FRACTION)])
    return ([r for r in rows if r["seq"] not in test_seqs],
            [r for r in rows if r["seq"] in test_seqs], test_seqs)


def prf(y, pred):
    if len(y) == 0:
        return {"precision": None, "recall": None, "f1": None, "n": 0}
    p, r, f, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
    return {"precision": round(float(p), 3), "recall": round(float(r), 3),
            "f1": round(float(f), 3), "n": int(len(y))}


def shannon_delta_predictions(test):
    """Per encrypted file with an original: (row, delta). Originals map by (seq, type)."""
    orig = {(r["seq"], r["ftype"]): r for r in test if r["group"] == "original"}
    out = []
    for r in test:
        if r["group"] != "family":
            continue
        o = orig.get((r["seq"], r["ftype"]))
        if o is not None:
            out.append((r, r["feat"][0] - o["feat"][0]))
    return out


def main() -> None:
    rows = load()
    train, test, test_seqs = split_by_seq(rows)
    Xtr = np.array([r["feat"] for r in train]); ytr = np.array([r["label"] for r in train])
    Xte = np.array([r["feat"] for r in test]);  yte = np.array([r["label"] for r in test])

    models = {
        "logreg": make_pipeline(StandardScaler(),
                                LogisticRegression(max_iter=1000, class_weight="balanced")),
        "random_forest": RandomForestClassifier(n_estimators=200, random_state=0,
                                                class_weight="balanced", n_jobs=-1),
    }
    for m in models.values():
        m.fit(Xtr, ytr)
    prob = {n: m.predict_proba(Xte)[:, 1] for n, m in models.items()}
    pred = {n: (p >= 0.5).astype(int) for n, p in prob.items()}

    result = {
        "command": "python experiments/model_a.py",
        "git_commit": subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                                     capture_output=True, text=True).stdout.strip(),
        "split": {"seed": SPLIT_SEED, "test_fraction": TEST_FRACTION,
                  "train_files": len(train), "test_files": len(test),
                  "train_positive": int(ytr.sum()), "test_positive": int(yte.sum()),
                  "test_sequence_numbers": len(test_seqs)},
        "features": list(FEATURE_NAMES),
    }

    # --- Overall, all test files ------------------------------------------
    overall = {n: {**prf(yte, pred[n]), "auc": round(float(roc_auc_score(yte, prob[n])), 3)}
               for n in models}
    result["overall_all_test_files"] = overall

    # --- Shannon-delta baseline on encrypted files that have an original ---
    pairs = shannon_delta_predictions(test)
    deltas = np.array([d for _, d in pairs])
    base_hits = deltas > SHANNON_ACTIVE
    idx = {id(r): i for i, r in enumerate(test)}
    result["shannon_delta_rule"] = {
        "threshold_bits": SHANNON_ACTIVE, "encrypted_files_with_original": len(pairs),
        "recall": round(float(base_hits.mean()), 3),
    }

    # --- Per file type: recall on encrypted files + false positives on originals ---
    by_type = {}
    for t in sorted({r["ftype"] for r in test if r["group"] != "archive"}):
        enc = [r for r in test if r["group"] == "family" and r["ftype"] == t]
        ori = [r for r in test if r["group"] == "original" and r["ftype"] == t]
        entry = {"encrypted_n": len(enc), "original_n": len(ori)}
        sub = enc + ori
        ysub = np.array([r["label"] for r in sub])
        for n in models:
            ps = np.array([pred[n][idx[id(r)]] for r in sub])
            entry[n] = prf(ysub, ps)
        pr = [(r, d) for r, d in pairs if r["ftype"] == t]
        entry["shannon_delta"] = {
            "recall": round(float(np.mean([d > SHANNON_ACTIVE for _, d in pr])), 3) if pr else None,
            "precision_on_originals": "1.0 by construction (delta vs itself = 0)",
            "n_pairs": len(pr),
        }
        by_type[t] = entry
    result["per_file_type"] = by_type

    # --- Archives: false positives, and the constructed baseline scenario ---
    arch = [r for r in test if r["group"] == "archive"]
    arch_fp = {n: {"false_positive_rate": round(float(np.mean([pred[n][idx[id(r)]] for r in arch])), 3)
                   if arch else None, "n": len(arch)} for n in models}
    orig_by_seq = defaultdict(list)
    for r in test:
        if r["group"] == "original" and r["ftype"] in ("doc", "xls", "docx", "xlsx", "pdf", "pptx"):
            orig_by_seq[r["seq"]].append(r)
    cons = [r["feat"][0] - o["feat"][0] for r in arch for o in orig_by_seq.get(r["seq"], [])[:1]]
    arch_fp["shannon_delta_archive_over_plaintext"] = {
        "false_positive_rate": round(float(np.mean(np.array(cons) > SHANNON_ACTIVE)), 3) if cons else None,
        "n": len(cons),
        "note": "constructed: archive treated as a rewrite of a same-sequence-number original",
    }
    result["archive_false_positives"] = arch_fp

    # --- Per family recall (test split) ------------------------------------
    result["per_family_recall"] = {
        fam: {n: round(float(np.mean([pred[n][idx[id(r)]] for r in test if r["subset"] == fam])), 3)
              for n in models} | {"n": sum(r["subset"] == fam for r in test)}
        for fam in FAMILIES}

    # --- Leave-one-family-out: train without a family, test its test files -
    lofo = {}
    for fam in FAMILIES:
        tr = [r for r in train if r["subset"] != fam]
        te = [r for r in test if r["subset"] == fam]
        m = RandomForestClassifier(n_estimators=200, random_state=0,
                                   class_weight="balanced", n_jobs=-1)
        m.fit(np.array([r["feat"] for r in tr]), np.array([r["label"] for r in tr]))
        lofo[fam] = {"recall": round(float(m.predict(np.array([r["feat"] for r in te])).mean()), 3),
                     "n": len(te)}
    result["leave_one_family_out_random_forest_recall"] = lofo

    # --- Shortcut check: does the model lean on the magic-header flag? ------
    # A recognised file signature is a property of the DATASET's way of
    # damaging files (encrypted copies lose their header) more than of
    # encryption itself: a ransomware that keeps the header would defeat it,
    # and a benign archive is told apart from ciphertext only by its header.
    # Retrain with feature subsets and score the same test files.
    subsets = {
        "all": list(FEATURE_NAMES),
        "no_magic": [n for n in FEATURE_NAMES if n != "magic"],
        "entropy_only": ["entropy", "head_entropy", "mid_entropy"],
    }
    abl = {}
    for sname, names in subsets.items():
        cols = [FEATURE_NAMES.index(n) for n in names]
        for mname, factory in (
                ("logreg", lambda: make_pipeline(StandardScaler(), LogisticRegression(
                    max_iter=1000, class_weight="balanced"))),
                ("random_forest", lambda: RandomForestClassifier(
                    n_estimators=200, random_state=0, class_weight="balanced", n_jobs=-1))):
            m = factory().fit(Xtr[:, cols], ytr)
            pr = m.predict(Xte[:, cols])
            arch_idx = [idx[id(r)] for r in arch]
            abl[f"{mname}/{sname}"] = {
                **prf(yte, pr),
                "archive_false_positive_rate": round(float(pr[arch_idx].mean()), 3) if arch else None,
                "recall_by_type": {t: round(float(np.mean([pr[idx[id(r)]] for r in test
                                   if r["group"] == "family" and r["ftype"] == t])), 3)
                                   for t in sorted({r["ftype"] for r in test if r["group"] == "family"})},
            }
    result["feature_ablation"] = abl

    rf = models["random_forest"]
    result["random_forest_feature_importance"] = dict(sorted(
        ((n, round(float(v), 3)) for n, v in zip(FEATURE_NAMES, rf.feature_importances_)),
        key=lambda kv: -kv[1]))

    # Fitted on the TRAIN split only (never on the test sequence numbers), for
    # the replay policies P1/P2.  Lives under the gitignored experiments/data/; rebuild with this script.
    mdir = ROOT / "experiments" / "data" / "models"
    mdir.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": models["random_forest"], "features": list(FEATURE_NAMES)},
                mdir / "model_a_rf.joblib")

    (OUT / "model_a.json").write_text(json.dumps(result, indent=2) + "\n")
    (OUT / "model_a.md").write_text(render(result))
    print((OUT / "model_a.md").read_text())


def render(r: dict) -> str:
    L = ["# Model A results", "",
         f"Command: `{r['command']}`  |  code at {r['git_commit']}  |  raw numbers: `model_a.json`", "",
         f"Split by sequence number (seed {r['split']['seed']}): "
         f"{r['split']['train_files']} train files, {r['split']['test_files']} test files "
         f"({r['split']['test_sequence_numbers']} held-out sequence numbers, "
         f"{r['split']['test_positive']} encrypted test files).", "",
         "## All test files (encrypted vs everything else)", "",
         "| model | precision | recall | F1 | AUC |", "|---|---|---|---|---|"]
    for n, v in r["overall_all_test_files"].items():
        L.append(f"| {n} | {v['precision']} | {v['recall']} | {v['f1']} | {v['auc']} |")
    s = r["shannon_delta_rule"]
    L += ["", f"Shannon-delta rule (delta > {s['threshold_bits']} bits/byte vs the original), "
          f"{s['encrypted_files_with_original']} encrypted files with an original: recall {s['recall']}.", "",
          "## Per file type (encrypted copies vs originals of that type)", "",
          "| type | enc n | orig n | logreg P/R/F1 | forest P/R/F1 | Shannon-delta recall |", "|---|---|---|---|---|---|"]
    for t, e in r["per_file_type"].items():
        f = lambda m: f"{e[m]['precision']}/{e[m]['recall']}/{e[m]['f1']}"
        L.append(f"| {t} | {e['encrypted_n']} | {e['original_n']} | {f('logreg')} | "
                 f"{f('random_forest')} | {e['shannon_delta']['recall']} |")
    L += ["", "Shannon-delta precision on originals is 1.0 by construction (an unchanged file has delta 0).", "",
          "## Archives (benign, high entropy): false-positive rate", "", "| rule | FPR | n |", "|---|---|---|"]
    for n, v in r["archive_false_positives"].items():
        L.append(f"| {n} | {v['false_positive_rate']} | {v['n']} |")
    L += ["", "## Per family recall on the test split", "", "| family | n | logreg | forest |", "|---|---|---|---|"]
    for fam, v in r["per_family_recall"].items():
        L.append(f"| {fam} | {v['n']} | {v['logreg']} | {v['random_forest']} |")
    L += ["", "## Leave-one-family-out (forest recall on the held-out family's test files)", "",
          "| family | recall | n |", "|---|---|---|"]
    for fam, v in r["leave_one_family_out_random_forest_recall"].items():
        L.append(f"| {fam} | {v['recall']} | {v['n']} |")
    L += ["", "## Shortcut check: feature ablation (same test files)", "",
          "| model/features | P | R | F1 | archive FPR | recall by type |", "|---|---|---|---|---|---|"]
    for k, v in r["feature_ablation"].items():
        rt = " ".join(f"{t}:{x}" for t, x in v["recall_by_type"].items())
        L.append(f"| {k} | {v['precision']} | {v['recall']} | {v['f1']} | "
                 f"{v['archive_false_positive_rate']} | {rt} |")
    L += ["", "## Forest feature importance", ""]
    L += [f"- {n}: {v}" for n, v in r["random_forest_feature_importance"].items()]
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    main()
