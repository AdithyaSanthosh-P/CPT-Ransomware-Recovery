"""
experiments/summarize_allruns.py
================================
Post-process policy_comparison_<label>.json (no replay, no re-run) into
numbers over ALL attack runs.

compare_policies.py reports median latency and median files overwritten over
DETECTED runs only, so a policy that detects few runs can look good there
(P0: 8 of 45).  Here an undetected run counts as the whole corpus lost
(corpus_files, 60 for these batches), which is what happens when no snapshot
is taken.  Latency has no equivalent value for a miss, so it stays
detected-only and is shown next to the detected count.

  python experiments/summarize_allruns.py --label heldout
"""

from __future__ import annotations

import argparse
import json
import statistics
from collections import defaultdict
from pathlib import Path

OUT = Path(__file__).parent / "results"
POLICIES = ("P0", "P1", "P2")
CORPUS = 60


def lost(r, p):
    return r[p]["files_before"] if r[p]["triggered"] else CORPUS


def med(xs):
    return statistics.median(xs) if xs else None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True)
    a = ap.parse_args()
    src = OUT / f"policy_comparison_{a.label}.json"
    d = json.loads(src.read_text())
    att = [r for r in d["runs"] if r["kind"] == "attack"]

    L = [f"# All-run summary ({a.label})", "",
         f"Source: `{src.name}` (existing runs, nothing re-run).  Command: "
         f"`python experiments/summarize_allruns.py --label {a.label}`", "",
         f"Files lost = files overwritten when the snapshot was requested; an undetected run counts as "
         f"{CORPUS}/{CORPUS} (no snapshot taken).  Latency is detected runs only.", "",
         "## Over all attack runs", "",
         "| policy | detected | median files lost, all runs | % of corpus | median files lost, detected only | median latency ms, detected only |",
         "|---|---|---|---|---|---|"]
    for p in POLICIES:
        det = [r[p] for r in att if r[p]["triggered"]]
        allv = med([lost(r, p) for r in att])
        L.append(f"| {p} | {len(det)}/{len(att)} | {allv} | {100 * allv / CORPUS:.1f} | "
                 f"{med([x['files_before'] for x in det])} | {round(med([x['latency_ms'] for x in det]), 1) if det else None} |")

    by = defaultdict(list)
    for r in att:
        by[r["name"]].append(r)
    L += ["", "## Per attack scenario (5 held-out seeds each)", "",
          "| scenario | P0 det | P0 files lost (median, all) | P1 det | P1 files lost | P2 det | P2 files lost |",
          "|---|---|---|---|---|---|---|"]
    for m, rs in by.items():
        cells = []
        for p in POLICIES:
            cells += [f"{sum(r[p]['triggered'] for r in rs)}/{len(rs)}", str(med([lost(r, p) for r in rs]))]
        L.append(f"| {m} | " + " | ".join(cells) + " |")
    L.append("")
    out = OUT / f"policy_comparison_{a.label}_allruns.md"
    out.write_text("\n".join(L))
    print("\n".join(L))


if __name__ == "__main__":
    main()
