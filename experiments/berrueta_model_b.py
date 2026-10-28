"""
experiments/berrueta_model_b.py
===============================
Score the already-trained Model B on real ransomware I/O traces (Berrueta et
al., IEEE DataPort 10.21227/qnyn-q136; Windows 7 clients writing to an SMB2
share).  Model B is NOT trained or tuned on this data: it was fitted on our
own simulator traces (experiments/model_b.py) and this is evaluated once.

  python experiments/berrueta_model_b.py \
      --data experiments/data/berrueta/unz/textFiles --label originalScenario

What is measured, and what is not
  * The data has no file contents, so Model A and the entropy signal cannot
    be run.  Only rate, extension and spread exist.  This tests Model B alone.
  * Every run is an attack: there are no benign runs, so this measures
    recall (did it trigger, how fast, how many files first) and says nothing
    about false triggers.
  * Policy PB: Model B's probability is the only fused input (weight 1.0 in
    the rate slot), the typed content-plus-behaviour quorum is waived because
    the content signal is absent (count quorum of 1), and the accumulator,
    thresholds, decay and cooldown are exactly the live ones.  This is a
    stated choice for this dataset, not the live policy.
  * Domain shift: rate/extension/spread normalisation ceilings are policy
    constants chosen for our simulator and Linux; SMB traces from a different
    OS and speed may sit well outside them.  A miss here can mean shift, not
    a weak detector, and is reported as such.

SMB2 -> CTRR events (columns per README.pdf)
  create request  (cmd 5)   path for a (client port, message id)
  create response (cmd 5)   FileID -> path, when status is success
  write request   (cmd 9)   marks the FileID dirty
  close request   (cmd 6)   dirty FileID -> OP_CLOSE_WRITE(path)
  set-info rename (cmd 17, subcommand 10)
                            OP_MOVED_FROM(old) + OP_MOVED_TO(new, src_path=old)
Time is the capture's own clock (seconds, converted to ns), so rates are in
the capture's real time.
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
from multiprocessing import Pool
from pathlib import Path

import joblib

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

from ctrr import scorer as S  # noqa: E402
from ctrr.extractor import (  # noqa: E402
    ExtractorPipeline, FileEvent, OP_CLOSE_WRITE, OP_MOVED_FROM, OP_MOVED_TO,
)
import replay_trace as R  # noqa: E402

MODELS = ROOT / "experiments" / "data" / "models"
OUT = ROOT / "experiments" / "results"

_DOCS = re.compile(r"documents", re.I)
_MIN_WRITES = 20          # runs with fewer write-closes are "no activity", not a miss


def norm_path(p: str) -> str:
    """Share path -> /share/<path under Documents>; only dirs and suffix matter."""
    p = p.replace("\\", "/")
    m = _DOCS.search(p)
    if m:
        p = p[m.end():]
    return "/share/" + p.strip("/")


def events_from_ioops(path: Path):
    """Yield FileEvents from one IOops.txt (see module docstring)."""
    pending: dict[tuple[str, str], str] = {}     # (client port, msg id) -> create path
    fid_path: dict[str, str] = {}
    dirty: set[str] = set()
    with path.open(errors="replace") as fh:
        next(fh, None)                            # header
        for line in fh:
            t = line.split()
            if len(t) < 19:
                continue
            try:
                ts = int(float(t[0]) * 1e9)
            except ValueError:
                continue
            cmd, sub, msg, resp, status = t[5], t[6], t[7], t[8], t[9]
            if cmd == "5":
                if resp == "0":
                    name = next((x for x in t[12:] if x.startswith("\\")), None)
                    if name:
                        pending[(t[3], msg)] = name
                elif status == "0":
                    name = pending.pop((t[4], msg), None)
                    if name and t[12] != "-":
                        fid_path[t[12]] = norm_path(name)
            elif resp != "0":
                continue
            elif cmd == "9":
                dirty.add(t[12])
            elif cmd == "6":
                fid = t[12]
                p = fid_path.pop(fid, None)
                if p and fid in dirty:
                    yield FileEvent(path=p, op=OP_CLOSE_WRITE, mono_ts=ts)
                dirty.discard(fid)
            elif cmd == "17" and sub == "10" and t[-1].startswith("\\"):
                old = fid_path.get(t[12])
                if old:
                    new = norm_path(t[-1])
                    yield FileEvent(path=old, op=OP_MOVED_FROM, mono_ts=ts)
                    yield FileEvent(path=new, op=OP_MOVED_TO, mono_ts=ts, src_path=old)
                    fid_path[t[12]] = new


def sample_ticks(io_path: Path):
    """Run the real extractors over the converted events; one tick per close-write."""
    pipe = ExtractorPipeline()
    ticks = []
    for ev in events_from_ioops(io_path):
        sub = pipe.process_event(ev)
        if ev.op == OP_CLOSE_WRITE:
            ticks.append({"mono_ts": ev.mono_ts, "path": ev.path, "entropy": 0.0,
                          "rate": sub.rate, "extension": sub.extension,
                          "spread": sub.spread})
    return ticks


def replay_pb(ticks, model_b):
    """Policy PB: Model B alone, count quorum of 1, live thresholds and decay."""
    saved = {k: getattr(S, k) for k in
             ("_WEIGHT_ENTROPY", "_WEIGHT_RATE", "_WEIGHT_EXTENSION", "_WEIGHT_SPREAD",
              "_TYPED_QUORUM", "_QUORUM_MIN")}
    try:
        S._WEIGHT_ENTROPY = S._WEIGHT_EXTENSION = S._WEIGHT_SPREAD = 0.0
        S._WEIGHT_RATE = 1.0
        S._TYPED_QUORUM = False
        S._QUORUM_MIN = 1
        pb = R.model_b_probs(model_b, ticks)
        sc = S.Scorer()
        for i, t in enumerate(ticks):
            if sc.tick(S.SubScores(rate=pb[i]), mono_ts=t["mono_ts"]) == S.ArbiterState.TRIGGER:
                return i, pb
        return None, pb
    finally:
        for k, v in saved.items():
            setattr(S, k, v)


def run_one(args):
    io_path, = args
    model_b = joblib.load(MODELS / "model_b_logreg.joblib")["model"]
    ticks = sample_ticks(io_path)
    run = io_path.parent.name
    scen = io_path.parent.parent.name
    row = {"run": run, "scenario": scen, "family": re.sub(r"_\d+$", "", run).lower(),
           "close_writes": len(ticks)}
    if len(ticks) < _MIN_WRITES:
        row["status"] = "no_activity"
        return row
    files = {t["path"] for t in ticks}
    ft, pb = replay_pb(ticks, model_b)
    row.update(
        status="detected" if ft is not None else "missed",
        files_total=len(files),
        max_rate=round(max(t["rate"] for t in ticks), 3),
        max_ext=round(max(t["extension"] for t in ticks), 3),
        max_spread=round(max(t["spread"] for t in ticks), 3),
        max_pb=round(max(pb), 3),
    )
    if ft is not None:
        t0 = ticks[0]["mono_ts"]
        row.update(latency_s=round((ticks[ft]["mono_ts"] - t0) / 1e9, 2),
                   files_before=len({t["path"] for t in ticks[: ft + 1]}))
        row["pct_before"] = round(100.0 * row["files_before"] / row["files_total"], 1)
    return row


def render(rows, label, cmd):
    act = [r for r in rows if r["status"] != "no_activity"]
    det = [r for r in act if r["status"] == "detected"]
    L = [f"# Model B on Berrueta I/O traces ({label})", "",
         f"Command: `{cmd}`  |  Model B logistic regression, trained on our simulator dev seeds only",
         "", "Recall only (every run is an attack; no benign runs exist in this dataset). "
         "Policy PB: Model B alone, count quorum 1, live thresholds. Entropy and Model A are "
         "absent (no file contents). Detection time and files are measured from the first "
         "close-after-write in the capture.", "",
         f"Runs: {len(rows)} IOops files, {len(act)} with activity (>= {_MIN_WRITES} write-closes), "
         f"{len(rows) - len(act)} without.", "",
         f"**Detected: {len(det)}/{len(act)}**", ""]
    if det:
        L += [f"Median time to trigger {statistics.median(r['latency_s'] for r in det)} s; "
              f"median files first {statistics.median(r['files_before'] for r in det)}; "
              f"median % of encrypted files before trigger "
              f"{statistics.median(r['pct_before'] for r in det)}.", ""]
    L += ["| family | runs | detected | median s | median files first | median % first |",
          "|---|---|---|---|---|---|"]
    fam = {}
    for r in act:
        fam.setdefault(r["family"], []).append(r)
    for f, rs in sorted(fam.items()):
        d = [r for r in rs if r["status"] == "detected"]
        m = lambda k: statistics.median(r[k] for r in d) if d else "-"
        L.append(f"| {f} | {len(rs)} | {len(d)} | {m('latency_s')} | {m('files_before')} | {m('pct_before')} |")
    miss = [r for r in act if r["status"] == "missed"]
    if miss:
        L += ["", "## Missed runs (max sub-scores show whether the signal was ever high)", "",
              "| run | scenario | write-closes | files | max rate | max ext | max spread | max Model B |",
              "|---|---|---|---|---|---|---|---|"]
        for r in miss:
            L.append(f"| {r['run']} | {r['scenario']} | {r['close_writes']} | {r['files_total']} | "
                     f"{r['max_rate']} | {r['max_ext']} | {r['max_spread']} | {r['max_pb']} |")
    L.append("")
    return "\n".join(L)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--scenarios", nargs="*", default=None,
                    help="restrict to these scenario directories")
    ap.add_argument("--limit", type=int, default=0, help="first N files (smoke test)")
    ap.add_argument("--procs", type=int, default=4)
    a = ap.parse_args()
    files = sorted(a.data.glob("*/*/IOops.txt"))
    if a.scenarios:
        files = [f for f in files if f.parent.parent.name in a.scenarios]
    if a.limit:
        files = files[: a.limit]
    with Pool(a.procs) as pool:
        rows = pool.map(run_one, [(f,) for f in files], chunksize=1)
    cmd = "python experiments/berrueta_model_b.py " + " ".join(sys.argv[1:])
    (OUT / f"berrueta_model_b_{a.label}.json").write_text(
        json.dumps({"command": cmd, "rows": rows}, indent=2) + "\n")
    md = render(rows, a.label, cmd)
    (OUT / f"berrueta_model_b_{a.label}.md").write_text(md)
    print(md)


if __name__ == "__main__":
    main()
