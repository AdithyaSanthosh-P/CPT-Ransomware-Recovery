"""
tools/run_batch.py
==================
Unattended batch runner: reset the corpus, start the monitor with tracing,
run ONE attack or benign workload, stop the monitor, save the trace and the
run's configuration side by side.

  python tools/run_batch.py --split dev            # seeds 1-3, tuning runs
  python tools/run_batch.py --split heldout        # seeds 4-8, final numbers
  python tools/run_batch.py --only attack:baseline benign:git_clone --seeds 1

Output, one directory per run (resumable: finished runs are skipped):
  experiments/results/batch/<kind>-<name>-s<seed>/trace.jsonl   monitor ticks + markers
  experiments/results/batch/<kind>-<name>-s<seed>/config.json   configuration, commands, outcome
  experiments/results/batch/<kind>-<name>-s<seed>/monitor.log   monitor stdout

Attack matrix (one factor varied at a time around "baseline"; the full cross
product would be 108 configurations x 8 seeds, too slow for the sprint):
  baseline  : rate medium, rename fixed, encrypt full, content aes, layout flat
  rate_slow / rate_fast, rename_random / rename_none, encrypt_head /
  encrypt_alternate, content_napierone, layout_nested
Rates: slow 2 files/s, medium 10 files/s, fast unlimited (in practice about
18 files/s, bounded by the simulator's 50 ms write-to-rename pause).

Benign workloads, each run inside the watched directory: unzip_flat,
unzip_multidir (audit R7), tar_x, git_clone, cp_r.

Seed split (course-plan "Evaluation protocol"): seeds 1-3 are development,
seeds 4-8 are held out and must be run once, for the final numbers.  The
runner refuses to re-run a held-out seed unless --force is given.

DEMO-SCOPE: runs use the copytree snapshot backend (the snapshot is not what
is being evaluated; the trace is).  Btrfs is exercised by the demo itself.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(Path(__file__).parent))
from build_corpus import build  # noqa: E402
from simulate_attack import _write_marker  # noqa: E402

RESULTS = ROOT / "experiments" / "results" / "batch"   # overridable: --results-dir
NAPIERONE = ROOT / "experiments" / "data" / "napierone"
CORPUS_FILES = 60
DEV_SEEDS, HELDOUT_SEEDS = (1, 2, 3), (4, 5, 6, 7, 8)
_SETTLE_S = 3          # let the monitor drain its queue after the workload

_RATES = {"slow": 2.0, "medium": 10.0, "fast": 0.0}
_BASE = dict(rate="medium", rename="fixed", encrypt="full", content="aes", layout="flat")
ATTACKS = {
    "baseline":          {},
    "rate_slow":         {"rate": "slow"},
    "rate_fast":         {"rate": "fast"},
    "rename_random":     {"rename": "random"},
    "rename_none":       {"rename": "none"},
    "encrypt_head":      {"encrypt": "head"},
    "encrypt_alternate": {"encrypt": "alternate"},
    "content_napierone": {"content": "napierone"},
    "layout_nested":     {"layout": "nested"},
}
BENIGN = ("unzip_flat", "unzip_multidir", "tar_x", "git_clone", "cp_r")

# Ransomware family used for content=napierone.  One family is enough to
# test "real ciphertext"; per-family variation is not a claim of this batch.
_FAMILY = "RYUK"


def _git_commit() -> str:
    out = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                         capture_output=True, text=True)
    dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no", "--", "src", "tools"],
                           cwd=ROOT, capture_output=True, text=True).stdout.strip()
    return out.stdout.strip() + ("+dirty" if dirty else "")


def _manifest(root: Path) -> dict[str, str]:
    """relative path -> sha256 for every file under root (sentinel excluded)."""
    m = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.name != ".ctrr-test-corpus":
            m[str(p.relative_to(root))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return m


def _intact_in_snapshot(snap: Path, manifest: dict[str, str]) -> int:
    """How many original files the snapshot holds byte-for-byte unchanged."""
    return sum(1 for rel, sha in manifest.items()
               if (snap / rel).is_file()
               and hashlib.sha256((snap / rel).read_bytes()).hexdigest() == sha)


def _cpu_seconds(pid: int) -> float:
    """utime+stime of a process, from /proc (clock ticks -> seconds)."""
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


# ---------------------------------------------------------------------------
# Benign workloads
# ---------------------------------------------------------------------------

def _prepare_archives(work: Path) -> dict[str, Path]:
    """
    Build the archives the benign workloads unpack, once per batch.

    The content is real NapierOne originals (seed 100, disjoint from the
    corpus seeds) so the extracted files are realistic already-compressed
    documents, the hard case for an entropy signal.
    """
    arch = work / "archives"
    done = arch / ".ready"
    paths = {"flat": arch / "flat.zip", "multidir": arch / "multidir.zip",
             "large": arch / "large.tar.gz", "copysrc": arch / "copysrc"}
    if done.exists():
        return paths
    shutil.rmtree(arch, ignore_errors=True)
    arch.mkdir(parents=True)
    src = work / "archive_src"
    build(src, "napierone", 200, "nested", seed=100)
    with zipfile.ZipFile(arch / "flat.zip", "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(src.rglob("*"))[:CORPUS_FILES]:
            if p.is_file() and p.name != ".ctrr-test-corpus":
                z.write(p, p.name)
    with zipfile.ZipFile(arch / "multidir.zip", "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(src.rglob("*")):
            if p.is_file() and p.name != ".ctrr-test-corpus":
                z.write(p, p.relative_to(src))
    with tarfile.open(arch / "large.tar.gz", "w:gz") as t:
        for p in sorted(src.rglob("*")):
            if p.is_file() and p.name != ".ctrr-test-corpus":
                t.add(p, p.relative_to(src))
    shutil.copytree(src, arch / "copysrc")
    done.touch()
    return paths


def _benign_command(name: str, corpus: Path, arch: dict[str, Path]) -> list[str]:
    dest = corpus / name
    if name == "unzip_flat":
        return ["unzip", "-q", str(arch["flat"]), "-d", str(dest)]
    if name == "unzip_multidir":
        return ["unzip", "-q", str(arch["multidir"]), "-d", str(dest)]
    if name == "tar_x":
        dest.mkdir()
        return ["tar", "xzf", str(arch["large"]), "-C", str(dest)]
    if name == "git_clone":
        return ["git", "clone", "-q", str(ROOT), str(dest)]
    if name == "cp_r":
        return ["cp", "-r", str(arch["copysrc"]), str(dest)]
    raise ValueError(name)


# ---------------------------------------------------------------------------
# One run
# ---------------------------------------------------------------------------

def run_one(kind: str, name: str, seed: int, work: Path,
            arch: dict[str, Path] | None, force: bool) -> str:
    run_dir = RESULTS / f"{kind}-{name}-s{seed}"
    if (run_dir / "config.json").exists() and not force:
        return "skipped (already done)"
    if seed in HELDOUT_SEEDS and run_dir.exists() and not force:
        return "REFUSED: held-out seed already has partial output; use --force"
    shutil.rmtree(run_dir, ignore_errors=True)
    run_dir.mkdir(parents=True)

    corpus, snaps = work / "corpus", work / "snaps"
    shutil.rmtree(snaps, ignore_errors=True)
    attack = {**_BASE, **ATTACKS[name]} if kind == "attack" else None
    layout = attack["layout"] if attack else "flat"
    pair = NAPIERONE / _FAMILY if attack and attack["content"] == "napierone" else None
    build(corpus, "napierone", CORPUS_FILES, layout, seed, pair_with=pair)
    manifest = _manifest(corpus)

    trace, mlog = run_dir / "trace.jsonl", run_dir / "monitor.log"
    mon_cmd = [sys.executable, "-m", "ctrr.monitor", "--watch", str(corpus),
               "--snapshots", str(snaps), "--trace", str(trace)]
    t0 = time.monotonic()
    with mlog.open("w") as log:
        mon = subprocess.Popen(mon_cmd, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        for _ in range(100):                       # wait up to 10 s for "watching"
            if "watching" in mlog.read_text():
                break
            time.sleep(0.1)
        else:
            mon.kill()
            return "FAILED: monitor did not start"

        if attack:
            cmd = [sys.executable, "tools/simulate_attack.py", "--target", str(corpus),
                   "--rate", str(_RATES[attack["rate"]]), "--seed", str(seed),
                   "--encrypt", attack["encrypt"], "--rename", attack["rename"],
                   "--content", attack["content"], "--trace", str(trace)]
            if pair:
                cmd += ["--cipher-dir", str(pair)]
            rc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True).returncode
        else:
            cmd = _benign_command(name, corpus, arch)
            _write_marker(trace, "WORKLOAD_START", workload=name)
            rc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True).returncode
            _write_marker(trace, "WORKLOAD_END", workload=name)
        time.sleep(_SETTLE_S)
        cpu = _cpu_seconds(mon.pid)
        mon.send_signal(signal.SIGINT)
        mon.wait(timeout=15)

    text = mlog.read_text()
    snap_dirs = sorted(snaps.glob("*_trigger")) if snaps.exists() else []
    config = {
        "kind": kind, "name": name, "seed": seed,
        "mode": attack, "split": "heldout" if seed in HELDOUT_SEEDS else "dev",
        "corpus_files": len(manifest), "layout": layout,
        "ransomware_family": _FAMILY if pair else None,
        "workload_command": cmd, "workload_returncode": rc,
        "monitor_command": mon_cmd, "git_commit": _git_commit(),
        "wall_seconds": round(time.monotonic() - t0, 2),
        "monitor_cpu_seconds": cpu,
        "triggered": "[TRIGGER]" in text,
        "snapshots_taken": len(snap_dirs),
        # Files the first snapshot still holds unchanged = files saved.
        "snapshot_intact_files": (_intact_in_snapshot(snap_dirs[0], manifest)
                                  if snap_dirs else None),
    }
    (run_dir / "config.json").write_text(json.dumps(config, indent=2) + "\n")
    outcome = "TRIGGER" if config["triggered"] else "no trigger"
    return f"{outcome}  rc={rc}  {config['wall_seconds']}s  intact={config['snapshot_intact_files']}"


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--split", choices=("dev", "heldout"))
    g.add_argument("--seeds", type=int, nargs="+")
    ap.add_argument("--only", nargs="+", metavar="KIND:NAME",
                    help="e.g. attack:baseline benign:git_clone (default: everything)")
    ap.add_argument("--workdir", type=Path, default=Path("/tmp/ctrr-batch"))
    ap.add_argument("--results-dir", type=Path, default=None,
                    help="output directory (default: experiments/results/batch)")
    ap.add_argument("--force", action="store_true", help="re-run runs that already have output")
    a = ap.parse_args(argv)
    global RESULTS
    if a.results_dir:
        RESULTS = a.results_dir

    seeds = (DEV_SEEDS if a.split == "dev" else HELDOUT_SEEDS) if a.split else tuple(a.seeds)
    plan = [("attack", n) for n in ATTACKS] + [("benign", n) for n in BENIGN]
    if a.only:
        plan = [p for p in plan if f"{p[0]}:{p[1]}" in a.only]
    if not plan:
        sys.exit("ERROR: --only matched nothing")
    if not NAPIERONE.exists():
        sys.exit("ERROR: NapierOne data missing; run tools/fetch_napierone.py")

    a.workdir.mkdir(parents=True, exist_ok=True)
    arch = _prepare_archives(a.workdir) if any(k == "benign" for k, _ in plan) else None
    total = len(plan) * len(seeds)
    i = 0
    for seed in seeds:
        for kind, name in plan:
            i += 1
            print(f"[{i}/{total}] {kind}:{name} seed={seed} ... ", end="", flush=True)
            print(run_one(kind, name, seed, a.workdir, arch, a.force), flush=True)


if __name__ == "__main__":
    main()
