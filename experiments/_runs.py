"""experiments/_runs.py -- load batch run directories (config.json + trace.jsonl)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "src"))
import replay_trace as R  # noqa: E402


def load_runs(results_dir: Path) -> list[dict]:
    """
    One dict per finished run: config, ticks, markers, attack window and a
    ground-truth label (1 = inside the attack window) on every tick.
    """
    runs = []
    for cfg in sorted(Path(results_dir).glob("*/config.json")):
        config = json.loads(cfg.read_text())
        ticks, markers = R.split_records(R._load_trace(str(cfg.parent / "trace.jsonl")))
        window = R.attack_window(markers)
        for t in ticks:
            t["label"] = 1 if R.label_tick(t["mono_ts"], window) == "attack" else 0
        runs.append({"config": config, "ticks": ticks, "markers": markers,
                     "window": window, "dir": cfg.parent})
    return runs
