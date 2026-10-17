"""
tools/build_corpus.py
=====================
Build a fresh test corpus for the attack simulator and the batch runner.

  python tools/build_corpus.py --target /tmp/ctrr-corpus --source napierone --files 60 --seed 1
  python tools/build_corpus.py --target /tmp/ctrr-corpus --source synthetic --layout nested

Sources
  synthetic  60 identical-style text files, the corpus the original demo uses
  napierone  real original files of the seven document/image types, copied
             from experiments/data/napierone/<TYPE>/ (see tools/fetch_napierone.py)

Layouts
  flat    every file in the target directory
  nested  files spread over 6 subdirectories (d0..d5), so the spread
          extractor has more than one directory to see

The target is emptied first, but only if it is absent, empty, or already
carries the .ctrr-test-corpus sentinel; anything else is refused, the same
guard the simulator uses.  File choice is seeded, so a (source, files, seed)
triple always produces the same corpus.
"""

from __future__ import annotations

import argparse
import random
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from simulate_attack import _index_cipher_dir, _napierone_key  # noqa: E402

_SENTINEL = ".ctrr-test-corpus"
_DATA_DIR = Path(__file__).parent.parent / "experiments" / "data" / "napierone"
# Original-file subsets that have a matching encrypted copy in every
# ransomware family (NapierOne jpg is named 'jpg-fromweb' in the families).
_TYPES = ("DOC", "DOCX", "XLS", "XLSX", "PDF", "PPTX", "JPG")
# Keep any single file small so a 60-file run stays quick on a loop device.
_MAX_BYTES = 2 * 1024 * 1024
_NESTED_DIRS = 6


def _reset(target: Path) -> None:
    if target.exists() and any(target.iterdir()) and not (target / _SENTINEL).exists():
        sys.exit(f"ERROR: refusing to empty {target}: not empty and no {_SENTINEL} sentinel")
    if len(target.parts) <= 2:
        sys.exit(f"ERROR: target path is too shallow: {target}")
    if target.exists():
        for child in target.iterdir():
            shutil.rmtree(child) if child.is_dir() else child.unlink()
    target.mkdir(parents=True, exist_ok=True)
    (target / _SENTINEL).touch()


def _pick_napierone(n: int, seed: int, pair_with: Path | None) -> list[Path]:
    """
    n original files, drawn evenly across the types, seeded.

    With pair_with (a ransomware family directory) only originals that have
    an encrypted counterpart there are eligible, so a real-ciphertext attack
    can replace every file instead of falling back to AES for some.
    """
    paired = set(_index_cipher_dir(pair_with)) if pair_with else None
    rng = random.Random(seed)
    pools = []
    for t in _TYPES:
        files = sorted(p for p in (_DATA_DIR / t).glob("*")
                       if p.is_file() and p.stat().st_size <= _MAX_BYTES
                       and (paired is None or _napierone_key(p.name) in paired))
        rng.shuffle(files)
        pools.append(files)
    if not any(pools):
        sys.exit(f"ERROR: no NapierOne originals under {_DATA_DIR}; run tools/fetch_napierone.py")
    picked: list[Path] = []
    while len(picked) < n and any(pools):
        for pool in pools:
            if pool and len(picked) < n:
                picked.append(pool.pop())
    return picked


def build(target: Path, source: str, files: int, layout: str, seed: int,
          pair_with: Path | None = None) -> list[Path]:
    """Create the corpus and return the paths of the files it contains."""
    _reset(target)
    dirs = [target]
    if layout == "nested":
        dirs = [target / f"d{i}" for i in range(_NESTED_DIRS)]
        for d in dirs:
            d.mkdir()
    made = []
    if source == "synthetic":
        line = "The quick brown fox jumps over the lazy dog. This is a normal text document.\n"
        for i in range(1, files + 1):
            p = dirs[i % len(dirs)] / f"doc_{i}.txt"
            p.write_text(line * 200)
            made.append(p)
    else:
        for i, src in enumerate(_pick_napierone(files, seed, pair_with)):
            p = dirs[i % len(dirs)] / src.name
            shutil.copyfile(src, p)
            made.append(p)
    return made


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--target", required=True, type=Path)
    ap.add_argument("--source", choices=("synthetic", "napierone"), default="synthetic")
    ap.add_argument("--files", type=int, default=60)
    ap.add_argument("--layout", choices=("flat", "nested"), default="flat")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--pair-with", type=Path, default=None, metavar="FAMILY_DIR",
                    help="napierone only: pick only originals that have an encrypted"
                         " copy in this ransomware family directory")
    a = ap.parse_args(argv)
    made = build(a.target, a.source, a.files, a.layout, a.seed, a.pair_with)
    print(f"Corpus ready: {len(made)} files in {a.target} "
          f"(source={a.source} layout={a.layout} seed={a.seed})")


if __name__ == "__main__":
    main()
