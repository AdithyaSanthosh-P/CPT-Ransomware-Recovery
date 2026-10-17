"""
tools/simulate_attack.py
========================
Demo attack simulator for CTRR.

Mimics ransomware behaviour by:
  1. Reading each file in the target directory
  2. Overwriting it with AES-256-CTR ciphertext (via the cryptography library)
  3. Renaming it to <original_name>.enc

Modes (course-plan "Evaluation protocol"; defaults reproduce the original
demo attack exactly):
  --encrypt  full | head | alternate   how much of each file is overwritten
  --rename   fixed | random | none     suffix style after encryption
  --content  aes | napierone           self-generated AES, or the bytes of a
                                       real ransomware-encrypted NapierOne file
  --seed N                             file order and random suffixes

The simulator is intentionally slow enough for the monitor to observe the
signal build-up (NORMAL -> SUSPECT -> TRIGGER) before all files are encrypted.
A --rate flag controls files per second.

Safety
------
The simulator refuses to run unless:
  - The target directory exists and contains a sentinel file named
    '.ctrr-test-corpus'
  - The path is not '/' or any direct child of '/'

These checks prevent accidental use against real data.

Kill switch
-----------
Create a file named '.ctrr-stop' anywhere inside the target directory.
The simulator checks for this file between each encryption and exits cleanly.

Dependencies
------------
  cryptography  -- pip install cryptography
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
import time
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    print("ERROR: 'cryptography' package not installed.  Run: pip install cryptography",
          file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Safety guards
# ---------------------------------------------------------------------------

_SENTINEL_FILE = ".ctrr-test-corpus"
_STOP_FILE     = ".ctrr-stop"

# Files and directories the simulator skips when encrypting.
_SKIP_NAMES = {_SENTINEL_FILE, _STOP_FILE, ".gitkeep"}


def _check_safety(target: Path) -> None:
    """
    Raise SystemExit if the target directory does not meet the safety
    requirements.  This prevents accidental use against real data.
    """
    if not target.is_dir():
        sys.exit(f"ERROR: target directory does not exist: {target}")

    # Refuse to operate on filesystem root or its immediate children.
    if len(target.parts) <= 2:
        sys.exit(f"ERROR: target path is too shallow (refusing to operate on {target})")

    sentinel = target / _SENTINEL_FILE
    if not sentinel.exists():
        sys.exit(
            f"ERROR: sentinel file '{_SENTINEL_FILE}' not found in {target}.\n"
            f"       Create it to confirm this is a test corpus:\n"
            f"       touch {sentinel}"
        )


def _stop_requested(target: Path) -> bool:
    """Return True if the kill-switch file has appeared in the target."""
    return (target / _STOP_FILE).exists()


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------

def _encrypt_bytes(plaintext: bytes) -> bytes:
    """
    Encrypt plaintext with AES-256-CTR using a random key and nonce.

    AES-CTR output is statistically indistinguishable from random bytes,
    so the entropy extractor will score the overwritten file at ~1.0.
    A fresh key is generated per file to avoid any patterns across files.

    The key and nonce are discarded; this is intentional -- the simulator
    is not a real encryptor and recovery is not the goal here.
    """
    key   = os.urandom(32)    # 256-bit key
    nonce = os.urandom(16)    # 128-bit nonce
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    enc = cipher.encryptor()
    return enc.update(plaintext) + enc.finalize()


# Partial encryption works on fixed chunks.  16 KiB is a modelling choice,
# not a measured ransomware constant: it is larger than the extractor's 4 KiB
# head and mid samples, so "head" and "alternate" modes can leave one of the
# two sample windows holding plaintext.  Whether the entropy signal still
# fires is exactly what these modes are meant to test.
_PARTIAL_CHUNK = 16 * 1024


def _partial_ciphertext(plaintext: bytes, mode: str) -> bytes:
    """
    Overwrite part of plaintext with AES ciphertext, keeping its length.

    head      : only the first chunk is encrypted
    alternate : chunks 0, 2, 4, ... are encrypted, the rest stay plaintext
    """
    out = bytearray(plaintext)
    for i, off in enumerate(range(0, len(plaintext), _PARTIAL_CHUNK)):
        if mode == "head" and i > 0:
            break
        if mode == "alternate" and i % 2 == 1:
            continue
        chunk = plaintext[off:off + _PARTIAL_CHUNK]
        out[off:off + len(chunk)] = _encrypt_bytes(chunk)
    return bytes(out)


_SEQ_RE = re.compile(r"^(\d+)-([A-Za-z0-9]+)")


def _napierone_key(name: str) -> tuple[str, str] | None:
    """
    (sequence number, file type) of a NapierOne file name, or None.

    '0007-docx.docx' and '0007-docx.docx.RYK' both give ('0007', 'docx').
    NapierOne's encrypted JPGs are named '...-jpg-fromweb...' while the
    originals are '...-jpg...'; the regex stops at the first '-' after the
    type, so both normalise to 'jpg'.
    """
    m = _SEQ_RE.match(name)
    return (m.group(1), m.group(2).lower()) if m else None


def _index_cipher_dir(cipher_dir: Path) -> dict[tuple[str, str], Path]:
    """Map (sequence, type) -> real ransomware-encrypted file in cipher_dir."""
    index = {}
    for p in sorted(cipher_dir.iterdir()):
        key = _napierone_key(p.name)
        if p.is_file() and key:
            index.setdefault(key, p)
    return index


def _new_name(path: Path, rename: str, rng: random.Random) -> Path:
    if rename == "none":
        return path
    if rename == "fixed":
        return path.with_suffix(path.suffix + ".enc")
    # random: a different 8-hex-digit suffix per file, so the extension
    # extractor never sees the same novel suffix twice.
    return path.with_suffix(path.suffix + "." + "".join(rng.choices("0123456789abcdef", k=8)))


def _encrypt_file(path: Path, encrypt: str = "full", rename: str = "fixed",
                  content: str = "aes", cipher_index: dict | None = None,
                  rng: random.Random | None = None) -> tuple[Path, bool]:
    """
    Overwrite path with ciphertext according to the mode, then rename it.

    Returns (new path, used_real_ciphertext).  content="napierone" falls
    back to AES when the cipher directory has no file for this sequence
    number and type; the caller counts those fallbacks.

    The 50ms pause between write and rename is deliberate.  inotify delivers
    CLOSE_WRITE asynchronously: the monitor's reader thread receives the event,
    enqueues a FileEvent, and the processor thread reads the file to compute
    entropy.  Without the pause, write_bytes() triggers CLOSE_WRITE and rename()
    immediately removes the original path, so the entropy extractor gets an
    OSError on every file and scores 0.0.  50ms is enough for the kernel to
    deliver the event and the extractor to complete the read.  Real ransomware
    has inherent latency between write and rename (key derivation, metadata
    updates) so this is a realistic model.
    """
    rng = rng or random.Random()
    plaintext = path.read_bytes()
    real = False
    key = _napierone_key(path.name)
    if content == "napierone" and cipher_index and key in cipher_index:
        # Real ciphertext replaces the whole file (its length differs from
        # the original), so --encrypt does not apply to it.
        ciphertext = cipher_index[key].read_bytes()
        real = True
    elif encrypt == "full":
        ciphertext = _encrypt_bytes(plaintext)
    else:
        ciphertext = _partial_ciphertext(plaintext, encrypt)
    path.write_bytes(ciphertext)

    # Pause here so the entropy extractor can read the encrypted content
    # before the file disappears from its original path.
    time.sleep(0.05)

    new_path = _new_name(path, rename, rng)
    if new_path != path:
        path.rename(new_path)
    return new_path, real


# ---------------------------------------------------------------------------
# Main simulation loop
# ---------------------------------------------------------------------------

def _collect_files(target: Path) -> list[Path]:
    """
    Return all regular files in target that should be encrypted,
    sorted for deterministic ordering.
    """
    files = sorted(
        p for p in target.rglob("*")
        if p.is_file() and p.name not in _SKIP_NAMES
        and p.suffix != ".enc"   # skip already-encrypted files on re-run
    )
    return files


def _write_marker(trace: Path | None, event: str, **fields) -> None:
    """
    Append one ground-truth marker to the trace file.

    time.monotonic_ns() is CLOCK_MONOTONIC, the same clock the watcher stamps
    FileEvents with, and both processes run on one machine, so marker and
    tick timestamps are directly comparable.  Single-line O_APPEND writes
    from two processes do not interleave mid-line for lines this short.
    """
    if trace is None:
        return
    rec = {"type": "marker", "event": event, "mono_ts": time.monotonic_ns(), **fields}
    with trace.open("a") as fh:
        fh.write(json.dumps(rec) + "\n")


def simulate(target: Path, rate: float, verbose: bool,
             trace: Path | None = None, encrypt: str = "full",
             rename: str = "fixed", content: str = "aes",
             cipher_dir: Path | None = None, seed: int = 0) -> None:
    """
    Encrypt files in target at the specified rate (files per second).

    Parameters
    ----------
    target  : directory to attack
    rate    : files per second (0 = as fast as possible)
    verbose : print each file as it is encrypted
    trace   : optional JSONL file; ATTACK_START / ATTACK_END markers are appended
    encrypt, rename, content, cipher_dir, seed : attack mode, see module docstring
    """
    _check_safety(target)

    if content == "napierone" and cipher_dir is None:
        sys.exit("ERROR: --content napierone needs --cipher-dir")
    cipher_index = _index_cipher_dir(cipher_dir) if cipher_dir else None
    rng = random.Random(seed)

    files = _collect_files(target)
    # Seeded shuffle: ransomware does not walk files alphabetically, and the
    # seed makes the order reproducible.  Seed 0 keeps the original sorted
    # order so the demo attack is unchanged.
    if seed:
        rng.shuffle(files)
    if not files:
        print(f"No files to encrypt in {target}")
        return

    print(f"[ATTACK_START] target={target}  files={len(files)}  rate={rate} fps")
    _write_marker(trace, "ATTACK_START", files=len(files), rate=rate,
                  encrypt=encrypt, rename=rename, content=content, seed=seed)

    interval = (1.0 / rate) if rate > 0 else 0.0
    encrypted = 0
    real_count = 0

    for path in files:
        if _stop_requested(target):
            print(f"[ATTACK_STOP] kill-switch detected after {encrypted} files")
            _write_marker(trace, "ATTACK_END", encrypted=encrypted, stopped=True,
                          real_ciphertext=real_count)
            return

        try:
            enc_path, real = _encrypt_file(path, encrypt, rename, content,
                                           cipher_index, rng)
            encrypted += 1
            real_count += real
            if verbose:
                print(f"  encrypted {path.name} -> {enc_path.name}")
        except OSError as exc:
            print(f"  SKIP {path.name}: {exc}", file=sys.stderr)

        if interval > 0:
            time.sleep(interval)

    print(f"[ATTACK_END] encrypted={encrypted}"
          + (f"  real_ciphertext={real_count}" if content == "napierone" else ""))
    _write_marker(trace, "ATTACK_END", encrypted=encrypted, stopped=False,
                  real_ciphertext=real_count)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="CTRR attack simulator -- encrypts a test corpus to trigger the monitor"
    )
    p.add_argument(
        "--target", required=True, metavar="DIR",
        help="Test corpus directory (must contain .ctrr-test-corpus sentinel)",
    )
    p.add_argument(
        "--rate", type=float, default=10.0, metavar="FPS",
        help="Files encrypted per second (default: 10, 0 = unlimited)",
    )
    p.add_argument(
        "--verbose", "-v", action="store_true",
        help="Print each file as it is encrypted",
    )
    p.add_argument("--encrypt", choices=("full", "head", "alternate"), default="full",
                   help="How much of each file is overwritten (default: full)")
    p.add_argument("--rename", choices=("fixed", "random", "none"), default="fixed",
                   help="Suffix after encryption: .enc, random per file, or unchanged")
    p.add_argument("--content", choices=("aes", "napierone"), default="aes",
                   help="Ciphertext source: self-generated AES, or real NapierOne"
                        " ransomware output (needs --cipher-dir)")
    p.add_argument("--cipher-dir", default=None, metavar="DIR",
                   help="A NapierOne ransomware family directory, e.g."
                        " experiments/data/napierone/RYUK")
    p.add_argument("--seed", type=int, default=0,
                   help="File order and random suffixes (0 = sorted order)")
    p.add_argument(
        "--trace", default=None, metavar="FILE",
        help="Append ATTACK_START / ATTACK_END ground-truth markers to this JSONL"
             " file (normally the same file the monitor writes with --trace)",
    )
    return p.parse_args(argv)


if __name__ == "__main__":
    args = _parse_args()
    simulate(Path(args.target), rate=args.rate, verbose=args.verbose,
             trace=Path(args.trace) if args.trace else None,
             encrypt=args.encrypt, rename=args.rename, content=args.content,
             cipher_dir=Path(args.cipher_dir) if args.cipher_dir else None,
             seed=args.seed)
