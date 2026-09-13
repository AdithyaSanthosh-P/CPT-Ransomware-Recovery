"""
tools/simulate_attack.py
========================
Demo attack simulator for CTRR.

Mimics ransomware behaviour by:
  1. Reading each file in the target directory
  2. Overwriting it with AES-256-CTR ciphertext (via the cryptography library)
  3. Renaming it to <original_name>.enc

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
import os
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


def _encrypt_file(path: Path) -> Path:
    """
    Read path, overwrite it with AES ciphertext, rename to <path>.enc.

    Returns the new path.  Raises OSError on read/write failure.
    """
    plaintext = path.read_bytes()
    ciphertext = _encrypt_bytes(plaintext)
    path.write_bytes(ciphertext)

    enc_path = path.with_suffix(path.suffix + ".enc")
    path.rename(enc_path)
    return enc_path


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


def simulate(target: Path, rate: float, verbose: bool) -> None:
    """
    Encrypt files in target at the specified rate (files per second).

    Parameters
    ----------
    target  : directory to attack
    rate    : files per second (0 = as fast as possible)
    verbose : print each file as it is encrypted
    """
    _check_safety(target)

    files = _collect_files(target)
    if not files:
        print(f"No files to encrypt in {target}")
        return

    print(f"[ATTACK_START] target={target}  files={len(files)}  rate={rate} fps")

    interval = (1.0 / rate) if rate > 0 else 0.0
    encrypted = 0

    for path in files:
        if _stop_requested(target):
            print(f"[ATTACK_STOP] kill-switch detected after {encrypted} files")
            return

        try:
            enc_path = _encrypt_file(path)
            encrypted += 1
            if verbose:
                print(f"  encrypted {path.name} -> {enc_path.name}")
        except OSError as exc:
            print(f"  SKIP {path.name}: {exc}", file=sys.stderr)

        if interval > 0:
            time.sleep(interval)

    print(f"[ATTACK_END] encrypted={encrypted}")


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
    return p.parse_args(argv)


if __name__ == "__main__":
    args = _parse_args()
    simulate(Path(args.target), rate=args.rate, verbose=args.verbose)
