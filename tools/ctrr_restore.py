"""
tools/ctrr_restore.py
=====================
Restore CLI for CTRR.

Provides three subcommands for interacting with snapshots taken by the monitor:

  list     -- Show all available snapshots with timestamps, file counts, and sizes.
  diff     -- Compare a snapshot to the live directory and show what changed.
  restore  -- Copy files from a snapshot back to the live directory, with optional
               SHA-256 manifest verification.

Usage
-----
  python tools/ctrr_restore.py list   --snapshots /tmp/ctrr-snapshots
  python tools/ctrr_restore.py diff   --snapshots /tmp/ctrr-snapshots [--snap NAME]
  python tools/ctrr_restore.py restore --snapshots /tmp/ctrr-snapshots --watch /tmp/corpus
                                        [--snap NAME] [--dry-run] [--verify]

Design decisions
----------------
  - The CLI works against both the shutil.copytree mock (demo) and real Btrfs
    read-only snapshots (production).  The only assumption is that a snapshot is
    a directory whose structure mirrors the watched directory.

  - diff computes a SHA-256 hash of every file in both trees and reports:
      ADDED    -- file exists in live but not in snapshot (likely encrypted by ransomware)
      REMOVED  -- file exists in snapshot but not in live (deleted during attack)
      MODIFIED -- file exists in both but hashes differ (encrypted in place)
      UNCHANGED-- file exists in both with identical hash (not touched)

  - restore copies files from snapshot -> live directory.  With --verify, it
    re-hashes every restored file and compares against the snapshot hash to
    confirm the copy was bit-perfect.  Without --verify, it just copies.

  - With --dry-run, restore prints what would be restored without writing anything.

  - Files are restored one at a time.  If any copy fails, the CLI reports the error
    and continues rather than aborting, so a partial restore is still useful.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------

_HASH_CHUNK = 65536    # 64 KB read chunks for streaming hash


def _sha256(path: Path) -> str:
    """Return the hex SHA-256 digest of a file.  Returns empty string on error."""
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(_HASH_CHUNK)
                if not chunk:
                    break
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def _file_size(path: Path) -> int:
    """Return file size in bytes, or 0 on error."""
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _dir_stats(root: Path) -> tuple[int, int]:
    """Return (file_count, total_bytes) for a directory tree."""
    count, total = 0, 0
    for p in root.rglob("*"):
        if p.is_file():
            count += 1
            total += _file_size(p)
    return count, total


def _human_bytes(n: int) -> str:
    """Format a byte count as a human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ---------------------------------------------------------------------------
# Snapshot discovery
# ---------------------------------------------------------------------------

def _find_snapshots(snapshot_dir: Path) -> list[Path]:
    """Return snapshot subdirectories sorted oldest-first."""
    if not snapshot_dir.exists():
        return []
    return sorted(
        p for p in snapshot_dir.iterdir()
        if p.is_dir()
    )


def _resolve_snap(snapshot_dir: Path, name: str | None) -> Path:
    """
    Return the Path for the requested snapshot.

    If name is None, return the most recent snapshot.
    Raises SystemExit with a helpful message if no snapshots exist or
    the named snapshot cannot be found.
    """
    snaps = _find_snapshots(snapshot_dir)
    if not snaps:
        print(f"ERROR: no snapshots found in {snapshot_dir}", file=sys.stderr)
        sys.exit(1)

    if name is None:
        return snaps[-1]

    # Allow matching by full path or just by directory name.
    for s in snaps:
        if s.name == name or str(s) == name:
            return s

    print(f"ERROR: snapshot '{name}' not found in {snapshot_dir}", file=sys.stderr)
    print("Available snapshots:", file=sys.stderr)
    for s in snaps:
        print(f"  {s.name}", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Subcommand: list
# ---------------------------------------------------------------------------

def cmd_list(args) -> None:
    snapshot_dir = Path(args.snapshots)
    snaps = _find_snapshots(snapshot_dir)

    if not snaps:
        print(f"No snapshots found in {snapshot_dir}")
        return

    print(f"Snapshots in {snapshot_dir}  ({len(snaps)} total)\n")
    print(f"  {'Name':<35}  {'Files':>7}  {'Size':>10}")
    print(f"  {'-'*35}  {'-'*7}  {'-'*10}")
    for snap in snaps:
        count, total = _dir_stats(snap)
        print(f"  {snap.name:<35}  {count:>7}  {_human_bytes(total):>10}")


# ---------------------------------------------------------------------------
# Subcommand: diff
# ---------------------------------------------------------------------------

def _build_hash_map(root: Path) -> dict[str, str]:
    """
    Walk root and return {relative_path_str: sha256_hex} for every file.
    Relative paths use forward slashes for portability.
    """
    result: dict[str, str] = {}
    for p in root.rglob("*"):
        if p.is_file():
            rel = p.relative_to(root).as_posix()
            result[rel] = _sha256(p)
    return result


def cmd_diff(args) -> None:
    snapshot_dir = Path(args.snapshots)
    snap = _resolve_snap(snapshot_dir, args.snap)

    print(f"Comparing snapshot:  {snap.name}")
    print(f"Against live tree:   {args.watch}\n")

    live_root = Path(args.watch)
    if not live_root.exists():
        print(f"ERROR: live directory does not exist: {live_root}", file=sys.stderr)
        sys.exit(1)

    snap_hashes  = _build_hash_map(snap)
    live_hashes  = _build_hash_map(live_root)

    snap_set = set(snap_hashes)
    live_set = set(live_hashes)

    removed   = snap_set - live_set      # in snapshot, gone from live
    added     = live_set - snap_set      # appeared in live (likely encrypted copy)
    common    = snap_set & live_set

    modified  = {f for f in common if snap_hashes[f] != live_hashes[f]}
    unchanged = common - modified

    print(f"  REMOVED   (deleted from live)  : {len(removed)}")
    print(f"  ADDED     (new in live)         : {len(added)}")
    print(f"  MODIFIED  (hash changed)        : {len(modified)}")
    print(f"  UNCHANGED                       : {len(unchanged)}")
    print()

    if args.verbose or (not removed and not added and not modified):
        for f in sorted(removed):
            print(f"  REMOVED    {f}")
        for f in sorted(added):
            print(f"  ADDED      {f}")
        for f in sorted(modified):
            print(f"  MODIFIED   {f}")
    else:
        # Summary mode: only print changed files.
        for f in sorted(removed):
            print(f"  REMOVED    {f}")
        for f in sorted(added):
            print(f"  ADDED      {f}")
        for f in sorted(modified):
            print(f"  MODIFIED   {f}")


# ---------------------------------------------------------------------------
# Subcommand: restore
# ---------------------------------------------------------------------------

def cmd_restore(args) -> None:
    snapshot_dir = Path(args.snapshots)
    snap         = _resolve_snap(snapshot_dir, args.snap)
    live_root    = Path(args.watch)

    dry_run = args.dry_run
    verify  = args.verify

    print(f"Restoring from snapshot:  {snap.name}")
    print(f"Into live directory:      {live_root}")
    if dry_run:
        print("DRY RUN -- no files will be written\n")
    else:
        print()

    snap_hashes = _build_hash_map(snap)

    restored = 0
    failed   = 0
    verified_ok  = 0
    verified_bad = 0

    for rel, snap_hash in sorted(snap_hashes.items()):
        src  = snap  / rel
        dst  = live_root / rel

        if dry_run:
            print(f"  would restore  {rel}")
            continue

        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(str(src), str(dst))
            restored += 1
        except OSError as exc:
            print(f"  FAILED  {rel}  ({exc})", file=sys.stderr)
            failed += 1
            continue

        if verify:
            live_hash = _sha256(dst)
            if live_hash == snap_hash:
                verified_ok += 1
            else:
                print(f"  VERIFY FAIL  {rel}  (hash mismatch after copy)", file=sys.stderr)
                verified_bad += 1

    if dry_run:
        print(f"\n  Would restore {len(snap_hashes)} files.")
        return

    print(f"\nRestore complete.")
    print(f"  Restored : {restored}")
    if failed:
        print(f"  Failed   : {failed}  (check stderr)")
    if verify:
        print(f"  Verified : {verified_ok} ok  /  {verified_bad} bad")
        if verified_bad:
            print("  WARNING: some files failed hash verification.", file=sys.stderr)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="CTRR restore CLI -- list and recover from snapshots"
    )
    sub = p.add_subparsers(dest="command", required=True)

    # -- list ----------------------------------------------------------------
    p_list = sub.add_parser("list", help="List available snapshots")
    p_list.add_argument(
        "--snapshots", required=True, metavar="DIR",
        help="Snapshot storage directory (same as monitor --snapshots)"
    )

    # -- diff ----------------------------------------------------------------
    p_diff = sub.add_parser("diff", help="Show what changed between a snapshot and live")
    p_diff.add_argument(
        "--snapshots", required=True, metavar="DIR",
        help="Snapshot storage directory"
    )
    p_diff.add_argument(
        "--watch", required=True, metavar="DIR",
        help="Live directory to compare against"
    )
    p_diff.add_argument(
        "--snap", default=None, metavar="NAME",
        help="Snapshot name or path (default: most recent)"
    )
    p_diff.add_argument(
        "--verbose", "-v", action="store_true",
        help="Print all files including unchanged"
    )

    # -- restore -------------------------------------------------------------
    p_restore = sub.add_parser("restore", help="Restore files from a snapshot")
    p_restore.add_argument(
        "--snapshots", required=True, metavar="DIR",
        help="Snapshot storage directory"
    )
    p_restore.add_argument(
        "--watch", required=True, metavar="DIR",
        help="Live directory to restore into"
    )
    p_restore.add_argument(
        "--snap", default=None, metavar="NAME",
        help="Snapshot name or path (default: most recent)"
    )
    p_restore.add_argument(
        "--dry-run", action="store_true",
        help="Print what would be restored without writing any files"
    )
    p_restore.add_argument(
        "--verify", action="store_true",
        help="SHA-256 verify every restored file against the snapshot hash"
    )

    return p.parse_args(argv)


def main(argv=None) -> None:
    args = _parse_args(argv)
    if args.command == "list":
        cmd_list(args)
    elif args.command == "diff":
        cmd_diff(args)
    elif args.command == "restore":
        cmd_restore(args)


if __name__ == "__main__":
    main()
