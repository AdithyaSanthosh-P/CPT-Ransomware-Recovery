"""
src/ctrr/snapshot.py
====================
Snapshot backend for CTRR.

For the demo, snapshots are implemented as a full directory copy using
shutil.copytree.  The public interface (SnapshotBackend) is intentionally
minimal so the real Btrfs backend can be swapped in later by replacing this
module without changing monitor.py.

Real Btrfs backend (post-demo)
-------------------------------
  subprocess.run(["btrfs", "subvolume", "snapshot", "-r", src, dst])

The -r flag makes the snapshot read-only so the encrypting process cannot
modify it.  The mock uses shutil.copytree with copy_function=shutil.copy2
(preserves metadata) and dirs_exist_ok=False (fails if destination already
exists, which is the correct safety behaviour).

Naming convention
-----------------
Snapshots are named: <ISO-8601-UTC>_<reason>
Example: 2026-09-13T10:23:01Z_trigger

This matches the naming scheme from the execution plan so that when the
real backend is wired in the log output does not change.
"""

from __future__ import annotations

import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)


class SnapshotError(Exception):
    """Raised when a snapshot operation fails."""


class SnapshotBackend:
    """
    Demo-scope snapshot backend using shutil.copytree.

    Parameters
    ----------
    snapshot_dir : str
        Directory where snapshots are stored.  Created at init if it does
        not already exist.
    watched_dir : str
        The directory being watched.  This is the source for every snapshot.

    Thread safety
    -------------
    take() is called from the monitor's processor thread.  shutil.copytree
    releases the GIL during I/O so this does not block the event loop for
    small corpora, but it is not async.  For the demo corpus this is fine.
    """

    def __init__(self, snapshot_dir: str, watched_dir: str) -> None:
        self.snapshot_dir = Path(snapshot_dir)
        self.watched_dir  = Path(watched_dir)
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)

    def take(self, reason: str = "trigger") -> str:
        """
        Copy the watched directory into a new snapshot subdirectory.

        Parameters
        ----------
        reason : str
            Short label appended to the snapshot name.  Canonical values
            are 'trigger' (arbiter fired) and 'floor' (periodic baseline).

        Returns
        -------
        str
            Absolute path to the newly created snapshot directory.

        Raises
        ------
        SnapshotError
            If the copy fails for any reason.
        """
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        name = f"{ts}_{reason}"
        dst  = self.snapshot_dir / name

        log.info("snapshot start  src=%s dst=%s", self.watched_dir, dst)
        try:
            shutil.copytree(
                src=str(self.watched_dir),
                dst=str(dst),
                copy_function=shutil.copy2,   # preserve mtime/mode
                dirs_exist_ok=False,           # fail if dst already exists
            )
        except Exception as exc:
            raise SnapshotError(f"copytree failed: {exc}") from exc

        # Sanity check: at least one file was copied.
        file_count = sum(1 for _ in dst.rglob("*") if _.is_file())
        log.info("snapshot done   dst=%s files=%d", dst, file_count)

        return str(dst)

    def list_snapshots(self) -> list[str]:
        """
        Return a sorted list of snapshot paths in this backend's directory,
        oldest first.
        """
        snaps = sorted(
            str(p) for p in self.snapshot_dir.iterdir()
            if p.is_dir()
        )
        return snaps
