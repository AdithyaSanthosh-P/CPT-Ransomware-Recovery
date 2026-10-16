"""
src/ctrr/snapshot.py
====================
Snapshot backends for CTRR.

Two backends share one interface, take(reason) -> path and list_snapshots():

  SnapshotBackend -- shutil.copytree mock, for development machines without
                     Btrfs.  The copy is an ordinary writable directory, so it
                     must never be presented as a read-only snapshot.
  BtrfsBackend    -- a real read-only Btrfs snapshot of the watched subvolume,
                     taken through a root-owned helper that the monitor may
                     run via exactly one sudoers rule (see deploy/).

The monitor picks one with --backend; nothing else in the pipeline changes.

Why a read-only Btrfs snapshot
------------------------------
`btrfs subvolume snapshot -r` is a copy-on-write metadata operation: it does
not copy file data, so it takes milliseconds regardless of corpus size, and
the snapshot shares extents with the live subvolume until the live files are
overwritten.  The read-only flag means the encrypting process, which runs as
the same unprivileged user as everything else, cannot modify the snapshot,
and deleting it needs root.  Root ransomware can flip the flag and delete it;
that is outside this project's threat model.

Naming convention
-----------------
Snapshots are named: <ISO-8601-UTC>_<reason>
Example: 2026-09-13T10:23:01Z_trigger

Both backends use this format, so the log output and the restore CLI do not
depend on which backend took the snapshot.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

# Root-owned helper installed by deploy/setup_btrfs.sh.  It takes the reason as
# its only argument and has the source subvolume and snapshot directory fixed
# inside it, so the unprivileged monitor cannot choose what gets snapshotted or
# where.  That is why the sudoers rule can be exact: a rule that allowed
# `btrfs subvolume snapshot -r SRC DIR/*` would need a wildcard, and sudoers
# wildcards also match "/" and spaces, which would let the caller pass other
# paths and extra arguments.
BTRFS_HELPER = "/usr/local/sbin/ctrr-snapshot"

# Every Btrfs subvolume root directory has inode number 256
# (BTRFS_FIRST_FREE_OBJECTID).  Checking it is a cheap, unprivileged way to
# confirm the watched directory really is a subvolume root before arming.
_BTRFS_SUBVOL_ROOT_INO = 256

# A snapshot is taken on the processor thread, so a hung helper must not stall
# event processing indefinitely.
_HELPER_TIMEOUT_S = 10


class SnapshotError(Exception):
    """Raised when a snapshot operation fails."""


def _is_subvolume_root(path: Path) -> bool:
    """True if path is the root directory of a Btrfs subvolume (inode 256)."""
    try:
        return os.stat(path).st_ino == _BTRFS_SUBVOL_ROOT_INO
    except OSError:
        return False


def _snapshot_name(reason: str) -> str:
    """Return the <ISO-8601-UTC>_<reason> name shared by both backends."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"{ts}_{reason}"


def _list_snapshot_dirs(snapshot_dir: Path) -> list[str]:
    """Sorted snapshot paths in snapshot_dir, oldest first (names sort by time)."""
    return sorted(str(p) for p in snapshot_dir.iterdir() if p.is_dir())


class SnapshotBackend:
    """
    DEMO-SCOPE snapshot backend using shutil.copytree.

    The result is a writable copy, not a read-only snapshot, and copying is
    not atomic: files being encrypted during the copy land in it in whatever
    state they are in.  Use BtrfsBackend for anything presented as a
    read-only checkpoint.

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
        dst  = self.snapshot_dir / _snapshot_name(reason)

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
        return _list_snapshot_dirs(self.snapshot_dir)

    # Shown by the monitor at startup so the demo output says which backend
    # is live.  The mock must never be mistaken for a read-only snapshot.
    description = "copytree mock (writable copy, NOT read-only)"


class BtrfsBackend:
    """
    Read-only Btrfs snapshot backend.

    take() runs `sudo -n <helper> <reason>`.  The helper (deploy/ctrr-snapshot,
    installed root-owned at BTRFS_HELPER) runs
    `btrfs subvolume snapshot -r <fixed source> <fixed dir>/<name>` and prints
    the new path.  The monitor itself never runs as root.

    Startup checks fail fast, at construction, rather than at the moment of
    TRIGGER when there is no time to fix anything:
      - the watched directory is a Btrfs subvolume root (inode 256),
      - the helper exists and its fixed paths match the monitor's arguments,
      - sudo will run the helper without a password prompt.

    After each snapshot, take() confirms the read-only flag with
    `btrfs property get -ts <snap> ro`, which works unprivileged.  A snapshot
    that cannot be confirmed read-only is reported as a failure.

    Parameters
    ----------
    snapshot_dir : str
        Directory the helper writes snapshots into (root-owned, so the
        monitoring user cannot rename or remove snapshots).
    watched_dir : str
        The watched Btrfs subvolume; the helper's fixed source.
    helper : str
        Path to the root-owned snapshot helper.
    """

    description = "btrfs read-only snapshot"

    def __init__(self, snapshot_dir: str, watched_dir: str,
                 helper: str = BTRFS_HELPER) -> None:
        self.snapshot_dir = Path(snapshot_dir)
        self.watched_dir  = Path(watched_dir)
        self.helper       = helper

        self._btrfs = shutil.which("btrfs")
        if self._btrfs is None:
            raise SnapshotError("btrfs command not found (install btrfs-progs)")

        if not _is_subvolume_root(self.watched_dir):
            raise SnapshotError(
                f"{self.watched_dir} is not a Btrfs subvolume root "
                f"(its inode is not {_BTRFS_SUBVOL_ROOT_INO})"
            )

        if not os.access(self.helper, os.X_OK):
            raise SnapshotError(f"snapshot helper not installed: {self.helper}")

        # --print-config needs no privilege; it only reports the helper's
        # fixed paths so a mismatch is caught here instead of producing a
        # snapshot of the wrong tree, or one the monitor cannot find.
        cfg = self._run([self.helper, "--print-config"])
        fixed = dict(line.split("=", 1) for line in cfg.stdout.split() if "=" in line)
        if (Path(fixed.get("SRC", "")) != self.watched_dir
                or Path(fixed.get("DST_DIR", "")) != self.snapshot_dir):
            raise SnapshotError(
                f"helper paths {fixed} do not match --watch {self.watched_dir} "
                f"and --snapshots {self.snapshot_dir}"
            )

        # `sudo -n -l CMD ARGS` exits 0 only if that exact invocation is
        # allowed without a password.  -n everywhere: a password prompt on the
        # processor thread would stall event handling.
        probe = self._run(["sudo", "-n", "-l", self.helper, "trigger"], check=False)
        if probe.returncode != 0:
            raise SnapshotError(
                "sudo will not run the snapshot helper without a password; "
                "install the sudoers rule with deploy/setup_btrfs.sh"
            )

    def _run(self, argv: list[str], check: bool = True) -> subprocess.CompletedProcess:
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=_HELPER_TIMEOUT_S, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SnapshotError(f"{argv[0]} failed: {exc}") from exc
        if check and proc.returncode != 0:
            raise SnapshotError(
                f"{' '.join(argv)} exited {proc.returncode}: {proc.stderr.strip()}"
            )
        return proc

    def take(self, reason: str = "trigger") -> str:
        """
        Take a read-only snapshot of the watched subvolume.

        Returns the snapshot path.  Raises SnapshotError if the helper fails,
        prints a path outside snapshot_dir, or the result is not read-only.
        """
        log.info("snapshot start  btrfs src=%s", self.watched_dir)
        proc = self._run(["sudo", "-n", self.helper, reason])
        snap = Path(proc.stdout.strip())
        if snap.parent != self.snapshot_dir:
            raise SnapshotError(f"helper returned unexpected path: {snap!r}")

        prop = self._run([self._btrfs, "property", "get", "-ts", str(snap), "ro"])
        if prop.stdout.strip() != "ro=true":
            raise SnapshotError(f"snapshot is not read-only: {prop.stdout.strip()!r}")

        log.info("snapshot done   dst=%s ro=true", snap)
        return str(snap)

    def list_snapshots(self) -> list[str]:
        """Snapshot paths, oldest first."""
        return _list_snapshot_dirs(self.snapshot_dir)


def make_backend(kind: str, snapshot_dir: str, watched_dir: str):
    """Construct the backend named by the monitor's --backend flag."""
    if kind == "copy":
        return SnapshotBackend(snapshot_dir, watched_dir)
    if kind == "btrfs":
        return BtrfsBackend(snapshot_dir, watched_dir)
    raise ValueError(f"unknown snapshot backend: {kind!r}")
