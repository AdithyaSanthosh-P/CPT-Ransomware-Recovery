#!/usr/bin/env bash
# =============================================================================
# CTRR — Module 9: Snapshot & Restoration (~65% complete)
# =============================================================================
# WHAT THIS DEMO MEANS: the snapshot backend module in isolation, without
# the daemon/attack around it. The full live version of this (list / diff /
# restore --verify against a real triggered snapshot) is covered in
# Section 0.3 of the end-to-end demo.
#
# WHAT THE OUTPUT MEANS:
#   "snapshot at: ..."   -> a snapshot directory was created under
#                           /tmp/demo-snaps, taken from /tmp/test-corpus
#   "all snapshots: [...]" -> list_snapshots() enumerating what exists —
#                           this is the same call the restore CLI's `list`
#                           subcommand uses in Section 0.3
#
# KNOWN GAP: this is shutil.copytree, NOT real Btrfs — say so explicitly.
# The interface (take(), list_snapshots()) is designed to be a drop-in
# swap for `subprocess.run(["btrfs","subvolume","snapshot","-r",...])`
# without touching monitor.py — that's the answer to "does this only work
# on Btrfs?"
# =============================================================================
set -uo pipefail
# Repo root, found from this script's own location so a fresh clone works anywhere.
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT" || { echo "Set PROJECT_ROOT at the top of this script."; exit 1; }

python -c "
from ctrr.snapshot import SnapshotBackend
sb = SnapshotBackend('/tmp/demo-snaps', '/tmp/test-corpus')
path = sb.take(reason='demo')
print('snapshot at:', path)
print('all snapshots:', sb.list_snapshots())
"
