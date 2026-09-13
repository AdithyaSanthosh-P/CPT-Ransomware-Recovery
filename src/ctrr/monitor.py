"""
src/ctrr/monitor.py
===================
Main entry point for the CTRR demo.

Ties together the four components:

  Watcher        -- produces FileEvents from inotify
  ExtractorPipeline -- converts FileEvents to SubScores
  Scorer         -- fuses SubScores into ArbiterState
  SnapshotBackend -- takes a copy of the watched directory on TRIGGER

Usage
-----
  python -m ctrr.monitor --watch /tmp/test-corpus [--snapshots /tmp/snapshots]

Output (stdout, line-buffered)
------------------------------
  [NORMAL]   activity normal
  [SUSPECT]  entropy=0.61 rate=0.34 ext=0.00 fused=0.39
  [TRIGGER]  quorum met  entropy=0.92 rate=0.88 ext=0.80 fused=0.87
             snapshot -> /tmp/snapshots/2026-09-13T10:23:01Z_trigger
  [COOLDOWN] waiting 30s before re-arming

Design decisions
----------------
  - The monitor is intentionally thin.  No business logic lives here; it
    only wires components and formats log lines.

  - process_event is called from the watcher's processor thread.  The
    scorer.tick() and snapshot.take() calls happen in that same thread, so
    the watcher's callback must return quickly.  shutil.copytree on a small
    demo corpus (< 1000 files) completes in well under a second, which is
    acceptable for the demo.  The full system moves copytree to a separate
    snapshot thread.

  - The 500ms fusion tick from the architecture doc is approximated here by
    calling scorer.tick() on every event.  For the demo rate of events this
    is equivalent.  The full system uses a threading.Timer to fire the tick
    independently of event arrival.
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading

from ctrr.extractor import ExtractorPipeline, FileEvent
from ctrr.scorer import ArbiterState, Scorer
from ctrr.snapshot import SnapshotBackend, SnapshotError
from ctrr.watcher import Watcher

logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s %(name)s %(message)s",
    stream=sys.stderr,
)

# State labels printed to stdout so the demo terminal shows clean output.
_LABEL = {
    ArbiterState.NORMAL:   "[NORMAL]  ",
    ArbiterState.SUSPECT:  "[SUSPECT] ",
    ArbiterState.TRIGGER:  "[TRIGGER] ",
    ArbiterState.COOLDOWN: "[COOLDOWN]",
}


class Monitor:
    """
    Wires watcher -> extractors -> scorer -> snapshot into a running daemon.
    """

    def __init__(self, watch_root: str, snapshot_dir: str) -> None:
        self._pipeline = ExtractorPipeline()
        self._scorer   = Scorer()
        self._snapshot = SnapshotBackend(snapshot_dir, watch_root)
        self._watcher  = Watcher(watch_root, callback=self._on_event)
        self._last_state = ArbiterState.NORMAL
        # No lock needed: _on_event is always called from the watcher's single
        # processor thread.  If a future version adds parallel callbacks,
        # a lock must be added here.

    def start(self) -> None:
        """Enrol the directory, then start the watcher threads."""
        self._pipeline.enrol_directory(self._watcher.watch_root)
        self._watcher.start()
        print("[NORMAL]   watching", self._watcher.watch_root, flush=True)

    def stop(self) -> None:
        """Stop the watcher threads cleanly."""
        self._watcher.stop()

    # ------------------------------------------------------------------
    # Event callback -- called from the watcher's processor thread
    # ------------------------------------------------------------------

    def _on_event(self, event: FileEvent) -> None:
        scores = self._pipeline.process_event(event)
        state  = self._scorer.tick(scores, event.mono_ts)

        if state == self._last_state and state == ArbiterState.NORMAL:
            # Stay quiet while everything is normal.
            return

        label = _LABEL.get(state, f"[{state.value}]")

        if state == ArbiterState.TRIGGER:
            print(
                f"{label} quorum met"
                f"  entropy={scores.entropy:.2f}"
                f"  rate={scores.rate:.2f}"
                f"  ext={scores.extension:.2f}"
                f"  fused={self._scorer.fused_score:.2f}",
                flush=True,
            )
            try:
                snap_path = self._snapshot.take(reason="trigger")
                print(f"           snapshot -> {snap_path}", flush=True)
            except SnapshotError as exc:
                print(f"           snapshot FAILED: {exc}", flush=True)

        elif state == ArbiterState.SUSPECT:
            print(
                f"{label}"
                f" entropy={scores.entropy:.2f}"
                f"  rate={scores.rate:.2f}"
                f"  ext={scores.extension:.2f}"
                f"  fused={self._scorer.fused_score:.2f}",
                flush=True,
            )

        elif state == ArbiterState.NORMAL and self._last_state != ArbiterState.NORMAL:
            print(f"{label}  activity normal", flush=True)

        elif state == ArbiterState.COOLDOWN and self._last_state != ArbiterState.COOLDOWN:
            print(f"{label} waiting 30s before re-arming", flush=True)

        self._last_state = state


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="CTRR monitor -- copy-time ransomware recovery daemon (demo mode)"
    )
    p.add_argument(
        "--watch", required=True, metavar="DIR",
        help="Directory tree to watch for ransomware activity",
    )
    p.add_argument(
        "--snapshots", default="/tmp/ctrr-snapshots", metavar="DIR",
        help="Directory where snapshots are stored (default: /tmp/ctrr-snapshots)",
    )
    return p.parse_args(argv)


def main(argv=None) -> None:
    args = _parse_args(argv)
    monitor = Monitor(watch_root=args.watch, snapshot_dir=args.snapshots)
    monitor.start()

    stop_event = threading.Event()

    def _handle_signal(signum, frame):
        print("\n[NORMAL]   shutting down", flush=True)
        stop_event.set()

    signal.signal(signal.SIGINT,  _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    stop_event.wait()
    monitor.stop()


if __name__ == "__main__":
    main()
