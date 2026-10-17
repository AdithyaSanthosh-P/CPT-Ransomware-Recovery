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
  python -m ctrr.monitor --backend btrfs --watch /mnt/ctrr/data --snapshots /mnt/ctrr/.snapshots

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
import json
import logging
import signal
import sys
import threading
from pathlib import Path

from ctrr.extractor import OP_CLOSE_WRITE, ExtractorPipeline, FileEvent
from ctrr.scorer import ArbiterState, Scorer
from ctrr.snapshot import SnapshotError, make_backend
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

    def __init__(self, watch_root: str, snapshot_dir: str,
                 trace_path: str | None = None, backend: str = "copy") -> None:
        self._pipeline   = ExtractorPipeline()
        self._scorer     = Scorer()
        # "copy" (the mock) stays the default so development machines without
        # Btrfs keep working; "btrfs" raises SnapshotError here if the
        # subvolume, helper or sudoers rule is not in place.
        self._snapshot   = make_backend(backend, snapshot_dir, watch_root)
        self._watcher    = Watcher(watch_root, callback=self._on_event)
        self._last_state = ArbiterState.NORMAL
        # None means telemetry is disabled; a Path means append to that file.
        self._trace_path = Path(trace_path) if trace_path else None
        # No lock needed: _on_event is always called from the watcher's single
        # processor thread.  If a future version adds parallel callbacks,
        # a lock must be added here.

    def start(self) -> None:
        """Enrol the directory, then start the watcher threads."""
        self._pipeline.enrol_directory(self._watcher.watch_root)
        self._watcher.start()
        print("[NORMAL]   watching", self._watcher.watch_root, flush=True)
        print(f"           snapshots: {self._snapshot.description}"
              f" -> {self._snapshot.snapshot_dir}", flush=True)

    def stop(self) -> None:
        """Stop the watcher threads cleanly."""
        self._watcher.stop()

    # ------------------------------------------------------------------
    # Event callback -- called from the watcher's processor thread
    # ------------------------------------------------------------------

    def _on_event(self, event: FileEvent) -> None:
        scores = self._pipeline.process_event(event)

        # DEMO-SCOPE FIX: only re-evaluate the arbiter on IN_CLOSE_WRITE.
        # scorer.tick() is currently called once per raw event rather than on
        # a fixed 500ms cadence (see docs/modules.md Module 6, "pending").
        # Ticking on IN_MOVED_FROM/IN_MOVED_TO too means 2 of every 3 ticks
        # per encrypted file carry a near-zero fused score (rename events
        # have no entropy signal), which decays the leaky integrator faster
        # than the IN_CLOSE_WRITE ticks can raise it -- the accumulator
        # plateaus around 0.26 and TRIGGER never fires, even after 100 files.
        # Restricting ticks to IN_CLOSE_WRITE removes that dilution. The
        # extractors still see every event so their sliding windows stay
        # correct; only the arbiter's cadence changes. Proper fix is the
        # independent 500ms timer already noted as pending.
        if event.op != OP_CLOSE_WRITE:
            return
        state  = self._scorer.tick(scores, event.mono_ts)

        # Telemetry records EVERY tick, NORMAL included.  Logging only
        # non-NORMAL ticks (the earlier behaviour) dropped the quiet ticks
        # the accumulator decays on, so a saved trace could not be replayed
        # to the same accumulator values and had no negative examples for
        # training Model B (audit bug B1).
        self._emit_trace(event, scores, state)

        if state == self._last_state and state == ArbiterState.NORMAL:
            # Stay quiet on the terminal while everything is normal.
            return

        label = _LABEL.get(state, f"[{state.value}]")

        if state == ArbiterState.TRIGGER:
            print(
                f"{label} quorum met"
                f"  entropy={scores.entropy:.2f}"
                f"  rate={scores.rate:.2f}"
                f"  ext={scores.extension:.2f}"
                f"  fused={self._scorer.fused_score:.2f}"
                f"  acc={self._scorer.accumulator:.2f}",
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
                f"  fused={self._scorer.fused_score:.2f}"
                f"  acc={self._scorer.accumulator:.2f}",
                flush=True,
            )

        elif state == ArbiterState.NORMAL and self._last_state != ArbiterState.NORMAL:
            print(f"{label}  activity normal", flush=True)

        elif state == ArbiterState.COOLDOWN and self._last_state != ArbiterState.COOLDOWN:
            print(f"{label} waiting 30s before re-arming", flush=True)

        self._last_state = state

    def _emit_trace(self, event: FileEvent, scores, state: ArbiterState) -> None:
        """Append one JSONL record to the trace file if telemetry is enabled.

        Each record captures everything needed to re-score this tick offline:
        all four sub-scores, the fused value, the accumulator, the state and
        the originating file event for attribution.  Values are written at
        full float precision (no rounding) so that replaying the trace under
        the same policy reproduces the live accumulator and state sequence
        exactly; rounding to 4 decimals could flip a threshold comparison.
        "type":"tick" distinguishes these from the "marker" records the
        attack simulator writes into the same file (ground truth).
        """
        if self._trace_path is None:
            return
        record = {
            "type":        "tick",
            "mono_ts":     event.mono_ts,
            "state":       state.value,
            "entropy":     scores.entropy,
            "rate":        scores.rate,
            "extension":   scores.extension,
            "spread":      scores.spread,
            "fused":       self._scorer.fused_score,
            "accumulator": self._scorer.accumulator,
            "path":        event.path,
            "op":          event.op,
        }
        with self._trace_path.open("a") as fh:
            fh.write(json.dumps(record) + "\n")


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
    p.add_argument(
        "--trace", default=None, metavar="FILE",
        help="Optional path for JSONL telemetry trace (e.g. /tmp/ctrr-trace.jsonl)."
             " Every tick is appended as one JSON line.",
    )
    p.add_argument(
        "--backend", choices=("copy", "btrfs"), default="copy",
        help="Snapshot backend: 'copy' is the copytree mock (writable copy);"
             " 'btrfs' takes a read-only Btrfs snapshot via the root-owned"
             " helper installed by deploy/setup_btrfs.sh (default: copy)",
    )
    return p.parse_args(argv)


def main(argv=None) -> None:
    args = _parse_args(argv)
    try:
        monitor = Monitor(
            watch_root=args.watch,
            snapshot_dir=args.snapshots,
            trace_path=args.trace,
            backend=args.backend,
        )
    except SnapshotError as exc:
        sys.exit(f"ERROR: snapshot backend not ready: {exc}")
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
