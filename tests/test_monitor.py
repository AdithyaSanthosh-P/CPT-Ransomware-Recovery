"""
tests/test_monitor.py
=====================
Unit tests for the tick cadence in src/ctrr/monitor.py.

The monitor feeds every event to the extractors but advances the arbiter
only on IN_CLOSE_WRITE (the DEMO-SCOPE stopgap documented in
Monitor._on_event).  These tests pin that behaviour so the stopgap cannot
silently regress before the independent 500 ms timer replaces it.

The watcher threads are never started: events are passed straight to
_on_event, so no inotify activity is involved.
"""

import pytest

from ctrr.extractor import (
    OP_CLOSE_WRITE,
    OP_CREATE,
    OP_DELETE,
    OP_MOVED_FROM,
    OP_MOVED_TO,
    FileEvent,
)
from ctrr.monitor import Monitor


@pytest.fixture
def monitor(tmp_path):
    watch = tmp_path / "watch"
    watch.mkdir()
    m = Monitor(str(watch), str(tmp_path / "snaps"))
    yield m
    # The watcher opened an inotify fd in its constructor; close it.
    m._watcher._inotify.close()


@pytest.fixture
def tick_calls(monitor, monkeypatch):
    """Record every Scorer.tick call made by the monitor."""
    calls = []
    real_tick = monitor._scorer.tick

    def recording_tick(scores, mono_ts):
        calls.append(mono_ts)
        return real_tick(scores, mono_ts)

    monkeypatch.setattr(monitor._scorer, "tick", recording_tick)
    return calls


class TestTickCadence:
    @pytest.mark.parametrize("op", [OP_MOVED_FROM, OP_MOVED_TO, OP_CREATE, OP_DELETE])
    def test_non_close_write_does_not_tick(self, monitor, tick_calls, tmp_path, op):
        monitor._on_event(FileEvent(path=str(tmp_path / "watch" / "a"), op=op, mono_ts=1))
        assert tick_calls == []

    def test_close_write_ticks_once(self, monitor, tick_calls, tmp_path):
        monitor._on_event(FileEvent(path=str(tmp_path / "watch" / "a"), op=OP_CLOSE_WRITE, mono_ts=7))
        assert tick_calls == [7]

    def test_extractors_still_see_rename_events(self, monitor, tick_calls, tmp_path):
        # A rename to a novel suffix must still reach the extension extractor
        # even though it does not tick the arbiter.
        w = tmp_path / "watch"
        monitor._on_event(FileEvent(path=str(w / "a.txt.enc"), op=OP_MOVED_TO,
                                    mono_ts=1, src_path=str(w / "a.txt")))
        assert tick_calls == []
        assert monitor._pipeline.latest().extension > 0.0
