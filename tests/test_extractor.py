"""
tests/test_extractor.py
=======================
Unit tests for src/ctrr/extractor.py.

Each extractor is tested in isolation using hand-built FileEvent sequences.
EntropyExtractor requires real files; pytest's tmp_path fixture creates them
in a temporary directory that is cleaned up automatically after each test.

Test strategy mirrors the M4 done-when criteria from the execution plan:
  - Hand-built event sequences with hand-computed expected outputs.
  - Property tests asserting every sub-score stays in [0, 1].

No mocking framework is used.  The tests are plain functions that construct
FileEvent objects directly and assert on the return value of .score().
"""

import os

import pytest

from ctrr.extractor import (
    OP_CLOSE_WRITE,
    OP_CREATE,
    OP_MOVED_FROM,
    OP_MOVED_TO,
    _EXTENSION_CEILING,
    _EXTENSION_WINDOW_NS,
    _RATE_CEILING_WPS,
    _RATE_WINDOW_NS,
    _SPREAD_CEILING,
    _SPREAD_WINDOW_NS,
    EntropyExtractor,
    ExtensionExtractor,
    ExtractorPipeline,
    FileEvent,
    RateExtractor,
    SpreadExtractor,
    SubScores,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def make_event(path: str, op: str, mono_ts: int = 0, src_path=None) -> FileEvent:
    """Construct a FileEvent with defaults suitable for unit tests."""
    return FileEvent(path=path, op=op, mono_ts=mono_ts, src_path=src_path)


def make_close_write(path: str, mono_ts: int = 0) -> FileEvent:
    return make_event(path, OP_CLOSE_WRITE, mono_ts=mono_ts)


def make_rename(src: str, dst: str, mono_ts: int = 0) -> FileEvent:
    """Produce the MOVED_TO half of a rename pair, as the watcher would."""
    return make_event(dst, OP_MOVED_TO, mono_ts=mono_ts, src_path=src)


# ---------------------------------------------------------------------------
# EntropyExtractor
# ---------------------------------------------------------------------------

class TestEntropyExtractor:
    """
    EntropyExtractor reads the actual file on every IN_CLOSE_WRITE event.
    All tests that need a file use the tmp_path fixture; tests for error
    cases pass a path that does not exist.
    """

    def test_cold_start_scores_neutral(self, tmp_path):
        """
        The first write to a previously unseen path must score 0.0.
        The extractor records the baseline and returns neutral because there
        is no prior state to measure a delta against.  Scoring suspicious
        here would produce a false positive on every newly created file.
        """
        p = tmp_path / "doc.txt"
        p.write_text("hello world")
        ext = EntropyExtractor()
        assert ext.score(make_close_write(str(p))) == 0.0

    def test_entropy_increase_scores_positive(self, tmp_path):
        """
        Overwriting a low-entropy file with high-entropy bytes simulates
        in-place encryption.  The delta must be > 0 and <= 1.
        """
        p = tmp_path / "doc.txt"
        p.write_bytes(b"a" * 4096)               # near-zero entropy baseline
        ext = EntropyExtractor()
        ext.score(make_close_write(str(p)))       # enrol; scores neutral

        p.write_bytes(os.urandom(4096))           # high-entropy overwrite
        score = ext.score(make_close_write(str(p)))
        assert score > 0.0
        assert score <= 1.0

    def test_entropy_near_ceiling_scores_one(self, tmp_path):
        """
        Null bytes (entropy ~0) overwritten with random bytes (entropy ~8
        bits/byte) produce a delta near the 4-bit normalisation ceiling,
        so the score should be close to 1.0.
        """
        p = tmp_path / "doc.bin"
        p.write_bytes(b"\x00" * 4096)            # entropy ~= 0.0
        ext = EntropyExtractor()
        ext.score(make_close_write(str(p)))       # enrol

        p.write_bytes(os.urandom(4096))           # entropy ~= 8.0
        score = ext.score(make_close_write(str(p)))
        assert score == pytest.approx(1.0, abs=0.05)

    def test_entropy_decrease_scores_zero(self, tmp_path):
        """
        Overwriting a high-entropy file with low-entropy data produces a
        negative delta.  The extractor must return 0.0 -- a drop in entropy
        is not a ransomware signal.
        """
        p = tmp_path / "doc.bin"
        p.write_bytes(os.urandom(4096))          # high-entropy baseline
        ext = EntropyExtractor()
        ext.score(make_close_write(str(p)))       # enrol

        p.write_bytes(b"\x00" * 4096)            # low-entropy overwrite
        assert ext.score(make_close_write(str(p))) == 0.0

    def test_non_close_write_ignored(self, tmp_path):
        """
        Non-IN_CLOSE_WRITE events must return 0.0 immediately.  Only a closed
        write carries meaningful entropy information.
        """
        p = tmp_path / "doc.txt"
        p.write_text("hello")
        ext = EntropyExtractor()
        assert ext.score(make_event(str(p), OP_CREATE)) == 0.0
        assert ext.score(make_event(str(p), OP_MOVED_FROM)) == 0.0

    def test_read_error_scores_neutral_and_counted(self):
        """
        If the file cannot be read (ENOENT, EACCES), score must be 0.0 and
        read_errors must increment.  Counting errors separately from drops
        is required so the operator can distinguish kernel overflows from
        filesystem permission issues.
        """
        ext = EntropyExtractor()
        assert ext.read_errors == 0
        score = ext.score(make_close_write("/nonexistent/path/file.txt"))
        assert score == 0.0
        assert ext.read_errors == 1

    def test_enrol_file_warms_baseline(self, tmp_path):
        """
        enrol_file() pre-populates the baseline so that the first
        post-enrolment event produces a meaningful delta rather than
        scoring neutral as cold-start would.
        """
        p = tmp_path / "doc.bin"
        p.write_bytes(b"\x00" * 4096)           # low entropy
        ext = EntropyExtractor()
        ext.enrol_file(str(p))                  # warm the cache

        p.write_bytes(os.urandom(4096))         # high-entropy overwrite
        score = ext.score(make_close_write(str(p)))
        assert score > 0.0

    def test_score_always_in_range(self, tmp_path):
        """Property: score is in [0, 1] for any file content."""
        p = tmp_path / "doc.bin"
        ext = EntropyExtractor()
        for content in [b"\x00" * 4096, os.urandom(4096), b"abc" * 300]:
            p.write_bytes(content)
            score = ext.score(make_close_write(str(p)))
            assert 0.0 <= score <= 1.0, f"score {score} out of range"


# ---------------------------------------------------------------------------
# RateExtractor
# ---------------------------------------------------------------------------

class TestRateExtractor:
    """
    RateExtractor tracks only monotonic timestamps; it never touches the
    filesystem.  All tests construct FileEvent objects with explicit mono_ts
    values (nanoseconds) to control the sliding window precisely.

    Window width: _RATE_WINDOW_NS nanoseconds (5 seconds).
    Ceiling:      _RATE_CEILING_WPS writes per second (50 wps).
    Score:        min(1.0, rate / ceiling).
    """

    def test_idle_scores_zero(self):
        """No IN_CLOSE_WRITE events means rate is 0; score must be 0.0."""
        ext = RateExtractor()
        score = ext.score(make_event("/tmp/x", OP_CREATE, mono_ts=0))
        assert score == 0.0

    def test_non_close_write_not_counted(self):
        """
        Only IN_CLOSE_WRITE events contribute to the rate.  Feeding other
        event types, even in large numbers, must leave the score at 0.0.
        """
        ext = RateExtractor()
        for i in range(1000):
            score = ext.score(make_event("/tmp/x", OP_CREATE, mono_ts=i * 1_000_000))
        assert score == 0.0

    def test_score_at_half_ceiling(self):
        """
        Feeding exactly (CEILING / 2) * window_sec events at timestamp 0
        should yield score ~= 0.5.

        Derivation (ceiling = _RATE_CEILING_WPS = 5.0 wps, window = 5 s):
          window_sec    = _RATE_WINDOW_NS / 1e9  (5 s)
          target_rate   = _RATE_CEILING_WPS / 2  (2.5 wps)
          events_needed = target_rate * window_sec = 12  (int truncation)
          rate          = 12 / 5 = 2.4 wps
          score         = 2.4 / 5.0 = 0.48
        abs tolerance is 0.03 to absorb int() truncation (12 vs 12.5 events).
        """
        window_sec = _RATE_WINDOW_NS / 1e9
        target_count = int((_RATE_CEILING_WPS / 2) * window_sec)
        ext = RateExtractor()
        for _ in range(target_count):
            score = ext.score(make_close_write("/tmp/x", mono_ts=0))
        assert score == pytest.approx(0.5, abs=0.03)

    def test_score_capped_at_one(self):
        """Score must not exceed 1.0 regardless of how high the rate climbs."""
        ext = RateExtractor()
        for _ in range(10_000):
            score = ext.score(make_close_write("/tmp/x", mono_ts=0))
        assert score == 1.0

    def test_window_eviction_drops_score(self):
        """
        After old events age out of the sliding window the score must fall.
        All events at T=0 are evicted when a new event arrives at T=6s,
        because the cutoff = 6s - 5s = 1s, and all T=0 events are < 1s.

        Only the single new event remains in the window.
        Rate = 1 / 5 = 0.2 wps; score = 0.2 / 50 = 0.004.
        """
        ext = RateExtractor()
        for _ in range(500):
            ext.score(make_close_write("/tmp/x", mono_ts=0))

        late_ts = _RATE_WINDOW_NS + 1_000_000_000   # 6 seconds in ns
        score = ext.score(make_close_write("/tmp/x", mono_ts=late_ts))
        assert score < 0.05

    def test_score_always_in_range(self):
        """Property: every sub-score is in [0, 1]."""
        ext = RateExtractor()
        for i in range(500):
            score = ext.score(make_close_write("/tmp/x", mono_ts=i * 1_000_000))
            assert 0.0 <= score <= 1.0, f"score {score} out of range at i={i}"


# ---------------------------------------------------------------------------
# ExtensionExtractor
# ---------------------------------------------------------------------------

class TestExtensionExtractor:
    """
    ExtensionExtractor tracks rename pairs in a sliding window.
    It needs no filesystem access; only event metadata (paths, timestamps)
    are used.

    Window width: _EXTENSION_WINDOW_NS nanoseconds (10 seconds).
    Ceiling:      _EXTENSION_CEILING distinct novel extensions (5).
    Score:        min(1.0, len(novel_extensions) / ceiling).
    """

    def test_no_renames_scores_zero(self):
        """Without any rename events the window is empty; score must be 0.0."""
        ext = ExtensionExtractor()
        score = ext.score(make_close_write("/tmp/doc.txt"))
        assert score == 0.0

    def test_same_extension_rename_not_counted(self):
        """
        A rename that preserves the extension (e.g. atomic temp-file swap)
        must not count as a novel extension event.
        foo.txt -> bar.txt : src_ext == dst_ext == '.txt', no increment.
        """
        ext = ExtensionExtractor()
        score = ext.score(make_rename("/tmp/doc.txt", "/tmp/doc2.txt"))
        assert score == 0.0

    def test_rename_without_src_path_ignored(self):
        """
        An unpaired MOVED_TO (src_path is None) cannot be scored for an
        extension change.  The extractor must ignore it and return 0.0.
        """
        ext = ExtensionExtractor()
        score = ext.score(make_event("/tmp/doc.enc", OP_MOVED_TO, mono_ts=0))
        assert score == 0.0

    def test_single_novel_extension_scores_between_zero_and_one(self):
        """
        One rename introducing a new suffix scores 1 / _EXTENSION_CEILING,
        which is > 0 and < 1 (given ceiling >= 2).
        """
        ext = ExtensionExtractor()
        score = ext.score(make_rename("/tmp/doc.txt", "/tmp/doc.txt.enc"))
        assert 0.0 < score < 1.0

    def test_ceiling_capped_at_one(self):
        """
        Once the ceiling number of distinct novel extensions is observed,
        the score must be exactly 1.0 and must not exceed it.
        """
        ext = ExtensionExtractor()
        score = 0.0
        for i in range(_EXTENSION_CEILING + 5):
            score = ext.score(
                make_rename(f"/tmp/file{i}.txt", f"/tmp/file{i}.ext{i}", mono_ts=0)
            )
        assert score == 1.0

    def test_window_eviction_drops_score(self):
        """
        After old renames age out of the 10-second window the score must
        drop.  An event at T=11s evicts everything at T=0.
        """
        ext = ExtensionExtractor()
        for i in range(_EXTENSION_CEILING + 2):
            ext.score(
                make_rename(f"/tmp/file{i}.txt", f"/tmp/file{i}.ext{i}", mono_ts=0)
            )

        late_ts = _EXTENSION_WINDOW_NS + 1_000_000_000   # 11 seconds in ns
        score = ext.score(make_close_write("/tmp/x", mono_ts=late_ts))
        assert score == 0.0

    def test_irrelevant_ops_return_zero(self):
        """Non-rename operations must be ignored and return 0.0."""
        ext = ExtensionExtractor()
        for op in (OP_CLOSE_WRITE, OP_CREATE, OP_MOVED_FROM):
            assert ext.score(make_event("/tmp/x.txt", op)) == 0.0

    def test_score_always_in_range(self):
        """Property: every sub-score is in [0, 1]."""
        ext = ExtensionExtractor()
        for i in range(100):
            score = ext.score(
                make_rename(f"/tmp/a{i}.txt", f"/tmp/a{i}.enc",
                            mono_ts=i * 1_000_000)
            )
            assert 0.0 <= score <= 1.0, f"score {score} out of range at i={i}"


# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# ExtractorPipeline integration
# ---------------------------------------------------------------------------

class TestExtractorPipeline:
    """
    Integration smoke tests for the pipeline wrapper.  These verify that the
    four extractors are wired correctly and that the public interface
    (process_event / latest / enrol_directory) behaves as documented.
    """

    def test_process_event_returns_subscores(self, tmp_path):
        """process_event() must return a SubScores with all fields in [0, 1]."""
        p = tmp_path / "doc.txt"
        p.write_text("hello world")
        pipeline = ExtractorPipeline()
        scores = pipeline.process_event(make_close_write(str(p)))
        assert isinstance(scores, SubScores)
        assert 0.0 <= scores.entropy   <= 1.0
        assert 0.0 <= scores.rate      <= 1.0
        assert 0.0 <= scores.extension <= 1.0
        assert 0.0 <= scores.spread    <= 1.0

    def test_latest_reflects_last_event(self, tmp_path):
        """latest() must return the SubScores from the most recent process_event()."""
        p = tmp_path / "doc.txt"
        p.write_text("hello")
        pipeline = ExtractorPipeline()
        scores = pipeline.process_event(make_close_write(str(p)))
        assert pipeline.latest() is scores

    def test_enrol_directory_warms_entropy_cache(self, tmp_path):
        """
        After enrol_directory(), the entropy extractor has a baseline for
        every file in the tree.  An IN_CLOSE_WRITE on a pre-enrolled low-
        entropy file overwritten with random bytes must score positively,
        not neutrally as cold-start would.
        """
        p = tmp_path / "doc.bin"
        p.write_bytes(b"\x00" * 4096)

        pipeline = ExtractorPipeline()
        pipeline.enrol_directory(str(tmp_path))

        p.write_bytes(os.urandom(4096))
        scores = pipeline.process_event(make_close_write(str(p)))
        assert scores.entropy > 0.0


# ---------------------------------------------------------------------------
# SpreadExtractor
# ---------------------------------------------------------------------------

def make_close_write_in(directory: str, filename: str, ts: int = 0) -> FileEvent:
    """Construct a CLOSE_WRITE event for a file in the given directory."""
    return FileEvent(
        path=f"{directory}/{filename}",
        op=OP_CLOSE_WRITE,
        mono_ts=ts,
    )


class TestSpreadExtractor:

    def test_idle_scores_zero(self):
        """No events: score must be 0.0."""
        ext = SpreadExtractor()
        event = make_close_write_in("/tmp/a", "f.txt", ts=0)
        assert ext.score(event) == 0.0

    def test_single_directory_scores_zero(self):
        """
        Multiple writes to the same directory must not raise the spread score --
        localised activity is normal (e.g., editing files in one folder).
        """
        ext = SpreadExtractor()
        ts = 0
        for i in range(5):
            ts += 100_000_000
            ext.score(make_close_write_in("/tmp/a", f"file{i}.txt", ts=ts))
        # All writes are in /tmp/a -- distinct_dirs = 1 -> score = 0.0.
        assert ext.score(make_close_write_in("/tmp/a", "last.txt", ts=ts + 1)) == 0.0

    def test_two_directories_scores_above_zero(self):
        """Writes in two different directories must produce a score > 0.0."""
        ext = SpreadExtractor()
        ext.score(make_close_write_in("/tmp/a", "f.txt", ts=1_000_000))
        score = ext.score(make_close_write_in("/tmp/b", "g.txt", ts=2_000_000))
        assert score > 0.0

    def test_score_at_ceiling(self):
        """Writes across SPREAD_CEILING distinct directories must clamp score to 1.0."""
        ext = SpreadExtractor()
        ts = 0
        for i in range(_SPREAD_CEILING):
            ts += 100_000_000
            ext.score(make_close_write_in(f"/tmp/dir{i}", "f.txt", ts=ts))
        # Score must be 1.0 (ceiling reached).
        assert ext.score(make_close_write_in("/tmp/extra", "x.txt", ts=ts + 1)) == pytest.approx(1.0)

    def test_non_close_write_not_counted(self):
        """Non-CLOSE_WRITE events must not contribute to spread count."""
        ext = SpreadExtractor()
        for i in range(_SPREAD_CEILING + 5):
            event = FileEvent(
                path=f"/tmp/dir{i}/f.txt",
                op=OP_MOVED_TO,
                mono_ts=i * 100_000_000,
            )
            ext.score(event)
        # Only CLOSE_WRITE fills the window; score stays 0.0.
        assert ext.score(make_close_write_in("/tmp/z", "z.txt", ts=9_999_999_999)) == 0.0

    def test_window_eviction_drops_score(self):
        """
        Events that have aged out of the window must not count.
        Write to many dirs, then wait past the window, then write to one dir.
        Score must reset to near 0.
        """
        ext = SpreadExtractor()
        # Write to 5 different directories at t=0..500ms.
        for i in range(5):
            ext.score(make_close_write_in(f"/tmp/dir{i}", "f.txt", ts=i * 100_000_000))

        # Now send an event far past the window (t >> SPREAD_WINDOW_NS).
        far_ts = _SPREAD_WINDOW_NS + 10_000_000_000
        score = ext.score(make_close_write_in("/tmp/new", "f.txt", ts=far_ts))
        # All previous events evicted; only /tmp/new in window -> score = 0.0.
        assert score == 0.0

    def test_score_always_in_range(self):
        """Property: score must always be in [0, 1]."""
        ext = SpreadExtractor()
        ts = 0
        for i in range(50):
            ts += 50_000_000
            s = ext.score(make_close_write_in(f"/tmp/d{i % 15}", "f.txt", ts=ts))
            assert 0.0 <= s <= 1.0, f"score out of range at iteration {i}: {s}"


# ---------------------------------------------------------------------------
# SubScores -- active_signals with 4 signals
# ---------------------------------------------------------------------------

class TestSubScores:

    def test_default_all_zero(self):
        s = SubScores()
        assert s.entropy == 0.0
        assert s.rate == 0.0
        assert s.extension == 0.0
        assert s.spread == 0.0

    def test_active_signals_counts_above_threshold(self):
        """Only signals strictly above threshold are counted."""
        s = SubScores(entropy=0.5, rate=0.0, extension=0.2, spread=0.0)
        assert s.active_signals(0.1) == 2

    def test_active_signals_all_four(self):
        s = SubScores(entropy=0.5, rate=0.5, extension=0.5, spread=0.5)
        assert s.active_signals(0.1) == 4

    def test_active_signals_none(self):
        s = SubScores(entropy=0.0, rate=0.0, extension=0.0, spread=0.0)
        assert s.active_signals(0.1) == 0

    def test_active_signals_spread_only(self):
        """Spread alone above threshold counts as 1 active signal."""
        s = SubScores(entropy=0.0, rate=0.0, extension=0.0, spread=0.5)
        assert s.active_signals(0.1) == 1
