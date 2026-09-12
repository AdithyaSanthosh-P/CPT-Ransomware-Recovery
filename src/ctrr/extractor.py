"""
src/ctrr/extractor.py
=====================
Three feature extractors that run on the normalised event stream from the
watcher.  Each extractor produces one sub-score in [0, 1]:

    EntropyExtractor   -- Shannon entropy delta vs per-path baseline
    RateExtractor      -- write events per second vs a policy ceiling
    ExtensionExtractor -- fraction of recent renames introducing a novel suffix

The extractors share nothing with each other; they are wired together by the
monitor.  Each sub-score is deliberately kept in [0, 1] so the fusion engine
(scorer.py) can apply a weighted sum without any additional normalisation.

Event contract
--------------
The watcher emits FileEvent objects (defined below).  The extractor module owns
this dataclass so it can be imported by both the watcher and the monitor without
a circular dependency.

Design decisions recorded here
-------------------------------
  - Entropy delta, not absolute: a .zip or .jpg already sits at ~7.9 bits/byte;
    an absolute threshold would fire on every re-compression.  Delta measures
    the jump from the per-path baseline, which is near-zero for those files.
  - Sampling 4 KB head + 4 KB mid on IN_CLOSE_WRITE only: avoids an unbounded
    read cost per event.  Parameters are frozen before any trace is recorded;
    changing them later invalidates all saved baselines.
  - "No baseline" scores neutral (0.0), not suspicious: the first write to a
    new path should not trigger.  The enrolment scan pre-populates the cache at
    startup.
  - All normalisation denominators come from policy constants, not from
    runtime statistics.  This makes scores reproducible from a saved trace.
"""

from __future__ import annotations

import os
from collections import deque
from dataclasses import dataclass
from pathlib import Path

import numpy as np


# ---------------------------------------------------------------------------
# Shared event type
# ---------------------------------------------------------------------------

# inotify operation codes used in this project.  The watcher maps raw inotify
# flags to one of these before enqueuing an event.
OP_CLOSE_WRITE = "IN_CLOSE_WRITE"   # file closed after being written
OP_MOVED_FROM  = "IN_MOVED_FROM"    # file renamed away (source side)
OP_MOVED_TO    = "IN_MOVED_TO"      # file renamed in (destination side)
OP_CREATE      = "IN_CREATE"
OP_DELETE      = "IN_DELETE"


@dataclass(frozen=True)
class FileEvent:
    """
    Normalised filesystem event emitted by the watcher.

    path     -- absolute path of the affected file
    op       -- one of the OP_* constants above
    mono_ts  -- time.monotonic_ns() at the moment the kernel event was read;
                used for rate calculation and replay.  Never wall-clock time.
    src_path -- set on OP_MOVED_TO to carry the rename source; None otherwise.
    """
    path:     str
    op:       str
    mono_ts:  int                        # nanoseconds, monotonic clock
    src_path: str | None = None


# ---------------------------------------------------------------------------
# Sampling constants
# Freeze these before recording any trace you intend to keep.
# ---------------------------------------------------------------------------

SAMPLE_HEAD_BYTES = 4096    # bytes read from the start of the file
SAMPLE_MID_BYTES  = 4096    # bytes read from the midpoint of the file


# ---------------------------------------------------------------------------
# Entropy helpers
# ---------------------------------------------------------------------------

def _read_sample(path: str) -> bytes | None:
    """
    Read SAMPLE_HEAD_BYTES from the start of a file and SAMPLE_MID_BYTES from
    the midpoint.  Returns None if the file cannot be read (ENOENT, EACCES,
    etc.).  Errors are expected and counted by the caller -- the sub-score
    is left neutral on any read failure.
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return None

    try:
        with open(path, "rb") as fh:
            head = fh.read(SAMPLE_HEAD_BYTES)
            if size > SAMPLE_HEAD_BYTES + SAMPLE_MID_BYTES:
                mid_offset = max(0, size // 2 - SAMPLE_MID_BYTES // 2)
                fh.seek(mid_offset)
                mid = fh.read(SAMPLE_MID_BYTES)
            else:
                # File is small enough that the head already covers it.
                mid = b""
    except OSError:
        return None

    return head + mid


def _shannon_entropy(data: bytes) -> float:
    """
    Shannon entropy H(X) in bits per byte over a 256-bin byte histogram.

    Result is in [0, 8.0]:
      - English text:        approx 3.5 -- 4.5 bits/byte
      - DEFLATE / zlib:      approx 7.8 -- 7.95 bits/byte
      - AES ciphertext:      approx 7.99 bits/byte
      - Empty data:          0.0 (returned immediately)

    Uses numpy.bincount over a uint8 view for speed; allocates one 256-element
    array per call.
    """
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probs = counts / counts.sum()
    probs = probs[probs > 0]                    # drop zero bins to avoid log(0)
    return float(-np.sum(probs * np.log2(probs)))


# ---------------------------------------------------------------------------
# EntropyExtractor
# ---------------------------------------------------------------------------

# Maximum plausible entropy delta from a low-entropy file to a fully-random
# one.  Used to normalise the raw delta into [0, 1].
# English text sits around 4 bits/byte; random bytes around 8 bits/byte.
# A delta of 4 bits/byte is the theoretical ceiling.
_ENTROPY_DELTA_MAX = 4.0


class EntropyExtractor:
    """
    Scores each IN_CLOSE_WRITE event by the change in Shannon entropy relative
    to the per-path baseline recorded at the previous write (or enrolment).

    Sub-score semantics
    -------------------
      0.0  -- entropy unchanged, or no baseline exists yet (neutral)
      0.5  -- delta of ~2 bits/byte (moderate jump, e.g. partial compression)
      1.0  -- delta >= 4 bits/byte (plaintext overwritten by ciphertext)

    The baseline is updated after scoring so the next event for the same path
    is measured against the most recent known state, not the enrolment state.
    This means a file that is encrypted in two passes still produces a delta
    on the second pass (second half encrypted raises the remaining delta).
    """

    def __init__(self) -> None:
        # Maps absolute path -> last measured entropy value.
        # Pre-populate via enrol_file() during startup scan.
        self._baseline: dict[str, float] = {}
        self._read_errors: int = 0

    def enrol_file(self, path: str) -> None:
        """
        Record the current entropy of a file as its baseline.  Called during
        the startup directory scan so the cache is warm before any attack
        could begin.  Silently skips unreadable files.
        """
        data = _read_sample(path)
        if data is not None:
            self._baseline[path] = _shannon_entropy(data)

    def score(self, event: FileEvent) -> float:
        """
        Return a sub-score in [0, 1] for a single IN_CLOSE_WRITE event.
        Returns 0.0 immediately for all other event types.

        Side effect: updates the baseline for event.path after scoring.
        """
        if event.op != OP_CLOSE_WRITE:
            return 0.0

        data = _read_sample(event.path)
        if data is None:
            # File vanished or was inaccessible.  Score neutral; log the error.
            self._read_errors += 1
            return 0.0

        current_entropy = _shannon_entropy(data)

        baseline = self._baseline.get(event.path)
        if baseline is None:
            # First time we have seen this path.  Record and score neutral.
            # Scoring suspicious on cold-start would produce false positives
            # for any newly created legitimate file.
            self._baseline[event.path] = current_entropy
            return 0.0

        delta = current_entropy - baseline

        # Update the baseline to the current state.
        self._baseline[event.path] = current_entropy

        if delta <= 0.0:
            # Entropy fell or stayed flat (e.g. truncation, overwrite with
            # lower-entropy content).  Not a ransomware signal.
            return 0.0

        # Clamp and normalise to [0, 1].
        return min(1.0, delta / _ENTROPY_DELTA_MAX)

    @property
    def read_errors(self) -> int:
        """Count of events where the file could not be sampled."""
        return self._read_errors


# ---------------------------------------------------------------------------
# RateExtractor
# ---------------------------------------------------------------------------

# Policy ceiling: writes per second considered fully suspicious.
# Below this rate the score scales linearly; at or above it the score is 1.0.
# 50 writes/sec is a conservative ceiling for legitimate interactive use;
# ransomware typically operates at hundreds to thousands per second.
_RATE_CEILING_WPS = 50.0

# Width of the sliding window over which the rate is measured.
_RATE_WINDOW_NS = 5_000_000_000    # 5 seconds in nanoseconds


class RateExtractor:
    """
    Scores based on the write rate (IN_CLOSE_WRITE events per second) observed
    in a sliding window of the last _RATE_WINDOW_NS nanoseconds.

    Sub-score semantics
    -------------------
      0.0  -- 0 writes/sec (idle)
      0.5  -- _RATE_CEILING_WPS / 2  writes/sec
      1.0  -- >= _RATE_CEILING_WPS   writes/sec
    """

    def __init__(self) -> None:
        # Timestamps (monotonic nanoseconds) of recent IN_CLOSE_WRITE events.
        # maxlen bounds memory; events older than _RATE_WINDOW_NS are evicted
        # lazily on each call to score().
        self._window: deque[int] = deque()

    def score(self, event: FileEvent) -> float:
        """
        Return a sub-score in [0, 1].  Accepts any event type but only
        IN_CLOSE_WRITE events contribute to the rate count.
        """
        if event.op == OP_CLOSE_WRITE:
            self._window.append(event.mono_ts)

        # Evict events that have fallen outside the window.
        cutoff = event.mono_ts - _RATE_WINDOW_NS
        while self._window and self._window[0] < cutoff:
            self._window.popleft()

        # Rate = events in window / window width in seconds.
        window_sec = _RATE_WINDOW_NS / 1e9
        rate = len(self._window) / window_sec

        return min(1.0, rate / _RATE_CEILING_WPS)


# ---------------------------------------------------------------------------
# ExtensionExtractor
# ---------------------------------------------------------------------------

# How many distinct novel extensions in the rename window before score = 1.0.
# "Novel" means the destination extension was not seen in any MOVED_FROM
# within the same window, i.e. the rename introduced a new suffix.
_EXTENSION_CEILING = 5

# Sliding window for rename events.
_EXTENSION_WINDOW_NS = 10_000_000_000   # 10 seconds in nanoseconds


class ExtensionExtractor:
    """
    Scores based on how many rename events in a sliding window introduced a
    new file extension that was not present before the rename.

    Ransomware typically renames every encrypted file to a new suffix
    (.locked, .enc, .crypted, etc.).  Legitimate renames almost never
    introduce a single novel extension across hundreds of files.

    Sub-score semantics
    -------------------
      0.0  -- no renames, or all renames preserved the extension
      0.5  -- _EXTENSION_CEILING / 2 novel extensions in the window
      1.0  -- >= _EXTENSION_CEILING novel extensions seen
    """

    def __init__(self) -> None:
        # Tracks (mono_ts, src_ext, dst_ext) for each rename pair in the window.
        self._renames: deque[tuple[int, str, str]] = deque()

    @staticmethod
    def _ext(path: str) -> str:
        """Return the lowercase file extension including the dot, or ''."""
        return Path(path).suffix.lower()

    def score(self, event: FileEvent) -> float:
        """
        Return a sub-score in [0, 1].  Only OP_MOVED_TO events with a known
        source path (src_path set) contribute to the rename window.
        """
        if event.op == OP_MOVED_TO and event.src_path is not None:
            src_ext = self._ext(event.src_path)
            dst_ext = self._ext(event.path)
            self._renames.append((event.mono_ts, src_ext, dst_ext))

        # Evict stale entries.
        cutoff = event.mono_ts - _EXTENSION_WINDOW_NS
        while self._renames and self._renames[0][0] < cutoff:
            self._renames.popleft()

        # Count how many renames in the window changed the extension.
        # A rename that keeps the same extension (e.g. a temp-file swap) is
        # not counted as a novel extension event.
        novel_extensions: set[str] = set()
        for _, src_ext, dst_ext in self._renames:
            if dst_ext != src_ext and dst_ext:
                novel_extensions.add(dst_ext)

        return min(1.0, len(novel_extensions) / _EXTENSION_CEILING)


# ---------------------------------------------------------------------------
# ExtractorPipeline
# ---------------------------------------------------------------------------

@dataclass
class SubScores:
    """
    The three sub-scores produced per fusion tick, each in [0, 1].
    Passed to the scorer (fusion engine) as a unit.
    """
    entropy:   float = 0.0
    rate:      float = 0.0
    extension: float = 0.0

    def active_signals(self, threshold: float = 0.1) -> int:
        """
        Count how many sub-scores exceed threshold.
        Used by the arbiter to evaluate the quorum requirement (>= 2 signals).
        """
        return sum(
            1 for s in (self.entropy, self.rate, self.extension)
            if s > threshold
        )


class ExtractorPipeline:
    """
    Thin wrapper that routes each incoming event to all three extractors and
    returns a SubScores snapshot.

    The monitor calls process_event() for every event off the watcher queue.
    The scorer reads the latest sub-scores on its 500 ms tick via latest().
    """

    def __init__(self) -> None:
        self.entropy_ext   = EntropyExtractor()
        self.rate_ext      = RateExtractor()
        self.extension_ext = ExtensionExtractor()
        self._latest       = SubScores()

    def enrol_directory(self, root: str) -> None:
        """
        Walk root and enrol every regular file in the entropy baseline cache.
        Call once at startup before the inotify watch is armed.
        """
        for dirpath, _dirs, files in os.walk(root):
            for fname in files:
                self.entropy_ext.enrol_file(os.path.join(dirpath, fname))

    def process_event(self, event: FileEvent) -> SubScores:
        """
        Feed event to all extractors, update the cached sub-scores, and
        return the current snapshot.  Called on every event from the watcher.
        """
        self._latest = SubScores(
            entropy   = self.entropy_ext.score(event),
            rate      = self.rate_ext.score(event),
            extension = self.extension_ext.score(event),
        )
        return self._latest

    def latest(self) -> SubScores:
        """Return the sub-scores from the most recently processed event."""
        return self._latest
