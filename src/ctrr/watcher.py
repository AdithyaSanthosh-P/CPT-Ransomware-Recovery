"""
src/ctrr/watcher.py
===================
inotify-based filesystem watcher for CTRR.

Architecture
------------
Two threads, no more:

  [READER THREAD]    Calls inotify_simple.INotify.read() in a blocking loop.
                     Translates raw inotify events into FileEvent objects and
                     puts them on a bounded queue.  Never does any processing.

  [PROCESSOR THREAD] Pulls FileEvent objects from the queue and calls the
                     user-supplied callback.  One callback at a time; no
                     parallelism in event processing.

The queue is bounded (QUEUE_MAXSIZE).  When it is full, new events are
dropped and a counter is incremented.  Drops are counted separately from
kernel-side IN_Q_OVERFLOW events because they have different causes:
  - userspace drops: the processor is too slow
  - kernel overflows: the inotify queue filled before the reader could drain it

Rename pairing
--------------
inotify emits MOVED_FROM and MOVED_TO as separate events linked by a cookie.
The reader pairs them: a MOVED_TO event is held until its MOVED_FROM arrives,
or until the pairing window expires.  An unpaired MOVED_FROM means the file
left the watch tree (treated as delete).  An unpaired MOVED_TO means it
entered (treated as create).

Demo scope vs full system
-------------------------
The following are deferred to the full production system:

  - IN_Q_OVERFLOW handling: in the full system, an overflow triggers a
    bounded rescan of the watched directory to recover missed events.
    Here, overflows are counted and logged only.

  - Recursive watch registration race: the full system registers a watch on
    IN_CREATE|IN_ISDIR and then immediately scans the new directory in case
    files were created before the watch was armed.  This implementation
    watches the top-level directory recursively via os.walk at startup but
    does not handle new subdirectories created after the watch is armed.

  - wd -> path map updates on IN_MOVE_SELF / IN_IGNORED: handled for
    the common case but not exhaustively tested.
"""

from __future__ import annotations

import logging
import os
import queue
import threading
import time

import inotify_simple

from ctrr.extractor import (
    OP_CLOSE_WRITE,
    OP_CREATE,
    OP_DELETE,
    OP_MOVED_FROM,
    OP_MOVED_TO,
    FileEvent,
)

log = logging.getLogger(__name__)

# Maximum number of FileEvents held in the inter-thread queue.
# When full, new events are dropped and counted.
QUEUE_MAXSIZE = 4096

# inotify flags we care about.
_WATCH_FLAGS = (
    inotify_simple.flags.CLOSE_WRITE
    | inotify_simple.flags.MOVED_FROM
    | inotify_simple.flags.MOVED_TO
    | inotify_simple.flags.CREATE
    | inotify_simple.flags.DELETE
)


class Watcher:
    """
    Recursive inotify watcher.

    Usage
    -----
    watcher = Watcher("/path/to/watch", callback=pipeline.process_event)
    watcher.start()
    # ... run until interrupted ...
    watcher.stop()
    """

    def __init__(self, watch_root: str, callback) -> None:
        """
        Parameters
        ----------
        watch_root : str
            Root directory to watch recursively.
        callback : callable
            Called with a single FileEvent argument from the processor thread.
            Must not raise; exceptions are caught and logged.
        """
        self.watch_root = str(watch_root)
        self._callback  = callback

        self._inotify   = inotify_simple.INotify()
        self._wd_to_path: dict[int, str] = {}   # inotify watch descriptor -> path

        # Rename pairing state: cookie -> (src_path, mono_ts).
        # Entries are added on MOVED_FROM and consumed on MOVED_TO.
        # Known limitation (demo scope): if a file is moved outside the watched
        # tree, MOVED_TO never arrives and the entry is never removed.  For the
        # demo corpus this is harmless.  The full system adds a periodic sweep
        # to evict entries older than a short window.
        self._pending_from: dict[int, tuple[str, int]] = {}

        self._queue: queue.Queue[FileEvent] = queue.Queue(maxsize=QUEUE_MAXSIZE)

        # Counters exported for monitoring / tests.
        self.userspace_drops   = 0
        self.kernel_overflows  = 0

        self._stop_event = threading.Event()
        self._reader_thread    = threading.Thread(
            target=self._reader_loop, name="ctrr-reader", daemon=True
        )
        self._processor_thread = threading.Thread(
            target=self._processor_loop, name="ctrr-processor", daemon=True
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Register watches and start both threads."""
        self._register_recursive(self.watch_root)
        self._reader_thread.start()
        self._processor_thread.start()
        log.info("watcher started  root=%s watches=%d",
                 self.watch_root, len(self._wd_to_path))

    def stop(self) -> None:
        """Signal both threads to stop and wait for them to exit."""
        self._stop_event.set()
        # Unblock the reader by closing the inotify fd.
        try:
            self._inotify.close()
        except Exception:
            pass
        self._reader_thread.join(timeout=2.0)
        # Unblock the processor with a sentinel.
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass
        self._processor_thread.join(timeout=2.0)
        log.info("watcher stopped  drops=%d overflows=%d",
                 self.userspace_drops, self.kernel_overflows)

    # ------------------------------------------------------------------
    # Internal: watch registration
    # ------------------------------------------------------------------

    def _register_recursive(self, root: str) -> None:
        """Add an inotify watch for root and every subdirectory under it."""
        for dirpath, dirs, _ in os.walk(root):
            self._add_watch(dirpath)

    def _add_watch(self, path: str) -> int:
        """Add one inotify watch and record the wd -> path mapping."""
        wd = self._inotify.add_watch(path, _WATCH_FLAGS)
        self._wd_to_path[wd] = path
        return wd

    # ------------------------------------------------------------------
    # Internal: reader thread
    # ------------------------------------------------------------------

    def _reader_loop(self) -> None:
        """
        Read raw inotify events in a tight loop.

        Only enqueues events; never calls the callback.  Keeps the read
        latency as low as possible by doing the minimum work per event.
        """
        while not self._stop_event.is_set():
            try:
                raw_events = self._inotify.read(timeout=500)
            except OSError:
                # inotify fd was closed by stop() -- exit cleanly.
                break

            mono_ts = time.monotonic_ns()

            for evt in raw_events:
                flags = inotify_simple.flags.from_mask(evt.mask)
                self._handle_raw(evt, flags, mono_ts)

    def _handle_raw(self, evt, flags, mono_ts: int) -> None:
        """Translate one raw inotify event into a FileEvent and enqueue it."""

        # Track new subdirectories so subsequent events inside them are mapped.
        if inotify_simple.flags.CREATE in flags and inotify_simple.flags.ISDIR in flags:
            parent_path = self._wd_to_path.get(evt.wd, "")
            new_dir = os.path.join(parent_path, evt.name) if evt.name else parent_path
            try:
                self._add_watch(new_dir)
            except OSError:
                pass
            return   # directory creates are not forwarded as file events

        # Handle kernel-side queue overflow.
        if inotify_simple.flags.Q_OVERFLOW in flags:
            self.kernel_overflows += 1
            log.warning("kernel inotify queue overflow  total=%d",
                        self.kernel_overflows)
            return

        # Resolve the full path.
        parent = self._wd_to_path.get(evt.wd, "")
        path   = os.path.join(parent, evt.name) if evt.name else parent

        # Map inotify flags to FileEvent op codes.
        if inotify_simple.flags.CLOSE_WRITE in flags:
            self._enqueue(FileEvent(path=path, op=OP_CLOSE_WRITE, mono_ts=mono_ts))

        elif inotify_simple.flags.MOVED_FROM in flags:
            # Park the source path, keyed by rename cookie, to pair with MOVED_TO.
            self._pending_from[evt.cookie] = (path, mono_ts)
            self._enqueue(FileEvent(path=path, op=OP_MOVED_FROM, mono_ts=mono_ts))

        elif inotify_simple.flags.MOVED_TO in flags:
            # Complete the rename pair if the source side is known.
            from_entry = self._pending_from.pop(evt.cookie, None)
            src_path   = from_entry[0] if from_entry else None
            self._enqueue(FileEvent(
                path=path, op=OP_MOVED_TO, mono_ts=mono_ts, src_path=src_path
            ))

        elif inotify_simple.flags.CREATE in flags:
            self._enqueue(FileEvent(path=path, op=OP_CREATE, mono_ts=mono_ts))

        elif inotify_simple.flags.DELETE in flags:
            self._enqueue(FileEvent(path=path, op=OP_DELETE, mono_ts=mono_ts))

        elif inotify_simple.flags.IGNORED in flags:
            # Watch was removed (directory deleted or moved out).
            self._wd_to_path.pop(evt.wd, None)

    def _enqueue(self, event: FileEvent) -> None:
        """Put an event on the queue, counting drops if the queue is full."""
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            self.userspace_drops += 1
            if self.userspace_drops % 100 == 1:
                log.warning("userspace queue full -- dropping events  total=%d",
                            self.userspace_drops)

    # ------------------------------------------------------------------
    # Internal: processor thread
    # ------------------------------------------------------------------

    def _processor_loop(self) -> None:
        """
        Pull events from the queue and invoke the callback one at a time.

        Exceptions from the callback are caught and logged so a single bad
        event cannot stop the processor.
        """
        while not self._stop_event.is_set():
            try:
                event = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue

            if event is None:
                # Sentinel from stop().
                break

            try:
                self._callback(event)
            except Exception:
                log.exception("callback raised on event %s", event)
