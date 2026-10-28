#!/usr/bin/env bash
# =============================================================================
# CTRR — Module 2: Filesystem Ingestion / Watcher (~85% complete)
# =============================================================================
# WHAT THIS DEMO MEANS: proves the watcher in isolation — inotify event
# capture, two-thread architecture, rename cookie pairing — with no
# scoring/fusion involved at all.
#
# WHAT THE OUTPUT MEANS (expected, in order):
#   EVENT IN_CREATE       a.txt      -> file created
#   EVENT IN_CLOSE_WRITE   a.txt      -> file handle closed after writes.
#       Note there is exactly ONE of these despite 5 separate writes to the
#       handle below — that coalescing is Module 3's job (normalisation),
#       living in the same processor thread; Module 2 just delivers the
#       raw-but-deduped stream.
#   EVENT IN_MOVED_FROM   a.txt      -> rename-cookie pairing, half 1
#   EVENT IN_MOVED_TO     a.renamed  -> rename-cookie pairing, half 2
#       This MOVED_FROM/MOVED_TO pair matched by cookie is what Module 2 owns.
# =============================================================================
set -uo pipefail
# Repo root, found from this script's own location so a fresh clone works anywhere.
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT" || { echo "Set PROJECT_ROOT at the top of this script."; exit 1; }

rm -rf /tmp/watch-demo && mkdir -p /tmp/watch-demo

python -c "
import time
from ctrr.watcher import Watcher

def cb(e):
    print('EVENT', e.op, e.path)

w = Watcher('/tmp/watch-demo', callback=cb)
w.start()
time.sleep(0.5)
with open('/tmp/watch-demo/a.txt', 'w') as f:
    for _ in range(5):
        f.write('x'); f.flush()
        time.sleep(0.05)
import os
os.rename('/tmp/watch-demo/a.txt', '/tmp/watch-demo/a.renamed')
time.sleep(0.5)
w.stop()
"
