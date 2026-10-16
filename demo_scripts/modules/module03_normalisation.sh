#!/usr/bin/env bash
# =============================================================================
# CTRR — Module 3: Event Normalisation (~90% complete)
# =============================================================================
# WHAT THIS DEMO MEANS: the raw kernel event stream is noisy — IN_MODIFY
# fires per write() syscall. This proves it gets collapsed into ONE clean
# event per file operation before anything downstream (extractors) sees it.
#
# WHAT THE OUTPUT MEANS:
#   EVENT IN_CREATE       b.txt   -> file created
#   EVENT IN_CLOSE_WRITE   b.txt   -> exactly ONE of these line is expected,
#       even though the script below performs 50 raw write() calls at the
#       OS level. 50 raw writes -> 1 delivered event IS the normalisation
#       demo. If you see more than one IN_CLOSE_WRITE here, normalisation
#       is broken.
# =============================================================================
set -uo pipefail
PROJECT_ROOT="/home/adi/Desktop/Projects/CPTR"
cd "$PROJECT_ROOT" || { echo "Set PROJECT_ROOT at the top of this script."; exit 1; }

rm -rf /tmp/watch-demo && mkdir -p /tmp/watch-demo

python -c "
import time
from ctrr.watcher import Watcher

def cb(e):
    print('EVENT', e.op, e.path)

w = Watcher('/tmp/watch-demo', callback=cb)
w.start()
time.sleep(0.3)
with open('/tmp/watch-demo/b.txt', 'w') as f:
    for _ in range(50):        # 50 raw writes
        f.write('x')
        f.flush()
time.sleep(0.5)
w.stop()
"
