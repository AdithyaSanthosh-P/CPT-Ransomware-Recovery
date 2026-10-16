#!/usr/bin/env bash
# =============================================================================
# CTRR — cleanup after any demo run
# =============================================================================
set -uo pipefail
rm -rf /tmp/test-corpus /tmp/watch-demo /tmp/ctrr-snaps /tmp/demo-snaps \
       /tmp/ctrr-trace.jsonl /tmp/benign.zip /tmp/ctrr-daemon.log \
       /tmp/monitor_out.log
echo "Cleaned up all demo artifacts under /tmp."
