#!/usr/bin/env bash
# =============================================================================
# CTRR — Section 0, TERMINAL 1: daemon only (two-window version)
# =============================================================================
# Run this in the FIRST window. It builds the corpus, then starts the daemon
# in the foreground so its state-machine output prints live in this window.
# Once you see "watching /tmp/test-corpus", switch to the second window and
# run demo_00b_terminal2_attack.sh.
#
# WHAT THE OUTPUT LINES MEAN:
#   [NORMAL]   -> no evidence accumulated yet
#   [SUSPECT]  -> entropy delta + write rate rising; not enough evidence alone
#   [TRIGGER]  -> hard threshold crossed AND quorum of >=2 signals active;
#                 printed path is where the recovery snapshot landed
#   [COOLDOWN] -> re-arm delay after a trigger
#
# Run from the project root:
#   cd /home/adi/Desktop/Projects/CPTR && source .venv/bin/activate
#   bash /path/to/demo_00a_terminal1_daemon.sh
# =============================================================================
set -uo pipefail

PROJECT_ROOT="/home/adi/Desktop/Projects/CPTR"
CORPUS=/tmp/test-corpus
SNAPS=/tmp/ctrr-snaps
TRACE=/tmp/ctrr-trace.jsonl

cd "$PROJECT_ROOT" || { echo "Set PROJECT_ROOT at the top of this script."; exit 1; }

echo "=== Building fresh 60-file test corpus ==="
rm -rf "$CORPUS" "$SNAPS" "$TRACE"
mkdir -p "$CORPUS" && touch "$CORPUS/.ctrr-test-corpus"
( cd "$CORPUS"
  for i in $(seq 1 60); do
    yes "The quick brown fox jumps over the lazy dog. This is a normal text document." \
      | head -n 200 > "doc_$i.txt"
  done
)
echo "Corpus ready: $(ls "$CORPUS" | wc -l) files."
echo
echo "=== Starting daemon (foreground) — leave this window running ==="
echo "    Switch to the other window now and run demo_00b_terminal2_attack.sh"
echo

python -m ctrr.monitor --watch "$CORPUS" --snapshots "$SNAPS" --trace "$TRACE"
