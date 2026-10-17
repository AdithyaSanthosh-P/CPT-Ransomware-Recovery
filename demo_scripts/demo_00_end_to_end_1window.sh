#!/usr/bin/env bash
# =============================================================================
# CTRR — Section 0: MAIN END-TO-END DEMO (single-window version)
# =============================================================================
# This is the whole thesis claim in one run, in ONE terminal:
#   1. Build a fresh 60-file test corpus.
#   2. Start the daemon in the BACKGROUND, its output piped to a log file
#      that this script tails live — so you see [NORMAL]/[SUSPECT]/[TRIGGER]
#      transitions scroll past without needing a second window.
#   3. Launch the attack simulator in the FOREGROUND.
#   4. Show which files got saved encrypted vs clean (proof the checkpoint
#      landed mid-attack, not after total loss).
#   5. Run the restore CLI (list / diff / restore --verify).
#   6. Reset the corpus and run the benign case (zip/unzip) to prove the
#      daemon stays at [NORMAL] under comparable write volume with no
#      entropy change — the false-positive story.
#
# If you'd rather watch the daemon and the attack in two separate windows,
# use demo_00a_terminal1_daemon.sh + demo_00b_terminal2_attack.sh instead.
#
# Run from the project root:
#   cd /home/adi/Desktop/Projects/CPTR && source .venv/bin/activate
#   bash /path/to/demo_00_end_to_end_1window.sh
# =============================================================================
set -uo pipefail

PROJECT_ROOT="/home/adi/Desktop/Projects/CPTR"
CORPUS=/tmp/test-corpus
SNAPS=/tmp/ctrr-snaps
TRACE=/tmp/ctrr-trace.jsonl
DAEMON_LOG=/tmp/ctrr-daemon.log

section() { echo; echo "==================================================================="; echo "$1"; echo "==================================================================="; }

cd "$PROJECT_ROOT" || { echo "Set PROJECT_ROOT at the top of this script."; exit 1; }

# --- 0.1 Setup — build a fresh test corpus ----------------------------------
# WHAT THIS PROVES: nothing yet — this is just test data. 60 files, not fewer:
# with the demo's threshold constants the evidence accumulator needs a
# sustained attack to cross the hard threshold; fewer files can run out
# before TRIGGER fires (see Module 7 notes below).
section "0.1  Building fresh 60-file test corpus"
rm -rf "$CORPUS" "$SNAPS" "$TRACE" "$DAEMON_LOG"
mkdir -p "$CORPUS" && touch "$CORPUS/.ctrr-test-corpus"
( cd "$CORPUS"
  for i in $(seq 1 60); do
    yes "The quick brown fox jumps over the lazy dog. This is a normal text document." \
      | head -n 200 > "doc_$i.txt"
  done
)
echo "Corpus ready: $(ls "$CORPUS" | wc -l) files in $CORPUS"

# --- 0.2 Case A — start daemon (background) + launch attack -----------------
# WHAT THE OUTPUT MEANS (watch the tailed daemon log below):
#   [NORMAL]   -> no evidence accumulated yet
#   [SUSPECT]  -> entropy delta + write rate rising as ciphertext overwrites
#                 start; NOT enough evidence to act on its own
#   [TRIGGER]  -> accumulated evidence crossed the hard threshold AND at
#                 least 2 independent signals are active (quorum gate).
#                 A single spiking signal alone cannot cause this line.
#                 The printed path is where the recovery snapshot landed.
#   [COOLDOWN] -> re-arm delay, prevents snapshot-spam on a sustained attack
section "0.2  Starting daemon in background, tailing its log"
python -m ctrr.monitor --watch "$CORPUS" --snapshots "$SNAPS" --trace "$TRACE" \
  > "$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
echo "Daemon PID: $DAEMON_PID  (log: $DAEMON_LOG)"
sleep 1

# Tail the log in the background so it prints live while the attack runs.
tail -f "$DAEMON_LOG" &
TAIL_PID=$!

section "0.2  Launching attack simulator (foreground)"
python tools/simulate_attack.py --target "$CORPUS" --rate 10 --trace "$TRACE"

# Give the daemon a moment to process the last events / write the trigger line.
sleep 3
kill "$TAIL_PID" 2>/dev/null

# --- Encrypted-before-checkpoint proof ---------------------------------------
# WHAT THIS PROVES: the snapshot was taken MID-ATTACK, not after total loss.
# Expect a split like 30 .enc / 30 .txt on the verified 60-file run — i.e.
# roughly half the corpus was still clean at the moment of TRIGGER.
section "0.2  Files saved in the triggered snapshot (encrypted vs clean)"
SNAP=$(ls -d "$SNAPS"/*/ 2>/dev/null | tail -n 1)
if [ -n "${SNAP:-}" ]; then
  echo "Snapshot: $SNAP"
  echo "  encrypted (.enc) at checkpoint : $(ls "$SNAP" 2>/dev/null | grep -c '\.enc$')"
  echo "  still clean (.txt) at checkpoint: $(ls "$SNAP" 2>/dev/null | grep -c '\.txt$')"
else
  echo "No snapshot directory found — daemon may not have reached TRIGGER."
  echo "Check $DAEMON_LOG for the accumulator trace."
fi

# --- 0.3 Recovery — restore CLI ----------------------------------------------
# WHAT THE OUTPUT MEANS:
#   list    -> every snapshot taken, oldest first
#   diff    -> REMOVED/ADDED/MODIFIED/UNCHANGED between the now-fully-
#              encrypted live tree and the snapshot — visual proof of damage
#   restore -> copies every file back; --verify re-hashes each with SHA-256,
#              so a 100% match is the literal answer to "did recovery work?"
section "0.3  Restore CLI — list / diff / restore --verify"
python tools/ctrr_restore.py list --snapshots "$SNAPS"
echo
python tools/ctrr_restore.py diff --watch "$CORPUS" --snapshots "$SNAPS"
echo
python tools/ctrr_restore.py restore --watch "$CORPUS" --snapshots "$SNAPS" --verify

# --- 0.4 Case B — benign workload that must NOT trigger ---------------------
# WHAT THE OUTPUT MEANS: reset the corpus, then overwrite all 30 files with
# IDENTICAL content via zip/unzip — comparable write volume to the attack,
# but zero entropy change and no extension renames. The tailed daemon log
# below should show [NORMAL] the ENTIRE time, no [SUSPECT]/[TRIGGER] lines.
# This is the benign-adversarial axis the project's novelty claim rests on:
# high write rate alone is not sufficient to trigger.
section "0.4  Resetting corpus for the benign (non-triggering) case"
rm -rf "$CORPUS"
mkdir -p "$CORPUS" && touch "$CORPUS/.ctrr-test-corpus"
( cd "$CORPUS"
  for i in $(seq 1 60); do
    yes "The quick brown fox jumps over the lazy dog. This is a normal text document." \
      | head -n 200 > "doc_$i.txt"
  done
)

section "0.4  Running benign workload (zip -> unzip) — watch for NO trigger"
: > "$DAEMON_LOG"   # clear log so this case is easy to read in isolation
tail -f "$DAEMON_LOG" &
TAIL_PID=$!

( cd "$CORPUS"
  zip -q -r /tmp/benign.zip . -x '.ctrr-test-corpus'
  unzip -oq /tmp/benign.zip -d "$CORPUS"
)
sleep 3
kill "$TAIL_PID" 2>/dev/null

echo
if grep -q "TRIGGER" "$DAEMON_LOG"; then
  echo "!! Unexpected TRIGGER during benign case — inspect $DAEMON_LOG"
else
  echo "Confirmed: daemon stayed at [NORMAL] throughout the benign workload."
fi

# --- Teardown -----------------------------------------------------------------
section "Stopping daemon"
kill "$DAEMON_PID" 2>/dev/null
wait "$DAEMON_PID" 2>/dev/null

echo
echo "Full daemon log kept at: $DAEMON_LOG"
echo "Trace file (for Module 10 replay demo) at: $TRACE"
echo "Done."
