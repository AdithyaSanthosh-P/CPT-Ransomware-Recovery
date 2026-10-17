#!/usr/bin/env bash
# =============================================================================
# CTRR — Section 0, TERMINAL 2: attack + restore + benign case
# =============================================================================
# Run this in the SECOND window, AFTER demo_00a_terminal1_daemon.sh is
# already running and showing "watching /tmp/test-corpus" in window 1.
#
# Sequence:
#   1. Launch the ransomware simulator against the live corpus — watch
#      window 1 for [SUSPECT] -> [TRIGGER] -> [COOLDOWN].
#   2. Show which files were saved encrypted vs clean in the snapshot
#      (proof the checkpoint landed mid-attack).
#   3. Run the restore CLI: list / diff / restore --verify.
#   4. Reset the corpus and run the benign zip/unzip workload — window 1
#      should stay at [NORMAL] the whole time (the false-positive story).
#
# Run from the project root:
#   cd /home/adi/Desktop/Projects/CPTR && source .venv/bin/activate
#   bash /path/to/demo_00b_terminal2_attack.sh
# =============================================================================
set -uo pipefail

PROJECT_ROOT="/home/adi/Desktop/Projects/CPTR"
CORPUS=/tmp/test-corpus
SNAPS=/tmp/ctrr-snaps

cd "$PROJECT_ROOT" || { echo "Set PROJECT_ROOT at the top of this script."; exit 1; }

section() { echo; echo "==================================================================="; echo "$1"; echo "==================================================================="; }

section "0.2  Launching attack simulator — watch Terminal 1 for TRIGGER"
python tools/simulate_attack.py --target "$CORPUS" --rate 10 --trace /tmp/ctrr-trace.jsonl
sleep 2

# WHAT THIS PROVES: the snapshot was taken MID-ATTACK. Expect roughly half
# the corpus (~30/30 on a verified 60-file run) still clean at checkpoint.
section "0.2  Files saved in the triggered snapshot (encrypted vs clean)"
SNAP=$(ls -d "$SNAPS"/*/ 2>/dev/null | tail -n 1)
if [ -n "${SNAP:-}" ]; then
  echo "Snapshot: $SNAP"
  echo "  encrypted (.enc) at checkpoint : $(ls "$SNAP" 2>/dev/null | grep -c '\.enc$')"
  echo "  still clean (.txt) at checkpoint: $(ls "$SNAP" 2>/dev/null | grep -c '\.txt$')"
else
  echo "No snapshot directory found yet — check Terminal 1 reached TRIGGER."
fi

# WHAT THE OUTPUT MEANS: diff shows REMOVED/ADDED/MODIFIED/UNCHANGED between
# the now-fully-encrypted live tree and the snapshot. restore --verify
# re-hashes every restored file with SHA-256 — a 100% match is the literal
# answer to "how do you know the restore actually worked?"
section "0.3  Restore CLI — list / diff / restore --verify"
python tools/ctrr_restore.py list --snapshots "$SNAPS"
echo
python tools/ctrr_restore.py diff --watch "$CORPUS" --snapshots "$SNAPS"
echo
python tools/ctrr_restore.py restore --watch "$CORPUS" --snapshots "$SNAPS" --verify

# Reset corpus for the benign case.
section "0.4  Resetting corpus for the benign (non-triggering) case"
rm -rf "$CORPUS"
mkdir -p "$CORPUS" && touch "$CORPUS/.ctrr-test-corpus"
( cd "$CORPUS"
  for i in $(seq 1 60); do
    yes "The quick brown fox jumps over the lazy dog. This is a normal text document." \
      | head -n 200 > "doc_$i.txt"
  done
)

# WHAT THE OUTPUT MEANS: identical-content overwrite via zip/unzip — same
# write volume as the attack, zero entropy change, no extension renames.
# Terminal 1 should stay at [NORMAL] the entire time. This is the
# benign-adversarial axis: high write rate alone is not sufficient to
# trigger, which is what makes this safe to run unattended.
section "0.4  Running benign workload (zip -> unzip) — watch Terminal 1 for NO trigger"
( cd "$CORPUS"
  zip -q -r /tmp/benign.zip . -x '.ctrr-test-corpus'
  unzip -oq /tmp/benign.zip -d "$CORPUS"
)
echo "Done. Confirm in Terminal 1 that it never left [NORMAL]."
