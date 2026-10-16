#!/usr/bin/env bash
# =============================================================================
# CTRR — module picker (single window)
# =============================================================================
# Shows a numbered menu of all 10 per-module demos and runs whichever one
# you pick, without you having to type out or locate each script by hand.
# Run it again to pick another module. Ctrl+C or option 0 to quit.
#
#   cd /home/adi/Desktop/Projects/CPTR && source .venv/bin/activate
#   bash /path/to/run_module_menu.sh
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$HERE/modules"

declare -A NAMES=(
  [1]="Environment & Infrastructure"
  [2]="Filesystem Ingestion (Watcher)"
  [3]="Event Normalisation"
  [4]="Entropy Extraction"
  [5]="Behavioral Extraction (rate/extension/spread)"
  [6]="Fusion Engine"
  [7]="State Arbiter"
  [8]="Privilege Separation (design only)"
  [9]="Snapshot & Restoration"
  [10]="Evaluation & Telemetry"
)

while true; do
  echo
  echo "=== CTRR module demos ==="
  for i in $(seq 1 10); do
    printf "  %2d) %s\n" "$i" "${NAMES[$i]}"
  done
  echo "   0) Quit"
  read -rp "Run module: " choice

  case "$choice" in
    0) exit 0 ;;
    1) bash "$MODULES_DIR/module01_environment.sh" ;;
    2) bash "$MODULES_DIR/module02_watcher.sh" ;;
    3) bash "$MODULES_DIR/module03_normalisation.sh" ;;
    4) bash "$MODULES_DIR/module04_entropy.sh" ;;
    5) bash "$MODULES_DIR/module05_behavioral.sh" ;;
    6) bash "$MODULES_DIR/module06_fusion.sh" ;;
    7) bash "$MODULES_DIR/module07_arbiter.sh" ;;
    8) bash "$MODULES_DIR/module08_privilege_separation.sh" ;;
    9) bash "$MODULES_DIR/module09_snapshot_restore.sh" ;;
    10) bash "$MODULES_DIR/module10_evaluation_telemetry.sh" ;;
    *) echo "Not a valid option." ;;
  esac
done
