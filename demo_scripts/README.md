# CTRR demo scripts

Each script finds the repo root from its own location, so a fresh clone works
from any path.

## Main end-to-end demo (Section 0)

**One window:**
```bash
cd /home/adi/Desktop/Projects/CPTR && source .venv/bin/activate
bash demo_00_end_to_end_1window.sh
```
Runs the whole story unattended: corpus build → daemon (backgrounded, log
tailed live) → attack → encrypted-vs-clean proof → restore CLI → benign
zip/unzip case that must NOT trigger. Nothing to type once it starts.

**Two windows** (if you want the daemon's live output in its own pane):
```bash
# Window 1
bash demo_00a_terminal1_daemon.sh
# Window 2, once window 1 says "watching /tmp/test-corpus"
bash demo_00b_terminal2_attack.sh
```

## Per-module demos (Sections 1–10)

Either run one directly:
```bash
bash modules/module06_fusion.sh
```
or use the menu to pick any of the 10 from one window without remembering
filenames:
```bash
bash run_module_menu.sh
```
Module 10 (replay) needs a trace file, so run the Section 0 demo first if
`/tmp/ctrr-trace.jsonl` doesn't exist yet.

## Cleanup
```bash
bash cleanup.sh
```

Every script has comments inline explaining what each line of output means
for that module, so you can read off the terminal instead of narrating from
memory.
