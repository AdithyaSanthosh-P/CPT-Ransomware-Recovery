# P2 weight sweep (dev traces)

Command: `python experiments/weight_sweep.py --runs experiments/results/batch-dev --label dev`

fused = w_A x Model A + w_B x Model B, thresholds and typed quorum unchanged. Dev traces only; Model B was trained on them, so every row is flattered (sensitivity, not generalisation). Files lost counts a miss as 60/60.

| w_A | w_B | detected | median files lost (all runs) | median latency ms (detected) | false triggers | modes with a miss |
|---|---|---|---|---|---|---|
| 0.1 | 0.9 | 24/27 | 8 | 1066.4 | 0/15 | rename_none |
| 0.2 | 0.8 | 24/27 | 8 | 1066.4 | 0/15 | rename_none |
| 0.3 | 0.7 | 24/27 | 8 | 1065.7 | 0/15 | rename_none |
| 0.4 | 0.6 | 24/27 | 8 | 1064.9 | 0/15 | rename_none |
| 0.5 | 0.5 | 27/27 | 7 | 1061.8 | 0/15 | - |
| 0.6 | 0.4 | 27/27 | 7 | 920.8 | 0/15 | - |
| 0.7 | 0.3 | 27/27 | 7 | 920.8 | 0/15 | - |
| 0.8 | 0.2 | 27/27 | 7 | 915.2 | 0/15 | - |
| 0.9 | 0.1 | 27/27 | 7 | 914.5 | 0/15 | - |
