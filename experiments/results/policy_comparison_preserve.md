# Policy comparison (heldout seeds [9, 10, 11, 12, 13])

Command: `python experiments/compare_policies.py --runs experiments/results/batch-preserve --label preserve --model-b logreg`  |  code at 8e3a1fe  |  per-run data: JSON

| policy | detected / attack runs | median latency ms | median files overwritten before snapshot | % of corpus | false triggers / benign runs |
|---|---|---|---|---|---|
| P0 | 0/15 | None | None | None | 0/0 |
| P1 | 5/15 | 2568.7 | 18 | 30.0 | 0/0 |
| P2 | 5/15 | 909.2 | 7 | 11.7 | 0/0 |

## Detections by attack mode

| mode | P0 | P1 | P2 |
|---|---|---|---|
| baseline | 0/5 | 5/5 | 5/5 |
| preserve_16 | 0/5 | 0/5 | 0/5 |
| preserve_4096 | 0/5 | 0/5 | 0/5 |

Monitor CPU (live, mean CPU seconds / wall seconds): {'attack': 0.151}
