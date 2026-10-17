# Policy comparison (dev seeds [1, 2, 3])

Command: `python experiments/compare_policies.py --runs results/batch-dev --label dev --model-b logreg`  |  code at 38e2532  |  per-run data: JSON

| policy | detected / attack runs | median latency ms | median files overwritten before snapshot | % of corpus | false triggers / benign runs |
|---|---|---|---|---|---|
| P0 | 6/27 | 5223.0 | 40.5 | 67.5 | 0/15 |
| P1 | 27/27 | 2581.6 | 18 | 30.0 | 3/15 |
| P2 | 27/27 | 1061.8 | 7 | 11.7 | 0/15 |

## Detections by attack mode

| mode | P0 | P1 | P2 |
|---|---|---|---|
| baseline | 1/3 | 3/3 | 3/3 |
| content_napierone | 1/3 | 3/3 | 3/3 |
| encrypt_alternate | 0/3 | 3/3 | 3/3 |
| encrypt_head | 0/3 | 3/3 | 3/3 |
| layout_nested | 3/3 | 3/3 | 3/3 |
| rate_fast | 1/3 | 3/3 | 3/3 |
| rate_slow | 0/3 | 3/3 | 3/3 |
| rename_none | 0/3 | 3/3 | 3/3 |
| rename_random | 0/3 | 3/3 | 3/3 |

Monitor CPU (live, mean CPU seconds / wall seconds): {'attack': 0.16, 'benign': 0.578}
