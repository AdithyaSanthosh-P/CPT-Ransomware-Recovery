# Policy comparison (heldout seeds [4, 5, 6, 7, 8])

Command: `python experiments/compare_policies.py --runs results/batch-heldout --label heldout --model-b logreg`  |  code at 117f882  |  per-run data: JSON

| policy | detected / attack runs | median latency ms | median files overwritten before snapshot | % of corpus | false triggers / benign runs |
|---|---|---|---|---|---|
| P0 | 8/45 | 4987.0 | 35.0 | 58.3 | 0/25 |
| P1 | 45/45 | 2583.9 | 18 | 30.0 | 3/25 |
| P2 | 45/45 | 1062.9 | 7 | 11.7 | 0/25 |

Note: latency, files overwritten and % of corpus are medians over detected runs only (P0: 8 runs). Over all 45 attack runs, counting a miss as 60/60 files lost, the medians are P0 60 (100%), P1 18 (30%), P2 7 (11.7%). Per-scenario table: `policy_comparison_heldout_allruns.md`. P1's 3 benign false triggers are all `git_clone`: git pack files (`PACK`) and zlib loose objects are missing from the signature table in `src/ctrr/features.py`, so Model A sees them as headerless high-entropy data. Model B uses rate, extension and spread only (no delta time).

## Detections by attack mode

| mode | P0 | P1 | P2 |
|---|---|---|---|
| baseline | 1/5 | 5/5 | 5/5 |
| content_napierone | 1/5 | 5/5 | 5/5 |
| encrypt_alternate | 0/5 | 5/5 | 5/5 |
| encrypt_head | 0/5 | 5/5 | 5/5 |
| layout_nested | 5/5 | 5/5 | 5/5 |
| rate_fast | 1/5 | 5/5 | 5/5 |
| rate_slow | 0/5 | 5/5 | 5/5 |
| rename_none | 0/5 | 5/5 | 5/5 |
| rename_random | 0/5 | 5/5 | 5/5 |

Monitor CPU (live, mean CPU seconds / wall seconds): {'attack': 0.161, 'benign': 0.583}
