# All-run summary (preserve)

Source: `policy_comparison_preserve.json` (existing runs, nothing re-run).  Command: `python experiments/summarize_allruns.py --label preserve`

Files lost = files overwritten when the snapshot was requested; an undetected run counts as 60/60 (no snapshot taken).  Latency is detected runs only.

## Over all attack runs

| policy | detected | median files lost, all runs | % of corpus | median files lost, detected only | median latency ms, detected only |
|---|---|---|---|---|---|
| P0 | 0/15 | 60 | 100.0 | None | None |
| P1 | 5/15 | 60 | 100.0 | 18 | 2568.7 |
| P2 | 5/15 | 60 | 100.0 | 7 | 909.2 |

## Per attack scenario (5 held-out seeds each)

| scenario | P0 det | P0 files lost (median, all) | P1 det | P1 files lost | P2 det | P2 files lost |
|---|---|---|---|---|---|---|
| baseline | 0/5 | 60 | 5/5 | 18 | 5/5 | 7 |
| preserve_16 | 0/5 | 60 | 0/5 | 60 | 0/5 | 60 |
| preserve_4096 | 0/5 | 60 | 0/5 | 60 | 0/5 | 60 |
