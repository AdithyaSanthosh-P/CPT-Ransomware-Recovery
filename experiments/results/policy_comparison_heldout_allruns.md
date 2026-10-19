# All-run summary (heldout)

Source: `policy_comparison_heldout.json` (existing runs, nothing re-run).  Command: `python experiments/summarize_allruns.py --label heldout`

Files lost = files overwritten when the snapshot was requested; an undetected run counts as 60/60 (no snapshot taken).  Latency is detected runs only.

## Over all attack runs

| policy | detected | median files lost, all runs | % of corpus | median files lost, detected only | median latency ms, detected only |
|---|---|---|---|---|---|
| P0 | 8/45 | 60 | 100.0 | 35.0 | 4987.0 |
| P1 | 45/45 | 18 | 30.0 | 18 | 2583.9 |
| P2 | 45/45 | 7 | 11.7 | 7 | 1062.9 |

## Per attack scenario (5 held-out seeds each)

| scenario | P0 det | P0 files lost (median, all) | P1 det | P1 files lost | P2 det | P2 files lost |
|---|---|---|---|---|---|---|
| baseline | 1/5 | 60 | 5/5 | 18 | 5/5 | 7 |
| content_napierone | 1/5 | 60 | 5/5 | 18 | 5/5 | 7 |
| encrypt_alternate | 0/5 | 60 | 5/5 | 18 | 5/5 | 7 |
| encrypt_head | 0/5 | 60 | 5/5 | 18 | 5/5 | 8 |
| layout_nested | 5/5 | 33 | 5/5 | 15 | 5/5 | 8 |
| rate_fast | 1/5 | 60 | 5/5 | 18 | 5/5 | 7 |
| rate_slow | 0/5 | 60 | 5/5 | 25 | 5/5 | 7 |
| rename_none | 0/5 | 60 | 5/5 | 28 | 5/5 | 23 |
| rename_random | 0/5 | 60 | 5/5 | 27 | 5/5 | 8 |
