# B3 (extension sub-score) before/after, development seeds 1-3

Commands (from the repo root, venv active):

    # before: extractor counting distinct new suffixes, code at c7d1114
    python tools/run_batch.py --split dev            # wrote experiments/results/batch (renamed to batch-before-b3)
    # after: uniformity-of-one-suffix extractor, code at e5d672b
    python tools/run_batch.py --split dev --results-dir experiments/results/batch-after-b3

Policy otherwise identical: hard threshold 0.65, count-based quorum (live). Copytree snapshot backend.
Cell = runs that reached TRIGGER / runs (seeds 1, 2, 3).

| run | before B3 | after B3 |
|---|---|---|
| attack:baseline (aes, fixed suffix, full) | 0/3 | 1/3 |
| attack:rate_slow | 0/3 | 0/3 |
| attack:rate_fast | 0/3 | 1/3 |
| attack:rename_random | 1/3 | 0/3 |
| attack:rename_none | 0/3 | 0/3 |
| attack:encrypt_head | 0/3 | 0/3 |
| attack:encrypt_alternate | 0/3 | 0/3 |
| attack:content_napierone (RYUK) | 0/3 | 1/3 |
| attack:layout_nested | 0/3 | 3/3 |
| benign (5 workloads x 3 seeds) | 0/15 | 0/15 |

Notes
- Corpora are real NapierOne originals (60 files, mostly already-compressed formats), not the synthetic text corpus; the entropy delta is small on them, which is why most attack runs do not trigger under either extension score.
- B3 helps fixed-suffix attacks (extension 0.2 -> 1.0). It hurts random per-file suffixes (uniformity 1/n), as predicted in the extractor docstring.
- The hard threshold was not changed.
- Typed quorum, replayed on the after-B3 traces (`_TYPED_QUORUM` True vs False): identical trigger counts on every run. The dev workloads contain no case where it makes a difference; this is not evidence for or against it.
- Live-vs-replay: replaying all 42 after-B3 traces under the live policy reproduces the live state and accumulator sequence exactly (42/42).
- One run (benign:cp_r seed 1) was re-run after a runner bug left an orphaned monitor appending to its trace; the runner now always stops its monitor (try/finally).
