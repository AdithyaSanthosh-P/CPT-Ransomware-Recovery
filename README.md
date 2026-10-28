# CTRR: Copy-Time Ransomware Recovery

A Linux userspace daemon that watches a directory with inotify, scores ransomware-like behaviour, and takes a **read-only Btrfs snapshot** when sustained evidence crosses a threshold. A restore CLI recovers files from the snapshot. The decision policy is replayable from a saved trace, and it is benchmarked against ML models trained on real ransomware output (NapierOne).

This is a course project (final-year project, demo scope). It does not use process information, it is not a kernel module, and the snapshot helper is a single sudoers rule rather than a privilege-separated daemon.

## Pipeline

`watcher.py` (inotify) -> `extractor.py` (entropy delta, write rate, extension uniformity, directory spread) -> `scorer.py` (weighted fusion, leaky-integrator accumulator, NORMAL/SUSPECT/TRIGGER/COOLDOWN arbiter with a typed quorum) -> `snapshot.py` (`BtrfsBackend` or a `copytree` mock) -> wired by `monitor.py`.

## Run it

    python -m venv .venv && source .venv/bin/activate && pip install -e '.[experiments]'
    pytest                                                      # 134 tests

    # real Btrfs (loopback image, needs sudo once): sudo bash deploy/setup_btrfs.sh up
    python -m ctrr.monitor --backend btrfs --watch /mnt/ctrr/data --snapshots /mnt/ctrr/.snapshots --trace trace.jsonl
    python tools/simulate_attack.py --target /mnt/ctrr/data --rate 10 --trace trace.jsonl
    btrfs property get -ts /mnt/ctrr/.snapshots/<snap> ro       # ro=true
    python tools/ctrr_restore.py restore --watch /mnt/ctrr/data --snapshots /mnt/ctrr/.snapshots --verify

The simulator refuses to run unless the target holds a `.ctrr-test-corpus` file. See `demo_scripts/README.md` for the unattended demos.

## Reproduce every number

| Result | Command | Output |
|---|---|---|
| NapierOne data | `python tools/fetch_napierone.py` | `experiments/data/napierone/` (gitignored) |
| Model A vs Shannon rule | `python experiments/model_a.py` | `experiments/results/model_a.{md,json}` |
| Model B | `python experiments/model_b.py --train experiments/results/batch-dev` | `model_b_fit.json` |
| Batch runs (dev seeds 1-3) | `python tools/run_batch.py --split dev --results-dir experiments/results/batch-dev` | one directory per run: trace, config, monitor log |
| Batch runs (held-out seeds 4-8, run once) | `python tools/run_batch.py --split heldout --results-dir experiments/results/batch-heldout` | same |
| Policy comparison | `python experiments/compare_policies.py --runs <batch dir> --label dev` | `policy_comparison_<label>.{md,json}` |
| B3 before/after | see `experiments/results/b3_before_after.md` | |

## Results (held-out seeds 4-8, 45 attack runs and 25 benign runs)

| Policy | Detected | Median latency (detected runs) | Median files overwritten, detected runs | Median files overwritten, all attack runs (miss = 60) | False triggers (benign) |
|---|---|---|---|---|---|
| P0: Shannon delta + hand-written scores | 8/45 | 4987 ms | 35 of 60 | 60 of 60 | 0/25 |
| P1: Model A in the entropy slot | 45/45 | 2584 ms | 18 of 60 | 18 of 60 | 3/25 (all `git_clone`) |
| P2: Model A + Model B, weights 0.5/0.5 | 45/45 | 1063 ms | 7 of 60 | 7 of 60 | 0/25 |

Latency and the detected-runs files column are medians over detected runs only, so P0's 35 describes just its 8 detections. The all-runs column and a per-scenario breakdown are in `experiments/results/policy_comparison_heldout_allruns.md` (from `python experiments/summarize_allruns.py --label heldout`, computed from the saved JSON, no re-run). Model B's features are rate, extension and spread only; delta time is not used.

Model A (random forest, split by NapierOne sequence number): F1 0.998 on held-out sequence numbers. **Caveat:** this score leans heavily on the file-signature feature. Without it the forest's false-positive rate on benign archives rises from 0 to 0.46 (F1 0.974), so the 0.998 largely reflects that NapierOne's encrypted files lack file headers, not that content statistics alone separate encryption from compression. The Shannon-delta rule reaches only 0.11 recall on pdf and 0.25 on jpg, because those formats are already high-entropy. Full tables: `experiments/results/model_a.md`.

## Model B on real ransomware I/O traces (Berrueta et al.)

Command: `python experiments/berrueta_model_b.py --data experiments/data/berrueta/unz/textFiles --label all`. Output: `experiments/results/berrueta_model_b_all.{md,json}`. Model B (logistic regression, trained only on our simulator dev seeds) was scored once, untouched, on 189 real Windows 7 SMB I/O logs (166 with at least 20 write-closes). Policy PB: Model B alone feeds the accumulator, the content-plus-behaviour quorum is waived because these logs have no file contents, and thresholds and decay are the live ones.

**Detected 145 of 166 runs.** Time from the first write-close to trigger: median 18.4 s; files written before the trigger: median 12 (these shares hold 760 to 5,000 files, so quote counts, not percentages). All 21 misses are runs with no rename events (the extension signal stays 0), which caps Model B at 0.352, below the 0.65 threshold: copy-and-delete or in-place overwrite ransomware, the audit B2 blind spot, shows up here on real data (bart, Spora, Zeus, CryptoMix, CryptoShield, CrypMIC, DMALocker, Ryuk, Virlock, revenge, and one CryptFile2 run). Slow or late detections (maktub median 1,804 files, CTB-Locker 60% of files, CryptFile2 and CryptoMix when detected) are also in the per-family table.

What this does and does not show: recall only (every run is an attack, no benign runs exist in this dataset, so no false-trigger claim); no entropy or Model A (no contents); the normalisation ceilings (rate, extension, spread) are our policy constants and these captures differ in OS, speed and share size, so some misses may be domain shift as well as the missing rename signal. The SMB-to-event converter is covered by three unit tests on synthetic lines only; it was cross-checked against the raw logs (rename counts match for Locky and CTB-Locker) but not against an independent implementation.

## Limits (read before quoting any number)

- **Model A leans on the file-signature feature.** Without it the forest's false-positive rate on benign archives rises from 0 to 0.46 (logistic regression: 1.0). A ransomware that keeps file headers would weaken it. P1 triggers on `git_clone` because the signature table in `src/ctrr/features.py` has no entry for git data: pack files do start with a signature (`PACK`) and loose objects are zlib streams (header byte 0x78), but neither is in the table, so they look like headerless high-entropy data to Model A. This is a gap in our table, not a property of git; reported, not fixed.
- **All attacks are simulated.** Behaviour comes from our simulator (with real NapierOne ciphertext in one mode), not from real ransomware I/O traces. Model B was trained on the simulator's traces, so P2's result shows it separates our simulator from our benign workloads, not that it generalises. Model B's check against real traces is recall-only (see the Berrueta section above).
- **One corpus size and one machine.** 60-file corpora, one loopback Btrfs image, one ransomware family (RYUK) for the real-ciphertext mode. Within a run the ticks are near-duplicates, so only per-run counts are quoted.
- **Batch runs use the `copytree` snapshot backend**; Btrfs is exercised by the demo only. "Files overwritten before snapshot" is counted from the trace, not from the snapshot contents.
- **Restore does not delete extra files.** After a restore, encrypted `.enc` copies that were not in the snapshot stay in place.
- **Live monitor uses Shannon delta (P0).** Model A and B are applied in replay only. The live demo still triggers on P0.
- **Threshold 0.65 is a demo-scope value**, not chosen by a sweep. The arbiter ticks on `IN_CLOSE_WRITE` rather than a fixed 500 ms timer. Copy-encrypt-delete ransomware (audit B2) is not detected.

## Layout

    src/ctrr/        watcher, extractor, features, scorer, snapshot, monitor
    tools/           simulate_attack, build_corpus, run_batch, replay_trace, ctrr_restore, fetch_napierone
    experiments/     model_a, model_b, compare_policies, bench_entropy, results/
    deploy/          Btrfs loopback setup, root-owned snapshot helper, sudoers rule
    demo_scripts/    unattended demos
    tests/           134 tests
