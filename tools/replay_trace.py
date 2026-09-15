"""
tools/replay_trace.py
=====================
Offline replay engine for CTRR.

Reads a JSONL trace produced by the monitor (via --trace flag) and re-scores
every tick through the fusion engine and arbiter under a user-specified policy.

This is the core tool for Phase 4 threshold sweeps.  Instead of re-running a
live attack on a VM for every parameter combination, record one trace and then
sweep the policy space in seconds:

  python tools/replay_trace.py /tmp/ctrr-trace.jsonl
  python tools/replay_trace.py /tmp/ctrr-trace.jsonl --soft 0.30 --hard 0.65
  python tools/replay_trace.py /tmp/ctrr-trace.jsonl --decay 0.90 --hard 0.60

The replay engine is a pure re-computation: it instantiates a fresh Scorer,
patches the policy constants to the CLI values, then feeds every sub-score
triple from the trace through fuse() -> tick() in order.  The output is a
summary of state transitions and how many ticks elapsed in each state, so you
can compare detection latency and false-positive rate across policy variants
without touching the live system.

Usage
-----
  python tools/replay_trace.py TRACE_FILE [options]

Options
-------
  --soft FLOAT     Soft threshold (default: current _SOFT_THRESHOLD)
  --hard FLOAT     Hard threshold (default: current _HARD_THRESHOLD)
  --decay FLOAT    Accumulator decay factor (default: current _ACCUMULATOR_DECAY)
  --gap FLOAT      Hysteresis gap (default: current _HYSTERESIS_GAP)
  --quiet          Only print the summary, not per-tick transitions
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Add the project root to the path so this script can be run directly from
# tools/ without installing the package.
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import ctrr.scorer as scorer_module
from ctrr.extractor import SubScores
from ctrr.scorer import ArbiterState, Scorer, fuse


def _parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="CTRR offline trace replay -- re-score a saved trace under new policy constants"
    )
    p.add_argument("trace", metavar="TRACE_FILE",
                   help="Path to the JSONL trace file produced by monitor --trace")
    p.add_argument("--soft",  type=float, default=None,
                   help="Override soft threshold (default: from scorer module)")
    p.add_argument("--hard",  type=float, default=None,
                   help="Override hard threshold (default: from scorer module)")
    p.add_argument("--decay", type=float, default=None,
                   help="Override accumulator decay factor (default: from scorer module)")
    p.add_argument("--gap",   type=float, default=None,
                   help="Override hysteresis gap (default: from scorer module)")
    p.add_argument("--quiet", action="store_true",
                   help="Suppress per-tick output; print summary only")
    return p.parse_args(argv)


def _apply_policy_overrides(args) -> dict:
    """Patch scorer module constants with CLI overrides and return the active policy."""
    policy = {
        "soft":  scorer_module._SOFT_THRESHOLD,
        "hard":  scorer_module._HARD_THRESHOLD,
        "decay": scorer_module._ACCUMULATOR_DECAY,
        "gap":   scorer_module._HYSTERESIS_GAP,
    }
    if args.soft  is not None:
        scorer_module._SOFT_THRESHOLD    = args.soft;  policy["soft"]  = args.soft
    if args.hard  is not None:
        scorer_module._HARD_THRESHOLD    = args.hard;  policy["hard"]  = args.hard
    if args.decay is not None:
        scorer_module._ACCUMULATOR_DECAY = args.decay; policy["decay"] = args.decay
    if args.gap   is not None:
        scorer_module._HYSTERESIS_GAP   = args.gap;   policy["gap"]   = args.gap
    return policy


def _load_trace(path: str) -> list[dict]:
    """Read all JSONL records from the trace file."""
    records = []
    with open(path) as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                print(f"  WARNING: line {line_no} is not valid JSON ({exc}), skipping",
                      file=sys.stderr)
    return records


def replay(records: list[dict], quiet: bool) -> dict:
    """
    Re-score every record through a fresh Scorer.

    Returns a summary dict with counts of ticks per state, number of triggers
    fired, and the index of the first TRIGGER tick (or None).
    """
    sc = Scorer()
    state_counts: dict[str, int] = {s.value: 0 for s in ArbiterState}
    trigger_count  = 0
    first_trigger_tick = None
    transitions: list[tuple[int, str, str]] = []  # (tick_index, from, to)

    prev_state = ArbiterState.NORMAL

    for i, rec in enumerate(records):
        sub = SubScores(
            entropy=rec["entropy"],
            rate=rec["rate"],
            extension=rec["extension"],
        )
        # mono_ts from trace; tick() only needs it for cooldown bookkeeping.
        state = sc.tick(sub, mono_ts=rec["mono_ts"])
        state_counts[state.value] = state_counts.get(state.value, 0) + 1

        if state == ArbiterState.TRIGGER:
            trigger_count += 1
            if first_trigger_tick is None:
                first_trigger_tick = i

        if state != prev_state:
            transitions.append((i, prev_state.value, state.value))
            if not quiet:
                print(
                    f"  tick {i:5d}  {prev_state.value:8s} -> {state.value:8s}"
                    f"  fused={sc.fused_score:.3f}  acc={sc.accumulator:.3f}"
                )
            prev_state = state

    return {
        "total_ticks":       len(records),
        "trigger_count":     trigger_count,
        "first_trigger_tick": first_trigger_tick,
        "state_counts":      state_counts,
        "transitions":       transitions,
    }


def main(argv=None) -> None:
    args = _parse_args(argv)
    policy = _apply_policy_overrides(args)

    trace_path = Path(args.trace)
    if not trace_path.exists():
        print(f"ERROR: trace file not found: {trace_path}", file=sys.stderr)
        sys.exit(1)

    records = _load_trace(str(trace_path))
    if not records:
        print("ERROR: trace file is empty or contains no valid records.", file=sys.stderr)
        sys.exit(1)

    print(f"Replaying {len(records)} ticks from {trace_path}")
    print(f"Policy: soft={policy['soft']}  hard={policy['hard']}"
          f"  decay={policy['decay']}  gap={policy['gap']}")
    print()

    if not args.quiet:
        print("State transitions:")

    summary = replay(records, quiet=args.quiet)

    print()
    print("Summary")
    print("-------")
    print(f"  Total ticks     : {summary['total_ticks']}")
    print(f"  Triggers fired  : {summary['trigger_count']}")
    if summary["first_trigger_tick"] is not None:
        print(f"  First trigger   : tick {summary['first_trigger_tick']}"
              f" ({summary['first_trigger_tick'] / max(summary['total_ticks'], 1) * 100:.1f}%"
              f" into trace)")
    else:
        print(f"  First trigger   : none (did not reach TRIGGER under this policy)")
    print(f"  Ticks per state :")
    for state, count in sorted(summary["state_counts"].items()):
        if count > 0:
            pct = count / summary["total_ticks"] * 100
            print(f"    {state:10s}: {count:5d}  ({pct:.1f}%)")


if __name__ == "__main__":
    main()
