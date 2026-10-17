"""
tests/test_trace_replay.py
==========================
Trace completeness and live-vs-replay equivalence (course-plan Day 2).

The claim under test: a trace written by the monitor contains every tick
with all four sub-scores, so replaying it under the same policy reproduces
the live state sequence and accumulator values exactly.  Without this, the
policy-comparison tables built from replay would not be evidence about the
live system.

The extractor pipeline is stubbed with a scripted SubScores sequence so the
test exercises the monitor's trace writer and the replay engine, not inotify
or file reads.
"""

import json
import sys
from pathlib import Path

import pytest

from ctrr.extractor import OP_CLOSE_WRITE, FileEvent, SubScores
from ctrr.monitor import Monitor

sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
import replay_trace  # noqa: E402
import simulate_attack  # noqa: E402

_MS = 1_000_000


def _script():
    """Quiet ticks, a sustained 4-signal attack, then quiet again.  Long
    enough to reach TRIGGER, COOLDOWN and decay back, with fractional values
    that would expose any rounding in the trace."""
    quiet  = SubScores(0.01, 0.02, 0.0, 0.0)
    attack = SubScores(0.88, 1.0, 0.2, 0.33333333333333337)
    return [quiet] * 5 + [attack] * 40 + [quiet] * 20


@pytest.fixture
def live_run(tmp_path):
    watch = tmp_path / "watch"
    watch.mkdir()
    trace = tmp_path / "trace.jsonl"
    m = Monitor(str(watch), str(tmp_path / "snaps"), trace_path=str(trace))
    scripted = iter(_script())
    m._pipeline.process_event = lambda event: next(scripted)
    # Taking a real snapshot is not what is under test.
    m._snapshot.take = lambda reason="trigger": str(tmp_path / "snap")
    live_states = []
    real_tick = m._scorer.tick

    def recording_tick(scores, mono_ts):
        state = real_tick(scores, mono_ts)
        live_states.append((state.value, m._scorer.fused_score, m._scorer.accumulator))
        return state

    m._scorer.tick = recording_tick
    for i in range(len(_script())):
        m._on_event(FileEvent(path=str(watch / f"f{i}"), op=OP_CLOSE_WRITE,
                              mono_ts=i * 100 * _MS))
    m._watcher._inotify.close()
    return trace, live_states


class TestTraceCompleteness:
    def test_every_tick_is_logged_including_normal(self, live_run):
        trace, live = live_run
        recs = [json.loads(l) for l in trace.read_text().splitlines()]
        assert len(recs) == len(live) == len(_script())
        assert recs[0]["state"] == "NORMAL"

    def test_all_four_subscores_logged_at_full_precision(self, live_run):
        trace, _ = live_run
        rec = json.loads(trace.read_text().splitlines()[10])
        assert rec["type"] == "tick"
        assert rec["spread"] == 0.33333333333333337
        assert {"entropy", "rate", "extension", "spread"} <= rec.keys()


class TestLiveReplayEquivalence:
    def test_replay_reproduces_live_states_and_accumulator(self, live_run):
        trace, live = live_run
        summary = replay_trace.replay(replay_trace._load_trace(str(trace)), quiet=True)
        assert summary["sequence"] == live  # exact float equality, not approx

    def test_live_run_reaches_trigger(self, live_run):
        # Guards the test itself: equivalence over an all-NORMAL run is vacuous.
        _, live = live_run
        assert "TRIGGER" in [s for s, _, _ in live]
        assert "COOLDOWN" in [s for s, _, _ in live]


class TestGroundTruthMarkers:
    def test_simulator_writes_start_and_end_markers(self, tmp_path):
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        (corpus / ".ctrr-test-corpus").touch()
        for i in range(2):
            (corpus / f"f{i}.txt").write_text("hello " * 100)
        trace = tmp_path / "t.jsonl"
        simulate_attack.simulate(corpus, rate=0, verbose=False, trace=trace)
        recs = [json.loads(l) for l in trace.read_text().splitlines()]
        assert [r["event"] for r in recs] == ["ATTACK_START", "ATTACK_END"]
        assert recs[0]["mono_ts"] < recs[1]["mono_ts"]
        assert recs[1]["encrypted"] == 2

    def test_markers_label_ticks_and_do_not_affect_scoring(self):
        ticks = [{"type": "tick", "mono_ts": t, "entropy": 0, "rate": 0,
                  "extension": 0, "spread": 0} for t in (10, 20, 30, 40)]
        markers = [{"type": "marker", "event": "ATTACK_START", "mono_ts": 15},
                   {"type": "marker", "event": "ATTACK_END", "mono_ts": 35}]
        window = replay_trace.attack_window(markers)
        assert window == (15, 35)
        labels = [replay_trace.label_tick(t["mono_ts"], window) for t in ticks]
        assert labels == ["benign", "attack", "attack", "benign"]
        assert replay_trace.replay(ticks + markers, quiet=True)["total_ticks"] == 4

    def test_no_markers_means_unlabelled(self):
        assert replay_trace.label_tick(5, replay_trace.attack_window([])) == "unlabelled"


class _ConstModel:
    """Stand-in for a fitted sklearn model: predict_proba -> fixed P(class 1)."""

    def __init__(self, p):
        self.p = p

    def predict_proba(self, X):
        import numpy as np
        return np.array([[1 - self.p, self.p]] * len(X))


def _attack_ticks(n=80):
    # Shannon entropy sub-score is 0 everywhere; only the model can supply content evidence.
    return [{"type": "tick", "mono_ts": i * 100 * _MS, "entropy": 0.0, "rate": 1.0,
             "extension": 1.0, "spread": 0.0, "feat": [0.0] * 9} for i in range(n)]


class TestPolicies:
    def test_p0_ignores_models_and_misses_when_entropy_is_zero(self):
        s = replay_trace.replay(_attack_ticks(), quiet=True, policy="P0")
        assert s["trigger_count"] == 0

    def test_p1_uses_model_a_in_the_entropy_slot(self):
        s = replay_trace.replay(_attack_ticks(), quiet=True, policy="P1",
                                model_a=_ConstModel(0.95))
        assert s["trigger_count"] == 1

    def test_p2_uses_model_a_and_b_with_equal_weights(self):
        s = replay_trace.replay(_attack_ticks(), quiet=True, policy="P2",
                                model_a=_ConstModel(0.9), model_b=_ConstModel(0.9))
        assert s["trigger_count"] == 1
        # fused = 0.5 * 0.9 + 0.5 * 0.9
        assert s["sequence"][0][1] == pytest.approx(0.9)

    def test_p2_restores_module_weights_afterwards(self):
        import ctrr.scorer as sc
        before = (sc._WEIGHT_ENTROPY, sc._WEIGHT_RATE, sc._WEIGHT_EXTENSION, sc._WEIGHT_SPREAD)
        replay_trace.replay(_attack_ticks(5), quiet=True, policy="P2",
                            model_a=_ConstModel(0.5), model_b=_ConstModel(0.5))
        assert (sc._WEIGHT_ENTROPY, sc._WEIGHT_RATE, sc._WEIGHT_EXTENSION, sc._WEIGHT_SPREAD) == before

    def test_model_policies_require_their_models(self):
        with pytest.raises(ValueError):
            replay_trace.replay(_attack_ticks(3), quiet=True, policy="P1")
        with pytest.raises(ValueError):
            replay_trace.replay(_attack_ticks(3), quiet=True, policy="P2", model_a=_ConstModel(1))

    def test_unreadable_file_gives_model_a_zero(self):
        ticks = _attack_ticks(80)
        for t in ticks:
            t["feat"] = None
        s = replay_trace.replay(ticks, quiet=True, policy="P1", model_a=_ConstModel(1.0))
        assert s["trigger_count"] == 0
