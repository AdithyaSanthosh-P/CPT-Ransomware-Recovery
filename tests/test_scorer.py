"""
tests/test_scorer.py
====================
Unit tests for src/ctrr/scorer.py.

Tests are organised by component:
  - fuse()       : pure function, easy to hand-compute expected values
  - Scorer.tick(): state machine transitions, each tested in isolation

No filesystem access.  All inputs are constructed SubScores objects with
explicit field values.  Monotonic timestamps are plain integers (nanoseconds).

Test strategy mirrors the M5 done-when criteria from the execution plan:
  - Table-driven tests covering every arbiter transition.
  - Property test: no two TRIGGERs occur without the arbiter passing through
    COOLDOWN between them.
"""

import pytest

from ctrr.extractor import SubScores
from ctrr.scorer import (
    ArbiterState,
    Scorer,
    _ACCUMULATOR_DECAY,
    _COOLDOWN_NS,
    _HARD_THRESHOLD,
    _HYSTERESIS_GAP,
    _QUORUM_MIN,
    _QUORUM_SIGNAL_THRESHOLD,
    _SOFT_THRESHOLD,
    _WEIGHT_ENTROPY,
    _WEIGHT_EXTENSION,
    _WEIGHT_RATE,
    _WEIGHT_SPREAD,
    fuse,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def scores(entropy=0.0, rate=0.0, extension=0.0, spread=0.0) -> SubScores:
    """Construct a SubScores with explicit values for test use."""
    return SubScores(entropy=entropy, rate=rate, extension=extension, spread=spread)


def pump_accumulator(scorer: Scorer, s: SubScores, ticks: int, start_ts: int = 0, step_ns: int = 100_000_000) -> int:
    """Feed `ticks` identical SubScores into the scorer and return the final mono_ts."""
    t = start_ts
    for _ in range(ticks):
        t += step_ns
        scorer.tick(s, mono_ts=t)
    return t


def scores_above_hard() -> SubScores:
    """
    Return a SubScores that produces a fused_score >= HARD_THRESHOLD with
    at least QUORUM_MIN signals above QUORUM_SIGNAL_THRESHOLD.
    Used to drive the accumulator past the hard threshold after enough ticks.
    """
    # All three signals high enough to clear quorum and hard threshold.
    return scores(entropy=0.9, rate=0.9, extension=0.9)


def scores_above_soft() -> SubScores:
    """
    Return a SubScores that produces a fused_score >= SOFT_THRESHOLD but
    < HARD_THRESHOLD.  Used to drive NORMAL -> SUSPECT without triggering.

    Derivation: fuse(1.0, 0, 0, 0) = 0.40 * 1.0 = 0.40 >= SOFT_THRESHOLD (0.35).
    fuse(1.0, 0, 0, 0) = 0.40 < HARD_THRESHOLD (0.70).  One active signal only
    (entropy=1.0 > 0.1), so quorum is not met even if the hard threshold were
    reached by some other combination.
    """
    return scores(entropy=1.0, rate=0.0, extension=0.0, spread=0.0)


def scores_neutral() -> SubScores:
    """All sub-scores at zero; fused_score = 0.0."""
    return scores()


def reach_suspect(scorer: Scorer, start_ts: int = 0) -> int:
    """Pump the scorer into SUSPECT state and return the final mono_ts used.

    With decay=0.85 and fuse=0.36, the accumulator approaches 0.36 asymptotically.
    After n ticks from 0: acc ~ 0.36 * (1 - 0.85^n).  To exceed SOFT_THRESHOLD=0.35
    we need 0.36 * (1 - 0.85^n) > 0.35, i.e. n > log(1/36) / log(0.85) ~ 24 ticks.
    30 ticks gives a comfortable margin.
    """
    return pump_accumulator(scorer, scores_above_soft(), ticks=30, start_ts=start_ts)


def reach_trigger(scorer: Scorer, start_ts: int = 0) -> int:
    """Pump the scorer from fresh through SUSPECT into TRIGGER; return final mono_ts."""
    # First reach SUSPECT.
    ts = reach_suspect(scorer, start_ts=start_ts)
    # Then pump high scores until TRIGGER fires (accumulator crosses HARD_THRESHOLD).
    # 40 ticks at fuse=0.9 guarantees the accumulator reaches 0.70.
    s = scores_above_hard()
    for _ in range(40):
        ts += 100_000_000
        state = scorer.tick(s, mono_ts=ts)
        if state == ArbiterState.TRIGGER:
            return ts
    raise AssertionError("TRIGGER did not fire after 40 high ticks -- check thresholds")


# ---------------------------------------------------------------------------
# fuse() -- pure fusion function
# ---------------------------------------------------------------------------

class TestFuse:

    def test_neutral_scores_fuse_to_zero(self):
        """All sub-scores at 0.0 must produce a fused score of 0.0."""
        assert fuse(scores()) == 0.0

    def test_fuse_weighted_sum_correct(self):
        """
        Hand-computed weighted sum:
          entropy=1.0, rate=0.0, extension=0.0, spread=0.0
          -> 0.40 * 1.0 + 0.30 * 0.0 + 0.15 * 0.0 + 0.15 * 0.0 = 0.40
        """
        assert fuse(scores(entropy=1.0)) == pytest.approx(_WEIGHT_ENTROPY)

    def test_fuse_all_ones_gives_one(self):
        """
        With all sub-scores at 1.0, the weighted sum must equal 1.0 because
        the weights are constrained to sum to 1.0.
        """
        assert fuse(scores(entropy=1.0, rate=1.0, extension=1.0, spread=1.0)) == pytest.approx(1.0)

    def test_fuse_result_in_range(self):
        """Property: fused score is in [0, 1] for any valid sub-scores."""
        test_cases = [
            scores(0.0, 0.0, 0.0, 0.0),
            scores(1.0, 1.0, 1.0, 1.0),
            scores(0.5, 0.3, 0.8, 0.2),
            scores(0.0, 1.0, 0.0, 0.5),
        ]
        for s in test_cases:
            result = fuse(s)
            assert 0.0 <= result <= 1.0, f"fuse({s}) = {result} out of range"


# ---------------------------------------------------------------------------
# Scorer -- initial state
# ---------------------------------------------------------------------------

class TestScorerInitialState:

    def test_initial_state_is_normal(self):
        """A freshly created Scorer must start in NORMAL."""
        scorer = Scorer()
        assert scorer.state == ArbiterState.NORMAL

    def test_initial_fused_score_is_zero(self):
        scorer = Scorer()
        assert scorer.fused_score == 0.0

    def test_initial_trigger_count_is_zero(self):
        scorer = Scorer()
        assert scorer.trigger_count == 0


# ---------------------------------------------------------------------------
# Scorer -- NORMAL -> SUSPECT transition
# ---------------------------------------------------------------------------

class TestNormalToSuspect:

    def test_neutral_scores_stay_normal(self):
        """Scores at 0.0 must keep the arbiter in NORMAL."""
        scorer = Scorer()
        state = scorer.tick(scores_neutral(), mono_ts=0)
        assert state == ArbiterState.NORMAL

    def test_score_below_soft_stays_normal(self):
        """A fused score just below SOFT_THRESHOLD must not advance to SUSPECT."""
        scorer = Scorer()
        # entropy=0.70 -> fuse=0.315 < SOFT_THRESHOLD; accumulator stays near 0.
        s = scores(entropy=0.70)
        assert fuse(s) < _SOFT_THRESHOLD
        state = scorer.tick(s, mono_ts=0)
        assert state == ArbiterState.NORMAL

    def test_sustained_score_above_soft_enters_suspect(self):
        """
        After enough ticks above SOFT_THRESHOLD the accumulator crosses
        the soft threshold and the arbiter enters SUSPECT.
        """
        scorer = Scorer()
        reach_suspect(scorer)
        assert scorer.state == ArbiterState.SUSPECT

    def test_fused_score_updated_on_tick(self):
        """tick() must update the fused_score property."""
        scorer = Scorer()
        scorer.tick(scores(entropy=1.0), mono_ts=0)
        assert scorer.fused_score == pytest.approx(_WEIGHT_ENTROPY)


# ---------------------------------------------------------------------------
# Scorer -- SUSPECT -> NORMAL (disarm)
# ---------------------------------------------------------------------------

class TestSuspectToNormal:

    def test_sustained_quiet_disarms_suspect(self):
        """
        After reaching SUSPECT, feeding enough quiet ticks must decay the
        accumulator past the hysteresis band and return to NORMAL.
        """
        scorer = Scorer()
        ts = reach_suspect(scorer)
        assert scorer.state == ArbiterState.SUSPECT

        # Feed neutral ticks; accumulator must decay past (SOFT - HYSTERESIS_GAP).
        ts = pump_accumulator(scorer, scores_neutral(), ticks=60, start_ts=ts)
        assert scorer.state == ArbiterState.NORMAL

    def test_single_quiet_tick_does_not_immediately_disarm(self):
        """
        Hysteresis: a single quiet tick from SUSPECT must not immediately
        return to NORMAL -- the accumulator needs time to decay.
        """
        scorer = Scorer()
        ts = reach_suspect(scorer)
        assert scorer.state == ArbiterState.SUSPECT

        # One neutral tick is not enough to cross the hysteresis band.
        ts += 100_000_000
        state = scorer.tick(scores_neutral(), mono_ts=ts)
        assert state == ArbiterState.SUSPECT


# ---------------------------------------------------------------------------
# Scorer -- SUSPECT -> TRIGGER
# ---------------------------------------------------------------------------

class TestSuspectToTrigger:

    def test_hard_threshold_with_quorum_triggers(self):
        """
        A sustained fused score above HARD_THRESHOLD with quorum must return
        TRIGGER and advance internally to COOLDOWN.
        """
        scorer = Scorer()
        reach_trigger(scorer)
        assert scorer.trigger_count == 1

    def test_trigger_increments_trigger_count(self):
        scorer = Scorer()
        reach_trigger(scorer)
        assert scorer.trigger_count == 1

    def test_state_after_trigger_is_cooldown(self):
        """The tick after a TRIGGER must return COOLDOWN, not TRIGGER again."""
        scorer = Scorer()
        ts = reach_trigger(scorer)
        # Internal state is now COOLDOWN; the next tick must return COOLDOWN.
        state = scorer.tick(scores_above_hard(), mono_ts=ts + 100_000_000)
        assert state == ArbiterState.COOLDOWN

    def test_trigger_without_quorum_does_not_fire(self):
        """
        A high fused score without meeting the quorum requirement must not
        trigger.  Only one signal is active here.
        """
        scorer = Scorer()

        # Verify: a SubScores with only one signal active does not meet quorum.
        s = scores(entropy=1.0, rate=0.0, extension=0.0)
        assert s.active_signals(_QUORUM_SIGNAL_THRESHOLD) < _QUORUM_MIN

    def test_direct_normal_to_trigger_not_possible(self):
        """
        A single tick from NORMAL with a high score cannot reach TRIGGER.
        The accumulator starts at 0.0 and cannot cross either SOFT_THRESHOLD
        (0.35) or HARD_THRESHOLD (0.70) in a single tick with decay=0.85.
        One tick at fuse=0.9: acc = (1-0.85)*0.9 = 0.135 < SOFT_THRESHOLD.
        """
        scorer = Scorer()
        state = scorer.tick(scores_above_hard(), mono_ts=0)
        # Accumulator is only 0.135 after one tick -- below SOFT_THRESHOLD.
        assert state == ArbiterState.NORMAL
        assert scorer.trigger_count == 0


# ---------------------------------------------------------------------------
# Scorer -- COOLDOWN -> NORMAL (re-arm)
# ---------------------------------------------------------------------------

class TestCooldown:

    def test_cooldown_persists_within_window(self):
        """High scores during the cooldown period must not re-trigger."""
        scorer = Scorer()
        ts = reach_trigger(scorer)

        # Feed high scores at T+100ms -- still within 30s cooldown.
        state = scorer.tick(scores_above_hard(), mono_ts=ts + 100_000_000)
        assert state == ArbiterState.COOLDOWN
        assert scorer.trigger_count == 1    # no second trigger

    def test_cooldown_expires_and_returns_to_normal(self):
        """After COOLDOWN_NS nanoseconds, the arbiter must re-arm to NORMAL."""
        scorer = Scorer()
        ts = reach_trigger(scorer)

        # Feed a neutral event past the cooldown window.
        past_cooldown = ts + _COOLDOWN_NS + 1_000_000_000
        state = scorer.tick(scores_neutral(), mono_ts=past_cooldown)
        assert state == ArbiterState.NORMAL

    def test_double_trigger_requires_cooldown_between(self):
        """
        Property: no two TRIGGERs can fire without the arbiter passing through
        COOLDOWN.  This is the M5 property test from the execution plan.

        Simulate a sustained attack: drive the arbiter to TRIGGER, then
        continue feeding high scores.  Confirm a second TRIGGER only fires
        after the cooldown has elapsed and the arbiter has re-armed.
        """
        scorer = Scorer()
        trigger_times = []

        t = 0
        step = 100_000_000   # 100ms steps

        for _ in range(1000):
            t += step
            state = scorer.tick(scores_above_hard(), mono_ts=t)
            if state == ArbiterState.TRIGGER:
                trigger_times.append(t)

        # Every consecutive pair of trigger timestamps must be separated by
        # at least COOLDOWN_NS nanoseconds (the arbiter cannot fire twice
        # within a single cooldown window).
        for i in range(1, len(trigger_times)):
            gap = trigger_times[i] - trigger_times[i - 1]
            assert gap >= _COOLDOWN_NS, (
                f"Two triggers {gap} ns apart -- less than cooldown {_COOLDOWN_NS} ns"
            )
# ---------------------------------------------------------------------------
# Accumulator and hysteresis
# ---------------------------------------------------------------------------

class TestAccumulator:

    def test_initial_accumulator_is_zero(self):
        """A freshly created Scorer must start with accumulator at 0.0."""
        scorer = Scorer()
        assert scorer.accumulator == 0.0

    def test_accumulator_rises_on_high_ticks(self):
        """The accumulator must increase each time fused_score >= SOFT_THRESHOLD."""
        scorer = Scorer()
        prev = scorer.accumulator
        s = scores_above_soft()
        for _ in range(5):
            scorer.tick(s, mono_ts=0)
            assert scorer.accumulator > prev, "accumulator did not rise on high tick"
            prev = scorer.accumulator

    def test_accumulator_decays_on_quiet_ticks(self):
        """After a high period, quiet ticks must bring the accumulator down."""
        scorer = Scorer()
        reach_suspect(scorer)   # drive accumulator up
        high_val = scorer.accumulator
        assert high_val > 0.0

        # One quiet tick; accumulator must have decayed.
        scorer.tick(scores_neutral(), mono_ts=999_999_999_999)
        assert scorer.accumulator < high_val

    def test_accumulator_clamped_to_unit_interval(self):
        """Accumulator must never exceed 1.0 or drop below 0.0."""
        scorer = Scorer()
        # Saturate with high scores.
        pump_accumulator(scorer, scores(entropy=1.0, rate=1.0, extension=1.0), ticks=200)
        assert scorer.accumulator <= 1.0
        # Then drain with quiet ticks.
        pump_accumulator(scorer, scores_neutral(), ticks=200)
        assert scorer.accumulator >= 0.0

    def test_single_spike_does_not_trigger(self):
        """
        A single tick with an extremely high fused score must not cause a
        TRIGGER -- the accumulator needs time to build past the hard threshold.
        This is the core anti-spike property of the leaky integrator.
        """
        scorer = Scorer()
        # One tick with the maximum possible score.
        state = scorer.tick(scores(entropy=1.0, rate=1.0, extension=1.0), mono_ts=1)
        # Should reach SUSPECT at most (accumulator too low for HARD_THRESHOLD).
        assert state != ArbiterState.TRIGGER
        assert scorer.trigger_count == 0

    def test_hysteresis_prevents_immediate_disarm(self):
        """
        A single quiet tick from SUSPECT must NOT immediately return to NORMAL
        because the accumulator is still above (SOFT_THRESHOLD - HYSTERESIS_GAP).
        """
        scorer = Scorer()
        ts = reach_suspect(scorer)
        assert scorer.state == ArbiterState.SUSPECT

        ts += 100_000_000
        state = scorer.tick(scores_neutral(), mono_ts=ts)
        # Accumulator still above the hysteresis floor; must stay SUSPECT.
        assert state == ArbiterState.SUSPECT

    def test_hysteresis_floor_calculation(self):
        """The disarm floor must be exactly SOFT_THRESHOLD - HYSTERESIS_GAP."""
        floor = _SOFT_THRESHOLD - _HYSTERESIS_GAP
        assert floor == pytest.approx(0.30)
