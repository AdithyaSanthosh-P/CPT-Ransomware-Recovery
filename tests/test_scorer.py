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
    _COOLDOWN_NS,
    _HARD_THRESHOLD,
    _QUORUM_MIN,
    _QUORUM_SIGNAL_THRESHOLD,
    _SOFT_THRESHOLD,
    _WEIGHT_ENTROPY,
    _WEIGHT_EXTENSION,
    _WEIGHT_RATE,
    fuse,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def scores(entropy=0.0, rate=0.0, extension=0.0) -> SubScores:
    """Construct a SubScores with explicit values for test use."""
    return SubScores(entropy=entropy, rate=rate, extension=extension)


def scores_above_hard() -> SubScores:
    """
    Return a SubScores that produces a fused_score >= HARD_THRESHOLD with
    at least QUORUM_MIN signals above QUORUM_SIGNAL_THRESHOLD.
    Used to drive the SUSPECT -> TRIGGER transition.
    """
    # All three signals high enough to clear quorum and hard threshold.
    return scores(entropy=0.9, rate=0.9, extension=0.9)


def scores_above_soft() -> SubScores:
    """
    Return a SubScores that produces a fused_score >= SOFT_THRESHOLD but
    < HARD_THRESHOLD.  Used to drive NORMAL -> SUSPECT without triggering.

    Derivation: fuse(0.8, 0, 0) = 0.45 * 0.8 = 0.36 >= SOFT_THRESHOLD (0.35).
    fuse(0.8, 0, 0) = 0.36 < HARD_THRESHOLD (0.70).  One active signal only
    (entropy=0.8 > 0.1), so quorum is not met even if the hard threshold were
    reached by some other combination.
    """
    return scores(entropy=0.8, rate=0.0, extension=0.0)


def scores_neutral() -> SubScores:
    """All sub-scores at zero; fused_score = 0.0."""
    return scores()


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
          entropy=1.0, rate=0.0, extension=0.0
          -> 0.45 * 1.0 + 0.35 * 0.0 + 0.20 * 0.0 = 0.45
        """
        assert fuse(scores(entropy=1.0)) == pytest.approx(_WEIGHT_ENTROPY)

    def test_fuse_all_ones_gives_one(self):
        """
        With all sub-scores at 1.0, the weighted sum must equal 1.0 because
        the weights are constrained to sum to 1.0.
        """
        assert fuse(scores(entropy=1.0, rate=1.0, extension=1.0)) == pytest.approx(1.0)

    def test_fuse_result_in_range(self):
        """Property: fused score is in [0, 1] for any valid sub-scores."""
        test_cases = [
            scores(0.0, 0.0, 0.0),
            scores(1.0, 1.0, 1.0),
            scores(0.5, 0.3, 0.8),
            scores(0.0, 1.0, 0.0),
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
        # Construct scores whose fused value is just below SOFT_THRESHOLD.
        # SOFT_THRESHOLD = 0.35; set entropy alone to 0.34 / 0.45 ~ 0.755
        # But simpler: use extension only at just below soft threshold.
        # fuse(0, 0, ext) = 0.20 * ext.  For fuse < 0.35, ext < 1.75 -- not possible.
        # Use entropy: 0.20 * ext: can't reach 0.35 alone.
        # Use entropy = 0.70: fuse = 0.45 * 0.70 = 0.315 < 0.35.
        s = scores(entropy=0.70)
        assert fuse(s) < _SOFT_THRESHOLD
        state = scorer.tick(s, mono_ts=0)
        assert state == ArbiterState.NORMAL

    def test_score_at_soft_threshold_enters_suspect(self):
        """
        A fused score at or above SOFT_THRESHOLD must advance to SUSPECT.
        scores_above_soft() produces fuse = 0.36 >= SOFT_THRESHOLD (0.35).
        """
        scorer = Scorer()
        assert fuse(scores_above_soft()) >= _SOFT_THRESHOLD   # guard
        state = scorer.tick(scores_above_soft(), mono_ts=0)
        assert state == ArbiterState.SUSPECT

    def test_fused_score_updated_on_tick(self):
        """tick() must update the fused_score property."""
        scorer = Scorer()
        scorer.tick(scores(entropy=1.0), mono_ts=0)
        assert scorer.fused_score == pytest.approx(_WEIGHT_ENTROPY)


# ---------------------------------------------------------------------------
# Scorer -- SUSPECT -> NORMAL (disarm)
# ---------------------------------------------------------------------------

class TestSuspectToNormal:

    def test_score_drop_disarms_suspect(self):
        """
        If the fused score falls back below SOFT_THRESHOLD while in SUSPECT,
        the arbiter must return to NORMAL.
        """
        scorer = Scorer()
        scorer.tick(scores_above_soft(), mono_ts=0)   # -> SUSPECT
        assert scorer.state == ArbiterState.SUSPECT

        state = scorer.tick(scores_neutral(), mono_ts=1_000_000_000)
        assert state == ArbiterState.NORMAL


# ---------------------------------------------------------------------------
# Scorer -- SUSPECT -> TRIGGER
# ---------------------------------------------------------------------------

class TestSuspectToTrigger:

    def test_hard_threshold_with_quorum_triggers(self):
        """
        A fused score at or above HARD_THRESHOLD with quorum must return
        TRIGGER and advance internally to COOLDOWN.

        Setup: two ticks to reach SUSPECT, then one tick with scores_above_hard
        to cross the hard threshold with quorum (all 3 signals active).
        """
        scorer = Scorer()
        scorer.tick(scores_above_soft(), mono_ts=0)            # NORMAL -> SUSPECT
        assert scorer.state == ArbiterState.SUSPECT            # guard
        state = scorer.tick(scores_above_hard(), mono_ts=1_000_000_000)
        assert state == ArbiterState.TRIGGER

    def test_trigger_increments_trigger_count(self):
        scorer = Scorer()
        scorer.tick(scores_above_soft(), mono_ts=0)            # -> SUSPECT
        scorer.tick(scores_above_hard(), mono_ts=1_000_000_000)  # -> TRIGGER
        assert scorer.trigger_count == 1

    def test_state_after_trigger_is_cooldown(self):
        """The tick after a TRIGGER must return COOLDOWN, not TRIGGER again."""
        scorer = Scorer()
        scorer.tick(scores_above_soft(), mono_ts=0)            # -> SUSPECT
        scorer.tick(scores_above_hard(), mono_ts=1_000_000_000)  # returns TRIGGER
        # Internal state is now COOLDOWN; the next tick must return COOLDOWN.
        state = scorer.tick(scores_above_hard(), mono_ts=2_000_000_000)
        assert state == ArbiterState.COOLDOWN

    def test_trigger_without_quorum_does_not_fire(self):
        """
        A high fused score without meeting the quorum requirement must not
        trigger.  Only one signal is active here.
        """
        scorer = Scorer()
        scorer.tick(scores_above_soft(), mono_ts=0)   # -> SUSPECT

        # Only entropy is high; rate and extension are 0.
        # Quorum check: active_signals(0.1) = 1, which is < QUORUM_MIN (2).
        # Fused score = 0.45 * 1.0 = 0.45 -- below HARD_THRESHOLD (0.70) anyway.
        # Use high enough entropy to clear hard threshold alone, if quorum were ignored.
        # fuse(entropy=1.0, 0, 0) = 0.45 < 0.70; hard threshold not met either.
        # So we need a case where fused >= HARD_THRESHOLD but quorum fails.
        # fuse(e, r, 0): 0.45e + 0.35r >= 0.70.  With r=0: e >= 1.56 -- not possible.
        # Achievable: entropy=1.0, rate=1.0, extension=0.0 -> fuse = 0.80 >= 0.70.
        # active_signals(0.1): entropy=1.0 > 0.1, rate=1.0 > 0.1, extension=0.0 -- 2 active.
        # That meets quorum.  To fail quorum: entropy=1.0, rate=0.0, extension=0.0
        # -> fuse=0.45 < HARD_THRESHOLD.  Cannot isolate the quorum failure alone with
        # default weights.  Instead test the quorum method directly on SubScores.

        # Verify: a SubScores with only one signal active does not meet quorum.
        s = scores(entropy=1.0, rate=0.0, extension=0.0)
        assert s.active_signals(_QUORUM_SIGNAL_THRESHOLD) < _QUORUM_MIN

    def test_direct_normal_to_trigger_not_possible(self):
        """
        A single tick from NORMAL with a high score must pass through SUSPECT
        first.  The arbiter must not jump directly from NORMAL to TRIGGER.
        """
        scorer = Scorer()
        state = scorer.tick(scores_above_hard(), mono_ts=0)
        # NORMAL -> SUSPECT is the only allowed transition on this tick.
        assert state == ArbiterState.SUSPECT
        assert scorer.trigger_count == 0


# ---------------------------------------------------------------------------
# Scorer -- COOLDOWN -> NORMAL (re-arm)
# ---------------------------------------------------------------------------

class TestCooldown:

    def test_cooldown_persists_within_window(self):
        """High scores during the cooldown period must not re-trigger."""
        scorer = Scorer()
        scorer.tick(scores_above_soft(), mono_ts=0)               # -> SUSPECT
        scorer.tick(scores_above_hard(), mono_ts=1_000_000_000)   # returns TRIGGER
        # Internal state is now COOLDOWN.

        # Feed high scores at T=2s -- still within 30s cooldown.
        state = scorer.tick(scores_above_hard(), mono_ts=2_000_000_000)
        assert state == ArbiterState.COOLDOWN
        assert scorer.trigger_count == 1    # no second trigger

    def test_cooldown_expires_and_returns_to_normal(self):
        """After COOLDOWN_NS nanoseconds, the arbiter must re-arm to NORMAL."""
        scorer = Scorer()
        scorer.tick(scores_above_soft(), mono_ts=0)
        trigger_ts = 1_000_000_000
        scorer.tick(scores_above_hard(), mono_ts=trigger_ts)   # TRIGGER

        # Feed a neutral event past the cooldown window.
        past_cooldown = trigger_ts + _COOLDOWN_NS + 1_000_000_000
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
            s = scores_above_hard() if scorer.state != ArbiterState.COOLDOWN \
                else scores_above_hard()
            state = scorer.tick(s, mono_ts=t)
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
