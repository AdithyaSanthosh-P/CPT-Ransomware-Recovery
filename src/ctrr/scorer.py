"""
src/ctrr/scorer.py
==================
Fusion engine and arbiter for CTRR.

Receives SubScores from the extractor pipeline on each tick and maintains
a state machine that transitions NORMAL -> SUSPECT -> TRIGGER.

Architecture
------------
Two stages run in sequence on every tick:

  [FUSION]       Weighted sum of three sub-scores -> fused_score in [0, 1].
                 Weights are module-level policy constants that sum to 1.0, so
                 the output is guaranteed in [0, 1] without additional clamping.
                 The fuse() function is intentionally a pure function so the
                 replay engine can call it on saved trace data without needing
                 a live Scorer instance.

  [ACCUMULATOR]  Leaky integrator that raises on each high-fused tick and
                 decays exponentially when the fused score is low.  The arbiter
                 acts on the accumulated value rather than the raw instantaneous
                 score, so the TRIGGER state requires sustained anomalous
                 activity and not just a single spike.

  [ARBITER]      Threshold comparisons + quorum gate -> ArbiterState.
                 NORMAL  : accumulator < SOFT_THRESHOLD
                 SUSPECT : accumulator >= SOFT_THRESHOLD
                 TRIGGER : accumulator >= ACCUMULATOR_TRIGGER_THRESHOLD
                           AND active_signals >= QUORUM_MIN
                 COOLDOWN: fixed period after a TRIGGER before re-arming

  TRIGGER is returned exactly once -- the tick on which the hard threshold
  and quorum are both crossed.  The arbiter then moves to COOLDOWN
  immediately.  The monitor acts on the returned TRIGGER state to fire the
  snapshot.

  Hysteresis: the SUSPECT -> NORMAL transition requires the accumulator to
  fall below (SOFT_THRESHOLD - HYSTERESIS_GAP), not just below SOFT_THRESHOLD.
  This prevents rapid state flapping when the score oscillates around the
  soft threshold boundary.

Deferred items (post-demo)
--------------------------
  - COOLDOWN -> ARMED distinction.  Production needs an explicit ARMED
    state before re-entering NORMAL so that a sustained attack cannot
    prevent re-arming.  The arbiter currently returns directly to NORMAL
    after the cooldown period.
"""

from __future__ import annotations

from enum import Enum

from ctrr.extractor import SubScores


# ---------------------------------------------------------------------------
# Policy constants
# All weights and thresholds are module-level so Phase 4 can sweep them by
# importing and patching these names, or by replacing this module with a
# policy-file-driven variant.
# ---------------------------------------------------------------------------

# Fusion weights -- must sum to 1.0 so the weighted sum stays in [0, 1].
# Entropy carries the most weight: it is the most discriminative signal on
# the development split (bench_entropy.py).  Rate responds fastest to burst
# behaviour.  Extension is the most precise but fires later in an attack.
# Spread is the weakest individual signal (tar and git also touch many dirs)
# but adds corroborating evidence when entropy and rate are both elevated.
_WEIGHT_ENTROPY   = 0.40
_WEIGHT_RATE      = 0.30
_WEIGHT_EXTENSION = 0.15
_WEIGHT_SPREAD    = 0.15

assert abs(_WEIGHT_ENTROPY + _WEIGHT_RATE + _WEIGHT_EXTENSION + _WEIGHT_SPREAD - 1.0) < 1e-9, \
    "fusion weights must sum to 1.0"

# Soft threshold: accumulator at or above this value moves the arbiter from
# NORMAL to SUSPECT and arms verbose logging.
_SOFT_THRESHOLD = 0.35

# Hard threshold: accumulator at or above this value, combined with quorum,
# fires a snapshot.  Evaluated against the *accumulated* value so a single
# spike in the raw fused score cannot trigger without sustained evidence.
_HARD_THRESHOLD = 0.70

# Quorum: at least this many sub-scores must be active (above the signal
# threshold) before a TRIGGER is allowed.  This prevents a single signal
# spiking to 1.0 from causing a trigger -- all three extractors are designed
# to be independent, so a corroborated reading is far more reliable.
_QUORUM_MIN              = 2
_QUORUM_SIGNAL_THRESHOLD = 0.1   # threshold passed to SubScores.active_signals()

# Cooldown: nanoseconds the arbiter waits in COOLDOWN before re-arming.
# 30 seconds is long enough to capture all files encrypted in a typical
# ransomware burst while short enough to re-arm if the attack resumes.
_COOLDOWN_NS = 30_000_000_000    # 30 seconds in nanoseconds

# Accumulator decay factor applied each tick when the fused score is below
# the soft threshold.  A value of 0.85 means the accumulator loses ~15% of
# its value per quiet tick, so it falls from 0.70 to below 0.35 in roughly
# 6 quiet ticks.  The rise rate is (1 - decay) * fused_score added per tick.
# Choosing decay close to 1.0 makes the system slow to react (less sensitive
# to short bursts); closer to 0.0 makes it react to single events.
_ACCUMULATOR_DECAY = 0.85

# Hysteresis band: the SUSPECT -> NORMAL disarm requires the accumulator to
# drop this far below SOFT_THRESHOLD before the arbiter resets.  Without
# hysteresis, a score oscillating just above/below SOFT_THRESHOLD causes
# rapid NORMAL/SUSPECT flapping which is noisy and hard to audit.
_HYSTERESIS_GAP = 0.05


# ---------------------------------------------------------------------------
# ArbiterState
# ---------------------------------------------------------------------------

class ArbiterState(Enum):
    """
    The four states of the CTRR arbiter state machine.

    String values are used so log lines read naturally without .value
    extraction: str(ArbiterState.NORMAL) -> 'ArbiterState.NORMAL' but
    state.value -> 'NORMAL'.  The monitor uses state.value for output.
    """
    NORMAL   = "NORMAL"
    SUSPECT  = "SUSPECT"
    TRIGGER  = "TRIGGER"    # transient: returned once, then COOLDOWN
    COOLDOWN = "COOLDOWN"


# ---------------------------------------------------------------------------
# Fusion function (pure, stateless)
# ---------------------------------------------------------------------------

def fuse(scores: SubScores) -> float:
    """
    Compute the instantaneous fused score as a weighted sum of sub-scores.

    This is a pure function with no side effects.  The replay engine calls
    it directly on saved trace data to recompute scores offline.  Keeping
    it separate from the Scorer class ensures the fusion logic is testable
    without instantiating the full arbiter.

    Return value is in [0, 1] because each sub-score is in [0, 1] and the
    weights sum to 1.0.
    """
    return (
        _WEIGHT_ENTROPY   * scores.entropy   +
        _WEIGHT_RATE      * scores.rate      +
        _WEIGHT_EXTENSION * scores.extension +
        _WEIGHT_SPREAD    * scores.spread
    )


# ---------------------------------------------------------------------------
# Scorer (fusion engine + arbiter)
# ---------------------------------------------------------------------------

class Scorer:
    """
    Stateful fusion engine and arbiter.

    The monitor calls tick() on every extractor snapshot.  tick() updates
    the internal fused score and advances the state machine, returning the
    new ArbiterState.

    Thread safety: not thread-safe.  The monitor must call tick() from a
    single thread (the processor thread).
    """

    def __init__(self) -> None:
        self._state         = ArbiterState.NORMAL
        self._fused_score   = 0.0
        self._accumulator   = 0.0   # leaky integrator value; arbiter acts on this
        self._trigger_ts    = 0     # mono_ts of the most recent trigger
        self._trigger_count = 0     # total number of triggers fired

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def tick(self, scores: SubScores, mono_ts: int) -> ArbiterState:
        """
        Advance the state machine by one step and return the new state.

        Parameters
        ----------
        scores   : SubScores snapshot from the extractor pipeline
        mono_ts  : monotonic timestamp (nanoseconds) of the triggering event;
                   used for cooldown bookkeeping only

        Returns
        -------
        ArbiterState
            TRIGGER is returned exactly once -- the tick on which the hard
            threshold and quorum are both first crossed.  The arbiter
            transitions internally to COOLDOWN at the same moment.
        """
        self._fused_score = fuse(scores)

        # --- Leaky integrator update ------------------------------------------
        # Rise: accumulator pulls toward fused_score each tick.
        # Decay: when fused_score is below soft threshold, the accumulator bleeds
        # down toward zero so a quiet period after an attack resets the state.
        if self._fused_score >= _SOFT_THRESHOLD:
            # Drive accumulator up toward 1.0 at rate (1 - decay) per tick.
            self._accumulator = (
                _ACCUMULATOR_DECAY * self._accumulator
                + (1.0 - _ACCUMULATOR_DECAY) * self._fused_score
            )
        else:
            # Quiet tick: accumulator decays toward zero.
            self._accumulator *= _ACCUMULATOR_DECAY
        # Clamp to [0, 1] to guard against floating-point drift.
        self._accumulator = min(1.0, max(0.0, self._accumulator))
        # --- End accumulator update -------------------------------------------

        if self._state == ArbiterState.COOLDOWN:
            # Re-arm once the cooldown window has elapsed.
            if mono_ts - self._trigger_ts >= _COOLDOWN_NS:
                self._state = ArbiterState.NORMAL
            return self._state

        if self._state == ArbiterState.NORMAL:
            if self._accumulator >= _SOFT_THRESHOLD:
                self._state = ArbiterState.SUSPECT
            return self._state

        if self._state == ArbiterState.SUSPECT:
            # Hysteresis: only disarm if the accumulator has dropped well
            # below the soft threshold, not just marginally below it.
            # This prevents oscillation when the score hovers at the boundary.
            if self._accumulator < (_SOFT_THRESHOLD - _HYSTERESIS_GAP):
                self._state = ArbiterState.NORMAL
                return self._state

            if (self._accumulator >= _HARD_THRESHOLD and
                    scores.active_signals(_QUORUM_SIGNAL_THRESHOLD) >= _QUORUM_MIN):
                # Hard threshold crossed with quorum -- fire a snapshot.
                self._trigger_ts    = mono_ts
                self._trigger_count += 1
                self._state         = ArbiterState.COOLDOWN
                # Return TRIGGER this one tick so the monitor can act on it.
                return ArbiterState.TRIGGER

            return self._state

        # Defensive fallback: should not be reached in normal operation.
        return self._state

    @property
    def state(self) -> ArbiterState:
        """Current arbiter state."""
        return self._state

    @property
    def fused_score(self) -> float:
        """Fused score from the most recent tick, in [0, 1]."""
        return self._fused_score

    @property
    def accumulator(self) -> float:
        """Leaky integrator value from the most recent tick, in [0, 1].

        This is the value the arbiter uses for threshold comparisons, not
        the raw fused_score.  Expose it so the telemetry layer can log both.
        """
        return self._accumulator

    @property
    def trigger_count(self) -> int:
        """Total number of TRIGGER events fired since instantiation."""
        return self._trigger_count
