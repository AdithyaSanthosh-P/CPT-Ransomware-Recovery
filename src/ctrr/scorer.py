"""
src/ctrr/scorer.py
==================
Fusion engine and arbiter for CTRR.

Receives SubScores from the extractor pipeline on each tick and maintains
a state machine that transitions NORMAL -> SUSPECT -> TRIGGER.

Architecture
------------
Two stages run in sequence on every tick:

  [FUSION]   Weighted sum of three sub-scores -> fused_score in [0, 1].
             Weights are module-level policy constants that sum to 1.0, so
             the output is guaranteed in [0, 1] without additional clamping.
             The fuse() function is intentionally a pure function so the
             replay engine can call it on saved trace data without needing
             a live Scorer instance.

  [ARBITER]  Threshold comparisons + quorum gate -> ArbiterState.
             NORMAL  : fused_score < SOFT_THRESHOLD
             SUSPECT : fused_score >= SOFT_THRESHOLD
             TRIGGER : fused_score >= HARD_THRESHOLD
                       AND active_signals >= QUORUM_MIN
             COOLDOWN: fixed period after a TRIGGER before re-arming

  TRIGGER is returned exactly once -- the tick on which the hard threshold
  and quorum are both crossed.  The arbiter then moves to COOLDOWN
  immediately.  The monitor acts on the returned TRIGGER state to fire the
  snapshot.

Demo scope vs full system
-------------------------
The following are deferred to the full production system (post-demo):

  - Leaky integrator / evidence accumulator with decay lambda.  In the full
    system the fused score feeds an accumulator; the arbiter acts on the
    accumulated value, not the raw instantaneous score.  This makes the
    system robust against brief spikes and provides a natural decay back to
    NORMAL after the attack stops.

  - Hysteresis on the SUSPECT -> NORMAL transition.  Without it a score
    oscillating around the soft threshold causes rapid state flapping.
    For the demo a simple re-crossing of SOFT_THRESHOLD is sufficient.

  - COOLDOWN -> ARMED distinction.  Production needs an explicit ARMED
    state before re-entering NORMAL so that a sustained attack cannot
    prevent re-arming.  For the demo the arbiter returns directly to NORMAL
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
_WEIGHT_ENTROPY   = 0.45
_WEIGHT_RATE      = 0.35
_WEIGHT_EXTENSION = 0.20

assert abs(_WEIGHT_ENTROPY + _WEIGHT_RATE + _WEIGHT_EXTENSION - 1.0) < 1e-9, \
    "fusion weights must sum to 1.0"

# Soft threshold: fused_score at or above this value moves the arbiter from
# NORMAL to SUSPECT and arms verbose logging.
_SOFT_THRESHOLD = 0.35

# Hard threshold: fused_score at or above this value, combined with quorum,
# fires a snapshot.
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
        _WEIGHT_EXTENSION * scores.extension
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
        self._trigger_ts    = 0       # mono_ts of the most recent trigger
        self._trigger_count = 0       # total number of triggers fired

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

        if self._state == ArbiterState.COOLDOWN:
            # Re-arm once the cooldown window has elapsed.
            if mono_ts - self._trigger_ts >= _COOLDOWN_NS:
                self._state = ArbiterState.NORMAL
            return self._state

        if self._state == ArbiterState.NORMAL:
            if self._fused_score >= _SOFT_THRESHOLD:
                self._state = ArbiterState.SUSPECT
            return self._state

        if self._state == ArbiterState.SUSPECT:
            if self._fused_score < _SOFT_THRESHOLD:
                # Score fell back below the soft threshold -- disarm.
                # Production will add hysteresis here so a brief dip does
                # not immediately disarm a sustained attack reading.
                self._state = ArbiterState.NORMAL
                return self._state

            if (self._fused_score >= _HARD_THRESHOLD and
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
    def trigger_count(self) -> int:
        """Total number of TRIGGER events fired since instantiation."""
        return self._trigger_count
