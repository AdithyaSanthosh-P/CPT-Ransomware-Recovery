"""tests/test_features.py -- Model A feature vector (src/ctrr/features.py)."""

import os

import pytest

from ctrr.features import FEATURE_NAMES, sample_features

F = {n: i for i, n in enumerate(FEATURE_NAMES)}


def test_length_and_empty_sample():
    assert len(sample_features(b"x" * 100)) == len(FEATURE_NAMES)
    assert sample_features(b"") == [0.0] * len(FEATURE_NAMES)


def test_random_bytes_look_uniform():
    v = sample_features(os.urandom(8192))
    assert v[F["entropy"]] > 7.9
    assert v[F["chi2"]] < 0.1
    assert v[F["distinct_frac"]] > 0.99
    assert v[F["magic"]] == 0.0


def test_text_looks_structured():
    v = sample_features(b"The quick brown fox jumps over the lazy dog.\n" * 200)
    assert v[F["entropy"]] < 5.0
    assert v[F["printable_frac"]] == 1.0
    assert v[F["chi2"]] > 1.0


def test_magic_flag_on_signature():
    assert sample_features(b"%PDF-1.7" + os.urandom(100))[F["magic"]] == 1.0
    assert sample_features(b"PK\x03\x04" + os.urandom(100))[F["magic"]] == 1.0
    assert sample_features(os.urandom(100))[F["magic"]] == 0.0


def test_head_and_mid_windows_are_separate():
    # head plaintext, mid random: the combined entropy sits between the two.
    v = sample_features(b"A" * 4096 + os.urandom(4096))
    assert v[F["head_entropy"]] == pytest.approx(0.0)
    assert v[F["mid_entropy"]] > 7.9
    assert 0.5 < v[F["entropy"]] < 7.9


def test_small_file_has_no_mid_window():
    assert sample_features(b"hello world" * 10)[F["mid_entropy"]] == 0.0
