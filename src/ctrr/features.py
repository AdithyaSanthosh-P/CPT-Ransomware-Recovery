"""
src/ctrr/features.py
====================
Content features for Model A ("is this file's content encrypted?").

The input is exactly the byte sample the entropy extractor already reads
(extractor._read_sample): up to 4 KiB from the head followed by up to 4 KiB
from the middle.  No per-file baseline is needed, so Model A can also score a
file it has never seen before.

The same function is used by training (experiments/model_a.py) and by the
monitor's trace writer, so a trace carries the exact feature vector the model
would have been given live and a policy that uses Model A can be replayed
offline.

Features (order fixed by FEATURE_NAMES; changing it invalidates saved traces
and models):
  entropy        Shannon entropy of the whole sample, bits per byte
  head_entropy   entropy of the first 4 KiB alone
  mid_entropy    entropy of the middle window alone (0 if the file is small)
  chi2           chi-square statistic against a uniform byte histogram,
                 divided by the sample length.  Uniform random bytes give
                 about 255/n; structured data gives a large value.
  zero_frac      fraction of 0x00 bytes (padding is common in documents)
  printable_frac fraction of printable ASCII, tab, CR, LF
  max_frac       frequency of the most common byte value
  distinct_frac  fraction of the 256 byte values that appear at all
  magic          1.0 if the sample starts with a recognised file signature
                 (ZIP/OOXML, PDF, JPEG, OLE2 doc/xls, gzip, 7z, PNG, GIF)
"""

from __future__ import annotations

import numpy as np

from ctrr.extractor import SAMPLE_HEAD_BYTES

FEATURE_NAMES = (
    "entropy", "head_entropy", "mid_entropy", "chi2",
    "zero_frac", "printable_frac", "max_frac", "distinct_frac", "magic",
)

_MAGIC = (
    b"PK\x03\x04",                          # zip, docx, xlsx, pptx
    b"%PDF",
    b"\xff\xd8\xff",                        # jpeg
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",    # OLE2: doc, xls
    b"\x1f\x8b",                            # gzip
    b"7z\xbc\xaf\x27\x1c",
    b"\x89PNG",
    b"GIF8",
)


def _entropy(counts: np.ndarray) -> float:
    n = counts.sum()
    if n == 0:
        return 0.0
    p = counts[counts > 0] / n
    return float(-np.sum(p * np.log2(p)))


def sample_features(sample: bytes) -> list[float]:
    """Feature vector (len == len(FEATURE_NAMES)) for one byte sample."""
    if not sample:
        return [0.0] * len(FEATURE_NAMES)
    arr = np.frombuffer(sample, dtype=np.uint8)
    n = arr.size
    counts = np.bincount(arr, minlength=256)
    head, mid = arr[:SAMPLE_HEAD_BYTES], arr[SAMPLE_HEAD_BYTES:]
    expected = n / 256.0
    chi2 = float(((counts - expected) ** 2 / expected).sum()) / n
    printable = counts[32:127].sum() + counts[9] + counts[10] + counts[13]
    return [
        _entropy(counts),
        _entropy(np.bincount(head, minlength=256)),
        _entropy(np.bincount(mid, minlength=256)) if mid.size else 0.0,
        chi2,
        counts[0] / n,
        float(printable) / n,
        float(counts.max()) / n,
        float((counts > 0).sum()) / 256.0,
        1.0 if sample.startswith(_MAGIC) else 0.0,
    ]
