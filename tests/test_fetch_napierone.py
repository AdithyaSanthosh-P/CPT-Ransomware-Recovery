"""
tests/test_fetch_napierone.py
=============================
Offline test of the member selection in tools/fetch_napierone.py: which files
inside a NapierOne zip are fetched, and in what order.  No network access.
"""

import importlib.util
import io
import sys
import zipfile
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "fetch_napierone", Path(__file__).resolve().parent.parent / "tools" / "fetch_napierone.py")
fetch = importlib.util.module_from_spec(_spec)
# dataclass() looks its defining module up in sys.modules, so register it first.
sys.modules[_spec.name] = fetch
_spec.loader.exec_module(fetch)


def _zip(names):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for n in names:
            zf.writestr(n, b"x")
    return zipfile.ZipFile(buf)


def test_skips_documentation_pdfs_and_sorts_by_sequence():
    zf = _zip(["0002-docx.docx.RYK", "RYUK.pdf", "0001-doc.doc.RYK", "sub/0003-pdf.pdf.RYK"])
    names = [Path(i.filename).name for i in fetch._members(zf, None)]
    assert names == ["0001-doc.doc.RYK", "0002-docx.docx.RYK", "0003-pdf.pdf.RYK"]


def test_cap_keeps_lowest_sequence_numbers():
    zf = _zip([f"{n:04d}-pptx.pptx" for n in (5, 1, 3, 2, 4)])
    names = [Path(i.filename).name for i in fetch._members(zf, 3)]
    assert names == ["0001-pptx.pptx", "0002-pptx.pptx", "0003-pptx.pptx"]


def test_default_selection_names_are_unique():
    names = [s.name for s in fetch.DEFAULT_SELECTION]
    assert len(names) == len(set(names))
