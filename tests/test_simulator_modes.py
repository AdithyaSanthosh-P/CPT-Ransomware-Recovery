"""
tests/test_simulator_modes.py
=============================
Attack-simulator modes and corpus builder (course-plan Day 3).  These pin the
mode semantics the evaluation matrix relies on, using small synthetic files so
no NapierOne download is needed.
"""

import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
import build_corpus  # noqa: E402
import simulate_attack as sim  # noqa: E402


@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch):
    monkeypatch.setattr(sim.time, "sleep", lambda s: None)


def _file(tmp_path, name="0001-doc.doc", size=64 * 1024):
    p = tmp_path / name
    p.write_bytes(b"A" * size)
    return p


class TestEncryptModes:
    def test_full_overwrites_everything(self, tmp_path):
        p = _file(tmp_path)
        new, real = sim._encrypt_file(p, "full", "fixed")
        data = new.read_bytes()
        assert len(data) == 64 * 1024 and b"A" * 64 not in data and not real

    def test_head_leaves_tail_plaintext(self, tmp_path):
        new, _ = sim._encrypt_file(_file(tmp_path), "head", "none")
        data = new.read_bytes()
        assert data[sim._PARTIAL_CHUNK:] == b"A" * (64 * 1024 - sim._PARTIAL_CHUNK)
        assert data[:sim._PARTIAL_CHUNK] != b"A" * sim._PARTIAL_CHUNK

    def test_preserve_keeps_leading_bytes_and_length(self, tmp_path):
        new, _ = sim._encrypt_file(_file(tmp_path), "full", "none", preserve=16)
        data = new.read_bytes()
        assert len(data) == 64 * 1024
        assert data[:16] == b"A" * 16 and data[16:32] != b"A" * 16

    def test_preserve_longer_than_file_leaves_it_unencrypted(self, tmp_path):
        p = _file(tmp_path, size=1000)
        new, _ = sim._encrypt_file(p, "full", "none", preserve=4096)
        assert new.read_bytes() == b"A" * 1000

    def test_preserve_rejected_with_partial_modes(self):
        with pytest.raises(SystemExit):
            sim._parse_args(["--target", "/x", "--encrypt", "head", "--preserve", "16"])

    def test_alternate_encrypts_even_chunks_only(self, tmp_path):
        new, _ = sim._encrypt_file(_file(tmp_path), "alternate", "none")
        data, c = new.read_bytes(), sim._PARTIAL_CHUNK
        assert data[c:2 * c] == b"A" * c and data[3 * c:4 * c] == b"A" * c
        assert data[:c] != b"A" * c and data[2 * c:3 * c] != b"A" * c


class TestRenameModes:
    def test_fixed(self, tmp_path):
        new, _ = sim._encrypt_file(_file(tmp_path), rename="fixed")
        assert new.name == "0001-doc.doc.enc" and new.exists()

    def test_none_keeps_name(self, tmp_path):
        p = _file(tmp_path)
        new, _ = sim._encrypt_file(p, rename="none")
        assert new == p and p.exists()

    def test_random_differs_per_file_and_is_seeded(self, tmp_path):
        rng = random.Random(5)
        a, _ = sim._encrypt_file(_file(tmp_path, "a.doc"), rename="random", rng=rng)
        b, _ = sim._encrypt_file(_file(tmp_path, "b.doc"), rename="random", rng=rng)
        assert a.suffix != b.suffix
        again = sim._new_name(tmp_path / "x.doc", "random", random.Random(5))
        assert again.suffix == a.suffix


class TestRealCiphertext:
    def test_key_matches_original_and_encrypted_names(self):
        assert sim._napierone_key("0007-docx.docx") == ("0007", "docx")
        assert sim._napierone_key("0007-docx.docx.RYK") == ("0007", "docx")
        assert sim._napierone_key("0011-jpg-fromweb.jpg.id-X.[a@b.c].iq20") == ("0011", "jpg")
        assert sim._napierone_key("0011-jpg.jpg") == ("0011", "jpg")
        assert sim._napierone_key("doc_1.txt") is None

    def test_uses_real_bytes_when_matched_and_falls_back_otherwise(self, tmp_path):
        cdir = tmp_path / "RYUK"
        cdir.mkdir()
        (cdir / "0001-doc.doc.RYK").write_bytes(b"REAL-CIPHERTEXT" * 10)
        idx = sim._index_cipher_dir(cdir)
        matched, real1 = sim._encrypt_file(_file(tmp_path, "0001-doc.doc"),
                                           content="napierone", cipher_index=idx)
        other, real2 = sim._encrypt_file(_file(tmp_path, "0002-doc.doc"),
                                         content="napierone", cipher_index=idx)
        assert real1 and matched.read_bytes() == b"REAL-CIPHERTEXT" * 10
        assert not real2 and other.read_bytes() != b"A" * (64 * 1024)


class TestCorpusBuilder:
    def test_synthetic_nested_spreads_over_directories(self, tmp_path):
        t = tmp_path / "work" / "corpus"
        files = build_corpus.build(t, "synthetic", 12, "nested", 1)
        assert len(files) == 12 and (t / ".ctrr-test-corpus").exists()
        assert len({f.parent for f in files}) == 6

    def test_refuses_non_empty_directory_without_sentinel(self, tmp_path):
        t = tmp_path / "work" / "precious"
        t.mkdir(parents=True)
        (t / "keep.txt").write_text("x")
        with pytest.raises(SystemExit):
            build_corpus.build(t, "synthetic", 3, "flat", 1)
        assert (t / "keep.txt").exists()

    def test_rebuild_empties_previous_corpus(self, tmp_path):
        t = tmp_path / "work" / "corpus"
        build_corpus.build(t, "synthetic", 5, "flat", 1)
        (t / "leftover.enc").write_text("x")
        build_corpus.build(t, "synthetic", 5, "flat", 1)
        assert not (t / "leftover.enc").exists()
