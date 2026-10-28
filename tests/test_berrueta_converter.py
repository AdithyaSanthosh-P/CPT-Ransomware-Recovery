"""SMB2 I/O log -> CTRR events (experiments/berrueta_model_b.py)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "experiments"))

from berrueta_model_b import events_from_ioops  # noqa: E402
from ctrr.extractor import OP_CLOSE_WRITE, OP_MOVED_FROM, OP_MOVED_TO  # noqa: E402

HEADER = ("Timestamp IP_src IP_dst TCPport_src TCPport_dst SMBcommand SMBsubcommand MessageId "
          "ReqResp status TreeID SessionID FileID (OpenPermissions) (FileSize) (filename) "
          "(dataOffset) (dataLength) (newFileName)\n")
FID = "A9100300003D0200FFFFFFFF"
CREATE_REQ = r"1.0 10.0.2.4 10.0.2.5 49157 445 5 - 7 0 0 5 99 -  0 15 \\PCB\Users\Public\Documents\d1\a.txt 0 0 -"
CREATE_RESP = f"1.1 10.0.2.5 10.0.2.4 445 49157 5 - 7 1 0 5 99 {FID} 0 56 - 0 0 -"
WRITE_REQ = f"2.0 10.0.2.4 10.0.2.5 49157 445 9 - 8 0 0 5 99 {FID} - - - 0 4096 -"
RENAME_REQ = rf"3.0 10.0.2.4 10.0.2.5 49157 445 17 10 9 0 0 5 99 {FID} - - - 0 0 \Public\Documents\d1\a.txt.enc"
CLOSE_REQ = f"4.0 10.0.2.4 10.0.2.5 49157 445 6 - 10 0 0 5 99 {FID} - - - 0 0 -"


def _events(tmp_path, *lines):
    p = tmp_path / "IOops.txt"
    p.write_text(HEADER + "\n".join(lines) + "\n")
    return list(events_from_ioops(p))


def test_write_then_close_is_close_write(tmp_path):
    ev = _events(tmp_path, CREATE_REQ, CREATE_RESP, WRITE_REQ, CLOSE_REQ)
    assert [(e.op, e.path) for e in ev] == [(OP_CLOSE_WRITE, "/share/d1/a.txt")]
    assert ev[0].mono_ts == 4_000_000_000


def test_close_without_write_is_ignored(tmp_path):
    assert _events(tmp_path, CREATE_REQ, CREATE_RESP, CLOSE_REQ) == []


def test_rename_emits_moved_pair_with_source(tmp_path):
    ev = _events(tmp_path, CREATE_REQ, CREATE_RESP, RENAME_REQ)
    assert [e.op for e in ev] == [OP_MOVED_FROM, OP_MOVED_TO]
    assert ev[1].path == "/share/d1/a.txt.enc" and ev[1].src_path == "/share/d1/a.txt"
