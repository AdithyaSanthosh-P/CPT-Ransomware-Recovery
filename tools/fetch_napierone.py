"""
tools/fetch_napierone.py
========================
Download the NapierOne subsets CTRR uses into experiments/data/napierone/.

NapierOne (Davies et al., 2022) is a public dataset of real files of common
types, plus copies of some of them after encryption by real ransomware
families.  It is hosted as AWS open data in the S3 bucket `napierone.com`
(region eu-north-1).  Each subset is published as a zip in three sizes
(tiny / small / total); this script uses the "tiny" zips, 100 files each.

How the download works
----------------------
A zip keeps its index (the "central directory") at the end of the file.  The
script reads that index with HTTP Range requests, then fetches only the
members it needs, so a subset can be limited to its first N files without
downloading the whole archive.  zipfile checks each member's CRC-32 as it is
read, so a corrupted transfer raises an error instead of producing a bad file.
No AWS account or AWS CLI is needed.

Layout produced
---------------
  experiments/data/napierone/<SUBSET>/<member file name>
  experiments/data/napierone/MANIFEST.jsonl   one line per file: subset, zip key, name, size, sha256
  experiments/data/napierone/FETCH_LOG.json   the command line, time and selection of every run

File names keep NapierOne's sequence number prefix (0001-...).  An original,
its archived versions and its encrypted copies share that number, which is
what the Model A train/test split groups on.

experiments/data/ is gitignored; nothing downloaded is committed.

Usage
-----
  python tools/fetch_napierone.py --dry-run          # sizes only, no download
  python tools/fetch_napierone.py                    # download the default selection
  python tools/fetch_napierone.py --only RYUK DOCX   # just these subsets
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import io
import json
import re
import shutil
import sys
import time
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

HOST = "s3.eu-north-1.amazonaws.com"
# Path-style addressing: the bucket name contains a dot, so the virtual-host
# form (napierone.com.s3.amazonaws.com) fails TLS hostname verification.
BUCKET_PREFIX = "/napierone.com/"

REPO = Path(__file__).resolve().parent.parent
DEFAULT_DEST = REPO / "experiments" / "data" / "napierone"

# Members are named <4-digit sequence>-<type>...; each zip also contains one
# or two documentation PDFs without that prefix, which are skipped.
_MEMBER_RE = re.compile(r"^\d{4}-")

# Attempts per byte range before giving up (backoff 1, 2, 4, 8 s).
_RETRIES = 5


@dataclass(frozen=True)
class Subset:
    name: str            # directory name under the destination
    key: str             # S3 object key of the tiny zip
    role: str            # what CTRR uses it for
    max_files: int | None = None   # None = all files in the tiny zip


def _family(name: str) -> Subset:
    return Subset(name, f"NapierOne/Data/EXTRA/{name}-tiny.zip", "encrypted (positive)")


def _original(name: str, key_name: str, max_files: int | None = None) -> Subset:
    return Subset(name, f"NapierOne/Data/{name}/{key_name}-tiny.zip",
                  "original (negative, pairs with encrypted)", max_files)


def _archive(name: str, key_name: str, max_files: int) -> Subset:
    return Subset(name if name == key_name else key_name,
                  f"NapierOne/Data/{name}/{key_name}-tiny.zip",
                  "archive (high-entropy negative)", max_files)


# Selection from docs/research/dataset-selection.md and docs/course-plan.md:
# the seven ransomware families named there, the original types those families
# encrypted (doc, docx, jpg, pdf, pptx, xls, xlsx), and three archive formats
# as hard negatives.  PPTX and the archives are capped because their tiny
# zips are 300-600 MB each and this machine is short of disk; the encrypted
# subsets only use sequence numbers up to about 17, so the cap does not lose
# any original that has an encrypted pair.
DEFAULT_SELECTION: list[Subset] = [
    *(_family(f) for f in ("NOTPETYA", "SODINOKIBI", "MAZE", "PHOBOS",
                           "NETWALKER", "DHARMA", "RYUK")),
    _original("DOC", "DOC"),
    _original("DOCX", "DOCX"),
    _original("JPG", "JPG-from-web"),
    _original("PDF", "PDF"),
    _original("PPTX", "PPTX", max_files=20),
    _original("XLS", "XLS"),
    _original("XLSX", "XLSX"),
    _archive("ZIP", "ZIP-DEFLATE", max_files=20),
    _archive("GZIP", "GZIP", max_files=20),
    _archive("7ZIP", "7ZIP-LZMA", max_files=20),
]


class RemoteFile(io.RawIOBase):
    """
    Read-only, seekable view of an S3 object over one kept-alive HTTPS
    connection, using Range requests.  Lets zipfile.ZipFile read the central
    directory and individual members without fetching the whole object.
    """

    def __init__(self, key: str) -> None:
        self._conn = http.client.HTTPSConnection(HOST, timeout=60)
        self._path = BUCKET_PREFIX + key
        self._pos = 0
        self._conn.request("HEAD", self._path)
        resp = self._conn.getresponse()
        resp.read()
        if resp.status != 200:
            raise OSError(f"HEAD {key}: HTTP {resp.status}")
        self.size = int(resp.getheader("Content-Length"))

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = 0) -> int:
        base = {0: 0, 1: self._pos, 2: self.size}[whence]
        self._pos = base + offset
        return self._pos

    def readinto(self, buf) -> int:
        if self._pos >= self.size:
            return 0
        end = min(self._pos + len(buf), self.size) - 1
        # S3 closes kept-alive connections after a while (observed: after
        # about a hundred files), so a dropped connection is reopened and the
        # same byte range requested again.  Range requests are idempotent, so
        # a retry cannot duplicate or skip data.
        for attempt in range(_RETRIES):
            try:
                self._conn.request("GET", self._path,
                                   headers={"Range": f"bytes={self._pos}-{end}"})
                resp = self._conn.getresponse()
                data = resp.read()
                break
            except (http.client.HTTPException, OSError) as exc:
                if attempt == _RETRIES - 1:
                    raise OSError(f"GET range failed after {_RETRIES} attempts: {exc}") from exc
                self._conn.close()
                time.sleep(2 ** attempt)
                self._conn = http.client.HTTPSConnection(HOST, timeout=60)
        if resp.status != 206:
            raise OSError(f"GET range: HTTP {resp.status}")
        buf[:len(data)] = data
        self._pos += len(data)
        return len(data)

    def close(self) -> None:
        self._conn.close()
        super().close()


def _open_zip(key: str) -> tuple[zipfile.ZipFile, RemoteFile]:
    remote = RemoteFile(key)
    # 1 MiB buffer: one Range request per MiB of member data.
    return zipfile.ZipFile(io.BufferedReader(remote, buffer_size=1 << 20)), remote


def _members(zf: zipfile.ZipFile, max_files: int | None) -> list[zipfile.ZipInfo]:
    infos = sorted((i for i in zf.infolist()
                    if not i.is_dir() and _MEMBER_RE.match(Path(i.filename).name)),
                   key=lambda i: Path(i.filename).name)
    return infos[:max_files] if max_files is not None else infos


def plan(selection: list[Subset]) -> list[tuple[Subset, list[zipfile.ZipInfo]]]:
    """Read each zip's index and return the members that would be fetched."""
    out = []
    for sub in selection:
        zf, remote = _open_zip(sub.key)
        try:
            out.append((sub, _members(zf, sub.max_files)))
        finally:
            remote.close()
    return out


def fetch(sub: Subset, dest: Path, manifest) -> tuple[int, int]:
    """Download one subset; returns (files written, files already present)."""
    target = dest / sub.name
    target.mkdir(parents=True, exist_ok=True)
    zf, remote = _open_zip(sub.key)
    written = skipped = 0
    try:
        for info in _members(zf, sub.max_files):
            out = target / Path(info.filename).name
            if out.exists() and out.stat().st_size == info.file_size:
                skipped += 1
                continue
            h = hashlib.sha256()
            tmp = out.with_name(out.name + ".part")
            with zf.open(info) as src, tmp.open("wb") as dst:   # CRC checked on read
                while chunk := src.read(1 << 20):
                    h.update(chunk)
                    dst.write(chunk)
            tmp.rename(out)
            manifest.write(json.dumps({
                "subset": sub.name, "key": sub.key, "name": out.name,
                "size": info.file_size, "sha256": h.hexdigest(),
            }) + "\n")
            manifest.flush()
            written += 1
    finally:
        remote.close()
    return written, skipped


def _parse_args(argv=None):
    p = argparse.ArgumentParser(description="Download the NapierOne subsets used by CTRR")
    p.add_argument("--dest", default=str(DEFAULT_DEST), help="destination directory")
    p.add_argument("--only", nargs="+", metavar="SUBSET",
                   help="restrict to these subset names (e.g. RYUK DOCX)")
    p.add_argument("--dry-run", action="store_true",
                   help="print file counts and sizes; download nothing")
    p.add_argument("--force", action="store_true",
                   help="download even if free disk space looks insufficient")
    return p.parse_args(argv)


def main(argv=None) -> None:
    args = _parse_args(argv)
    selection = DEFAULT_SELECTION
    if args.only:
        wanted = {s.upper() for s in args.only}
        selection = [s for s in selection if s.name.upper() in wanted]
        missing = wanted - {s.name.upper() for s in selection}
        if missing:
            sys.exit(f"ERROR: unknown subset(s): {', '.join(sorted(missing))}")

    print("Reading zip indexes ...", flush=True)
    planned = plan(selection)
    total = 0
    for sub, infos in planned:
        size = sum(i.file_size for i in infos)
        total += size
        cap = f" (first {sub.max_files})" if sub.max_files else ""
        print(f"  {sub.name:<11} {len(infos):>4} files {size / 1e6:>8.1f} MB  {sub.role}{cap}")
    print(f"  {'TOTAL':<11} {sum(len(i) for _, i in planned):>4} files {total / 1e6:>8.1f} MB")

    dest = Path(args.dest)
    dest.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(dest).free
    print(f"Free space at {dest}: {free / 1e9:.2f} GB")
    if args.dry_run:
        return
    # Keep 1 GB spare: a nearly full root filesystem breaks far more than this.
    if free - total < 1_000_000_000 and not args.force:
        sys.exit("ERROR: less than 1 GB would remain free; use --only to fetch less, or --force")

    with (dest / "MANIFEST.jsonl").open("a") as manifest:
        for sub, _ in planned:
            w, s = fetch(sub, dest, manifest)
            print(f"  {sub.name:<11} written={w} already-present={s}", flush=True)

    log_path = dest / "FETCH_LOG.json"
    log = json.loads(log_path.read_text()) if log_path.exists() else []
    log.append({
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "argv": sys.argv,
        "endpoint": f"https://{HOST}{BUCKET_PREFIX}",
        "selection": [{"name": s.name, "key": s.key, "max_files": s.max_files} for s in selection],
    })
    log_path.write_text(json.dumps(log, indent=2) + "\n")
    print(f"Done. Manifest: {dest / 'MANIFEST.jsonl'}")


if __name__ == "__main__":
    main()
