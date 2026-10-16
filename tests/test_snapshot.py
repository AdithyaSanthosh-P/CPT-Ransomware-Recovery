"""
tests/test_snapshot.py
======================
Unit tests for src/ctrr/snapshot.py and the deploy/ctrr-snapshot helper.

BtrfsBackend is tested with subprocess.run replaced by a fake, so these tests
need neither root nor a Btrfs filesystem.  They pin the exact commands the
backend runs (the sudoers rule depends on them) and every failure path that
must stop a non-read-only or misplaced snapshot from being reported as good.
The real filesystem path is exercised by the live demo on the loopback image.

The helper script is run directly, unprivileged, to check its argument
handling; the privileged snapshot path itself is not run here.
"""

import os
import re
import subprocess
from pathlib import Path

import pytest

import ctrr.snapshot as snapshot
from ctrr.snapshot import BtrfsBackend, SnapshotBackend, SnapshotError, make_backend

REPO = Path(__file__).resolve().parent.parent
NAME_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ_[a-z]+$")


# ---------------------------------------------------------------------------
# copytree mock
# ---------------------------------------------------------------------------

class TestCopyBackend:
    def test_take_copies_tree_and_names_snapshot(self, tmp_path):
        watched = tmp_path / "w"; watched.mkdir(); (watched / "a.txt").write_text("x")
        sb = SnapshotBackend(str(tmp_path / "s"), str(watched))
        snap = Path(sb.take(reason="trigger"))
        assert NAME_RE.match(snap.name)
        assert (snap / "a.txt").read_text() == "x"
        assert sb.list_snapshots() == [str(snap)]

    def test_description_says_not_read_only(self):
        assert "NOT read-only" in SnapshotBackend.description


# ---------------------------------------------------------------------------
# BtrfsBackend with a fake subprocess.run
# ---------------------------------------------------------------------------

class FakeRun:
    """Stand-in for subprocess.run that answers by argv and records calls."""

    def __init__(self, snap_dir, watched, ro="ro=true", sudo_ok=True,
                 helper_rc=0, helper_out=None, cfg_src=None):
        self.calls = []
        self.snap_dir, self.watched = snap_dir, watched
        self.ro, self.sudo_ok, self.helper_rc = ro, sudo_ok, helper_rc
        self.helper_out = helper_out
        self.cfg_src = cfg_src if cfg_src is not None else watched

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        out, rc = "", 0
        if argv[-1] == "--print-config":
            out = f"SRC={self.cfg_src}\nDST_DIR={self.snap_dir}\n"
        elif argv[:3] == ["sudo", "-n", "-l"]:
            rc = 0 if self.sudo_ok else 1
        elif argv[:2] == ["sudo", "-n"]:
            rc = self.helper_rc
            out = self.helper_out if self.helper_out is not None else \
                f"{self.snap_dir}/2026-10-16T12:00:00Z_{argv[-1]}\n"
        elif argv[1:3] == ["property", "get"]:
            out = self.ro + "\n"
        return subprocess.CompletedProcess(argv, rc, out, "helper said no" if rc else "")


@pytest.fixture
def env(tmp_path, monkeypatch):
    """A watched dir that passes the subvolume check, a snapshot dir and an executable helper."""
    watched = tmp_path / "data"; watched.mkdir()
    snaps = tmp_path / "snaps"; snaps.mkdir()
    helper = tmp_path / "ctrr-snapshot"; helper.write_text("#!/bin/sh\n"); helper.chmod(0o755)
    monkeypatch.setattr(snapshot, "_is_subvolume_root", lambda p: Path(p) == watched)
    monkeypatch.setattr(snapshot.shutil, "which", lambda name: "/usr/bin/btrfs")
    return watched, snaps, helper


def make(env, monkeypatch, **fake_kwargs):
    watched, snaps, helper = env
    fake = FakeRun(snaps, watched, **fake_kwargs)
    monkeypatch.setattr(snapshot.subprocess, "run", fake)
    return fake, (lambda: BtrfsBackend(str(snaps), str(watched), helper=str(helper)))


class TestBtrfsBackendStartup:
    def test_ok(self, env, monkeypatch):
        fake, build = make(env, monkeypatch)
        build()
        helper = str(env[2])
        assert [helper, "--print-config"] in fake.calls
        assert ["sudo", "-n", "-l", helper, "trigger"] in fake.calls

    def test_rejects_dir_that_is_not_a_subvolume_root(self, env, monkeypatch, tmp_path):
        _, build = make(env, monkeypatch)
        monkeypatch.setattr(snapshot, "_is_subvolume_root", lambda p: False)
        with pytest.raises(SnapshotError, match="not a Btrfs subvolume root"):
            build()

    def test_rejects_helper_paths_that_differ_from_arguments(self, env, monkeypatch):
        _, build = make(env, monkeypatch, cfg_src="/somewhere/else")
        with pytest.raises(SnapshotError, match="do not match"):
            build()

    def test_rejects_missing_sudo_rule(self, env, monkeypatch):
        _, build = make(env, monkeypatch, sudo_ok=False)
        with pytest.raises(SnapshotError, match="without a password"):
            build()

    def test_rejects_missing_helper(self, env, monkeypatch):
        _, _ = make(env, monkeypatch)
        watched, snaps, _ = env
        with pytest.raises(SnapshotError, match="not installed"):
            BtrfsBackend(str(snaps), str(watched), helper=str(watched / "nope"))

    def test_rejects_missing_btrfs_progs(self, env, monkeypatch):
        _, build = make(env, monkeypatch)
        monkeypatch.setattr(snapshot.shutil, "which", lambda name: None)
        with pytest.raises(SnapshotError, match="btrfs-progs"):
            build()


class TestBtrfsBackendTake:
    def test_runs_exact_sudo_command_and_verifies_read_only(self, env, monkeypatch):
        fake, build = make(env, monkeypatch)
        b = build()
        fake.calls.clear()
        path = b.take(reason="trigger")
        helper = str(env[2])
        # This exact argv is what /etc/sudoers.d/ctrr allows; anything else is refused.
        assert fake.calls[0] == ["sudo", "-n", helper, "trigger"]
        assert fake.calls[1] == ["/usr/bin/btrfs", "property", "get", "-ts", path, "ro"]
        assert Path(path).parent == env[1]

    def test_not_read_only_is_a_failure(self, env, monkeypatch):
        _, build = make(env, monkeypatch, ro="ro=false")
        with pytest.raises(SnapshotError, match="not read-only"):
            build().take()

    def test_path_outside_snapshot_dir_is_a_failure(self, env, monkeypatch):
        _, build = make(env, monkeypatch, helper_out="/tmp/elsewhere/2026-10-16T12:00:00Z_trigger\n")
        with pytest.raises(SnapshotError, match="unexpected path"):
            build().take()

    def test_helper_error_is_a_failure(self, env, monkeypatch):
        _, build = make(env, monkeypatch, helper_rc=1)
        with pytest.raises(SnapshotError, match="helper said no"):
            build().take()

    def test_description_says_read_only(self):
        assert BtrfsBackend.description == "btrfs read-only snapshot"


def test_make_backend_rejects_unknown_kind(tmp_path):
    with pytest.raises(ValueError):
        make_backend("zfs", str(tmp_path), str(tmp_path))


# ---------------------------------------------------------------------------
# deploy/ctrr-snapshot argument handling (run unprivileged)
# ---------------------------------------------------------------------------

@pytest.fixture
def helper_script(tmp_path):
    text = (REPO / "deploy" / "ctrr-snapshot").read_text()
    text = text.replace("@SRC@", "/mnt/ctrr/data").replace("@DST_DIR@", "/mnt/ctrr/.snapshots")
    path = tmp_path / "ctrr-snapshot"
    path.write_text(text)
    path.chmod(0o755)
    return str(path)


@pytest.mark.skipif(os.geteuid() == 0, reason="checks the non-root refusal path")
class TestHelperScript:
    def run(self, *args):
        return subprocess.run([*args], capture_output=True, text=True)

    def test_print_config_needs_no_privilege(self, helper_script):
        r = self.run(helper_script, "--print-config")
        assert r.returncode == 0
        assert r.stdout.split() == ["SRC=/mnt/ctrr/data", "DST_DIR=/mnt/ctrr/.snapshots"]

    @pytest.mark.parametrize("args", [[], ["delete"], ["../x"], ["trigger", "extra"]])
    def test_rejects_bad_arguments(self, helper_script, args):
        assert self.run(helper_script, *args).returncode == 2

    def test_refuses_to_snapshot_without_root(self, helper_script):
        r = self.run(helper_script, "trigger")
        assert r.returncode == 1 and "must run as root" in r.stderr


def test_setup_script_parses():
    assert subprocess.run(["bash", "-n", str(REPO / "deploy" / "setup_btrfs.sh")]).returncode == 0
