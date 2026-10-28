#!/usr/bin/env bash
# =============================================================================
# CTRR — Module 1: Environment & Infrastructure (~30% complete)
# =============================================================================
# WHAT THIS DEMO MEANS: proves there's a real, tested, version-controlled
# codebase behind the other 9 modules, not a pile of scripts.
#
# WHAT THE OUTPUT MEANS:
#   pytest summary -> "65/65 passed" is the whole point of this module: a
#                      green test suite backing every other module's claims
#   pyproject.toml  -> dependency + tooling config (proves it's a real
#                       packaged project, not loose files)
#   git log         -> commit history — incremental build discipline over
#                       the semester, not one dump at the end
#
# KNOWN GAP (say this out loud if asked): no Btrfs VM, no systemd unit
# files, no policy.yaml yet — this demo runs entirely in userspace against
# a shutil.copytree mock snapshot backend. Explicitly deferred, documented
# in docs/modules.md.
# =============================================================================
set -uo pipefail
# Repo root, found from this script's own location so a fresh clone works anywhere.
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT" || { echo "Set PROJECT_ROOT at the top of this script."; exit 1; }

echo "### Test suite ###"
python -m pytest -q

echo
echo "### Dependency / tooling config ###"
cat pyproject.toml

echo
echo "### Commit history (last 10) ###"
git log --oneline -10
