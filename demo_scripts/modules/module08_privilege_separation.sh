#!/usr/bin/env bash
# =============================================================================
# CTRR — Module 8: Privilege Separation (~5% complete)
# =============================================================================
# NO LIVE DEMO — NOT IMPLEMENTED. ctrr-snapd (the Unix-socket root helper)
# and the systemd hardening units don't exist yet. This script just prints
# the design so it can be talked through instead of shown.
#
# WHAT TO SAY IF ASKED: monitor runs unprivileged; a separate root-owned
# daemon listens on a Unix socket authenticated via SO_PEERCRED; only that
# daemon can invoke `btrfs subvolume snapshot -r`. Point to the
# "Privilege Separation" row in docs/projectContext.md Section 2 for the
# full rationale. This is the biggest remaining gap in the project — say
# so directly; professors respect an honest completion percentage more
# than a dodge.
# =============================================================================
set -uo pipefail

cat <<'EOF'
Module 8 — Privilege Separation: DESIGN ONLY, ~5% implemented.

Planned architecture:
  - ctrr-monitor runs UNPRIVILEGED (the watcher/extractor/fusion/arbiter
    pipeline never needs root).
  - ctrr-snapd runs as ROOT, socket-activated, listening on a Unix domain
    socket owned root:ctrr, mode 0660.
  - ctrr-snapd authenticates the caller with SO_PEERCRED (uid must equal
    the ctrr service user) before accepting a snapshot request.
  - ctrr-snapd takes NO paths from the request — source/destination
    subvolumes are hard-coded server-side, so a compromised monitor
    process cannot direct it to snapshot or read anything arbitrary.
  - Only ctrr-snapd is permitted to invoke `btrfs subvolume snapshot -r`.

Full rationale: docs/projectContext.md, Section 2, "Privilege Separation" row.
Status: NOT implemented for this demo. Named directly as the largest
remaining gap in the project.
EOF
