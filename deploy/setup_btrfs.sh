#!/bin/bash
# =============================================================================
# CTRR -- Btrfs loopback setup for the read-only snapshot backend
# =============================================================================
# Run with sudo from the project root:
#
#   sudo bash deploy/setup_btrfs.sh up       # create/mount image, install helper + sudoers
#   sudo bash deploy/setup_btrfs.sh status   # show what is in place
#   sudo bash deploy/setup_btrfs.sh down     # remove helper + sudoers, unmount (image kept)
#   sudo bash deploy/setup_btrfs.sh purge    # down, then delete the image file
#
# `up` is idempotent: after a reboot the loop mount is gone, and running `up`
# again remounts the existing image without reformatting it.
#
# Layout (one Btrfs filesystem in a sparse loopback file):
#   /mnt/ctrr               top level of the filesystem, root-owned
#   /mnt/ctrr/data          subvolume the monitor watches, owned by $SUDO_USER
#   /mnt/ctrr/.snapshots    root-owned directory the helper snapshots into
#
# Why a loopback image: the dev machine's disks are not Btrfs.  A sparse file
# formatted as Btrfs gives a real Btrfs filesystem (real CoW snapshots, real
# read-only flag) without repartitioning.  Timing numbers measured on it are
# loopback-specific and are reported as such.
#
# Security notes:
#   - The filesystem is mounted WITHOUT user_subvol_rm_allowed, so only root
#     can delete a subvolume.  A read-only snapshot also cannot be emptied
#     without first clearing its ro flag, which needs root.
#   - .snapshots is a sibling of data, not inside it: snapshotting into the
#     watched tree would make the monitor see its own snapshot as file
#     activity, and a Btrfs snapshot is not recursive anyway.
#   - Threat model: protects against ransomware running as the monitoring
#     user (or any non-root user).  Root can flip `ro` and delete snapshots.
# =============================================================================
set -euo pipefail

IMG="${CTRR_IMG:-/var/tmp/ctrr-btrfs.img}"
IMG_SIZE="${CTRR_IMG_SIZE:-2G}"
MNT=/mnt/ctrr
SRC="$MNT/data"
DST_DIR="$MNT/.snapshots"
# 0755: root-owned, so the monitoring user can read snapshots (needed by the
# unprivileged restore CLI and by `btrfs property get`) but cannot create,
# rename or remove entries in it.
SNAP_MODE="${CTRR_SNAP_MODE:-0755}"
HELPER_DST=/usr/local/sbin/ctrr-snapshot
SUDOERS_DST=/etc/sudoers.d/ctrr

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() { echo "setup_btrfs: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run with sudo"
CTRR_USER="${SUDO_USER:-}"
[ -n "$CTRR_USER" ] && [ "$CTRR_USER" != root ] || die "run via sudo from your normal user account (SUDO_USER is unset)"

cmd_status() {
    echo "image:      $IMG ($( [ -f "$IMG" ] && du -h --apparent-size "$IMG" | cut -f1 || echo missing ) apparent, $( [ -f "$IMG" ] && du -h "$IMG" | cut -f1 || echo 0 ) on disk)"
    if mountpoint -q "$MNT"; then
        echo "mount:      $(findmnt -no SOURCE,FSTYPE,OPTIONS "$MNT")"
        echo "subvolumes:"; btrfs subvolume list "$MNT" | sed 's/^/  /'
        echo "data:       $(stat -c '%U:%G %a ino=%i' "$SRC" 2>/dev/null || echo missing)"
        echo "snapshots:  $(stat -c '%U:%G %a' "$DST_DIR" 2>/dev/null || echo missing)"
    else
        echo "mount:      $MNT not mounted"
    fi
    echo "helper:     $( [ -x "$HELPER_DST" ] && stat -c '%U:%G %a' "$HELPER_DST" || echo missing )"
    echo "sudoers:    $( [ -f "$SUDOERS_DST" ] && stat -c '%U:%G %a' "$SUDOERS_DST" || echo missing )"
}

cmd_up() {
    command -v btrfs >/dev/null && command -v mkfs.btrfs >/dev/null \
        || die "btrfs-progs not installed: sudo apt install btrfs-progs"

    if [ ! -f "$IMG" ]; then
        echo "creating sparse $IMG_SIZE image at $IMG"
        truncate -s "$IMG_SIZE" "$IMG"
        mkfs.btrfs -q -L ctrr "$IMG"
    fi

    mkdir -p "$MNT"
    if ! mountpoint -q "$MNT"; then
        # Default options on purpose: no user_subvol_rm_allowed.
        mount -o loop "$IMG" "$MNT"
    fi

    if ! btrfs subvolume show "$SRC" >/dev/null 2>&1; then
        btrfs subvolume create "$SRC" >/dev/null
    fi
    chown "$CTRR_USER:$CTRR_USER" "$SRC"

    mkdir -p "$DST_DIR"
    chown root:root "$MNT" "$DST_DIR"
    chmod 0755 "$MNT"
    chmod "$SNAP_MODE" "$DST_DIR"

    # Install the helper with its fixed paths substituted in.  It must be
    # root-owned and not writable by the user, or the user could edit what
    # sudo runs as root.
    tmp="$(mktemp)"
    sed -e "s|@SRC@|$SRC|" -e "s|@DST_DIR@|$DST_DIR|" "$HERE/ctrr-snapshot" > "$tmp"
    install -o root -g root -m 0755 "$tmp" "$HELPER_DST"
    rm -f "$tmp"

    # Validate the sudoers fragment before installing it: a syntax error in
    # /etc/sudoers.d can lock sudo for everyone.
    tmp="$(mktemp)"
    sed -e "s|@USER@|$CTRR_USER|" "$HERE/sudoers.ctrr" > "$tmp"
    visudo -cf "$tmp" >/dev/null || { rm -f "$tmp"; die "sudoers fragment failed visudo check"; }
    install -o root -g root -m 0440 "$tmp" "$SUDOERS_DST"
    rm -f "$tmp"

    cmd_status
}

cmd_down() {
    rm -f "$SUDOERS_DST" "$HELPER_DST"
    if mountpoint -q "$MNT"; then umount "$MNT"; fi
    echo "helper and sudoers rule removed; $MNT unmounted; image kept at $IMG"
}

case "${1:-}" in
    up)     cmd_up ;;
    status) cmd_status ;;
    down)   cmd_down ;;
    purge)  cmd_down; rm -f "$IMG"; echo "deleted $IMG" ;;
    *)      echo "usage: sudo bash deploy/setup_btrfs.sh up|status|down|purge" >&2; exit 2 ;;
esac
