#!/bin/bash
# Remove locally installed howy artifacts without touching PAM service files.

set -euo pipefail

SERVICE_DEST="${SERVICE_DEST:-/etc/systemd/system/howy.service}"
SOCKET_DEST="${SOCKET_DEST:-/etc/systemd/system/howy.socket}"
HOWYD_DEST="${HOWYD_DEST:-/usr/bin/howyd}"
HOWY_DEST="${HOWY_DEST:-/usr/bin/howy}"
PAM_DEST="${PAM_DEST:-/usr/lib/security/pam_howy.so}"
SYSUSERS_DEST="${SYSUSERS_DEST:-/usr/lib/sysusers.d/howy.conf}"
BRIDGE_DEST="${BRIDGE_DEST:-/usr/lib/howy/howy-config-bridge}"
BOOTSTRAP_DEST="${BOOTSTRAP_DEST:-/usr/share/howy/config.bootstrap.toml}"
ALPM_HOOK_DEST="${ALPM_HOOK_DEST:-/usr/share/libalpm/hooks/05-howy-config-stash.hook}"

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        die "Run this script as root (for example: sudo scripts/uninstall-local.sh)"
    fi
}

remove_if_exists() {
    local path="$1"

    if [ -e "${path}" ] || [ -L "${path}" ]; then
        rm -f "${path}"
        printf 'Removed %s\n' "${path}"
    fi
}

run_bridge() {
    "$@"
}

uninstall_main() {
    require_root

    echo "Stopping socket activation before the service..."
    systemctl disable --now howy.socket >/dev/null 2>&1 || true
    systemctl stop howy.service >/dev/null 2>&1 || true
    if systemctl is-active --quiet howy.socket || systemctl is-active --quiet howy.service; then
        die "Howy units remained active; refusing artifact removal"
    fi
    if [ -x "${BRIDGE_DEST}" ]; then
        run_bridge "${BRIDGE_DEST}" stash-release-n >/dev/null \
            || die "Could not consume the bootstrap marker and preserve the exact config state"
    fi

    remove_if_exists "${SERVICE_DEST}"
    remove_if_exists "${SOCKET_DEST}"
    remove_if_exists "${HOWYD_DEST}"
    remove_if_exists "${HOWY_DEST}"
    remove_if_exists "${PAM_DEST}"
    remove_if_exists "${BRIDGE_DEST}"
    remove_if_exists "${BOOTSTRAP_DEST}"
    remove_if_exists "${ALPM_HOOK_DEST}"
    remove_if_exists "${SYSUSERS_DEST}"

    echo "Reloading systemd manager configuration..."
    systemctl daemon-reload

    cat <<'EOF'

Local howy artifacts removed.

The howy-ffmpeg account and group were not deleted.

Not removed:
  - /etc/pam.d/* changes you made manually
  - /etc/howy/config.toml
  - /etc/howy/models/
  - /etc/credstore.encrypted/howy.storage.mode1.epoch1 and other credential artifacts
  - /etc/systemd/system/howy.service.d/ and provisioning drop-ins
  - /var/lib/howy/security-state/ receipts and unadopted artifacts
  - /var/lib/howy/config-bridge/ release-N stash and manifest
  - /var/cache/howy and /var/log/howy

Review those paths manually if you want a deeper cleanup.
EOF
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    uninstall_main "$@"
fi
