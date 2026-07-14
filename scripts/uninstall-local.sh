#!/bin/bash
# Remove locally installed howy artifacts without touching PAM service files.

set -euo pipefail

SERVICE_DEST="${SERVICE_DEST:-/etc/systemd/system/howy.service}"
SOCKET_DEST="${SOCKET_DEST:-/etc/systemd/system/howy.socket}"
HOWYD_DEST="${HOWYD_DEST:-/usr/bin/howyd}"
HOWY_DEST="${HOWY_DEST:-/usr/bin/howy}"
PAM_DEST="${PAM_DEST:-/lib/security/pam_howy.so}"
SYSUSERS_DEST="${SYSUSERS_DEST:-/usr/lib/sysusers.d/howy.conf}"

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

    if [ -e "${path}" ]; then
        rm -f "${path}"
        printf 'Removed %s\n' "${path}"
    fi
}

uninstall_main() {
    require_root

    echo "Stopping local howy units if present..."
    systemctl disable --now howy.socket howy.service >/dev/null 2>&1 || true

    remove_if_exists "${SERVICE_DEST}"
    remove_if_exists "${SOCKET_DEST}"
    remove_if_exists "${HOWYD_DEST}"
    remove_if_exists "${HOWY_DEST}"
    remove_if_exists "${PAM_DEST}"
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
  - /var/cache/howy and /var/log/howy

Review those paths manually if you want a deeper cleanup.
EOF
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    uninstall_main "$@"
fi
