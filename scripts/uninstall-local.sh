#!/bin/bash
# Remove locally installed howy artifacts without touching PAM service files.

set -euo pipefail

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

main() {
    require_root

    echo "Stopping local howy units if present..."
    systemctl disable --now howy.socket howy.service >/dev/null 2>&1 || true

    remove_if_exists /etc/systemd/system/howy.service
    remove_if_exists /etc/systemd/system/howy.socket
    remove_if_exists /usr/bin/howyd
    remove_if_exists /usr/bin/howy
    remove_if_exists /lib/security/pam_howy.so

    echo "Reloading systemd manager configuration..."
    systemctl daemon-reload

    cat <<'EOF'

Local howy artifacts removed.

Not removed:
  - /etc/pam.d/* changes you made manually
  - /etc/howy/config.toml
  - /etc/howy/models/
  - /var/cache/howy and /var/log/howy

Review those paths manually if you want a deeper cleanup.
EOF
}

main "$@"
