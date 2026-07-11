#!/bin/bash
# Install local howy artifacts for conservative PAM/systemd testing.

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(dirname "${SCRIPT_DIR}")
TARGET_DIR="${REPO_ROOT}/target/release"

HOWYD_SRC="${TARGET_DIR}/howyd"
HOWY_SRC="${TARGET_DIR}/howy"
PAM_SRC="${TARGET_DIR}/libpam_howy.so"

PREWARM_STATUS="not-run"
PREWARM_MESSAGE="Install-time prewarm was not attempted."

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        die "Run this script as root (for example: sudo scripts/install-local.sh)"
    fi
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

confirm_overwrite() {
    local path="$1"

    if [ ! -e "${path}" ]; then
        return 0
    fi

    printf '%s already exists. Overwrite? [y/N] ' "${path}"
    read -r reply
    case "${reply}" in
        y|Y)
            return 0
            ;;
        *)
            die "Refusing to overwrite ${path}"
            ;;
    esac
}

build_release_artifacts() {
    echo "Building release artifacts for this checkout..."
    export ORT_LIB_PATH="${ORT_LIB_PATH:-/usr/lib}"
    export ORT_PREFER_DYNAMIC_LINK="${ORT_PREFER_DYNAMIC_LINK:-1}"
    cargo build --release -p howy-daemon -p howy-cli -p howy-pam
}

read_ml_provider() {
    local config_path="$1"
    local in_ml=0
    local line
    local trimmed
    local value

    while IFS= read -r line || [ -n "${line}" ]; do
        trimmed="${line#"${line%%[![:space:]]*}"}"

        case "${trimmed}" in
            ""|\#*)
                continue
                ;;
            \[*\])
                if [ "${trimmed}" = "[ml]" ]; then
                    in_ml=1
                else
                    in_ml=0
                fi
                ;;
            provider*=*|provider\ =*)
                if [ "${in_ml}" -eq 1 ]; then
                    value="${trimmed#*=}"
                    value="${value//\"/}"
                    value="${value//\'/}"
                    value="${value//[[:space:]]/}"
                    if [ -n "${value}" ]; then
                        printf '%s\n' "${value}"
                        return 0
                    fi
                fi
                ;;
        esac
    done < "${config_path}"

    printf 'auto\n'
}

install_files() {
    [ -x "${HOWYD_SRC}" ] || die "Missing artifact: ${HOWYD_SRC}"
    [ -x "${HOWY_SRC}" ] || die "Missing artifact: ${HOWY_SRC}"
    [ -f "${PAM_SRC}" ] || die "Missing artifact: ${PAM_SRC}"

    echo "Installing binaries..."
    install -D -m 0755 "${HOWYD_SRC}" /usr/bin/howyd
    install -D -m 0755 "${HOWY_SRC}" /usr/bin/howy

    echo "Installing PAM module..."
    install -D -m 0644 "${PAM_SRC}" /lib/security/pam_howy.so

    echo "Installing systemd units..."
    install -D -m 0644 "${REPO_ROOT}/systemd/howy.service" /etc/systemd/system/howy.service
    install -D -m 0644 "${REPO_ROOT}/systemd/howy.socket" /etc/systemd/system/howy.socket

    echo "Preparing local test directories..."
    install -d -m 0755 /etc/howy
    install -d -m 0755 /etc/howy/models
    install -d -m 0755 /var/cache/howy
    install -d -m 0755 /var/log/howy

    confirm_overwrite /etc/howy/config.toml
    echo "Installing local test config..."
    install -m 0644 "${REPO_ROOT}/howy.config" /etc/howy/config.toml
}

run_install_prewarm() {
    local provider
    local output
    local status

    provider=$(read_ml_provider /etc/howy/config.toml)
    provider=${provider,,}

    case "${provider}" in
        migraphx|auto)
            echo "Running one-shot install-time prewarm for provider '${provider}'..."
            if output=$(RUST_LOG=info HSA_OVERRIDE_GFX_VERSION=11.0.2 ORT_MIGRAPHX_MODEL_CACHE_PATH=/var/cache/howy ORT_MIGRAPHX_CACHE_PATH=/var/cache/howy /usr/bin/howyd --prewarm-only 2>&1); then
                printf '%s\n' "${output}"
                if [[ "${output}" == *"fallback_to_cpu=true"* ]]; then
                    PREWARM_STATUS="fallback"
                    PREWARM_MESSAGE="GPU prewarm completed only via CPU fallback; the PAM deployment remains usable, but MIGraphX cache may need regeneration later."
                    printf 'Warning: %s\n' "${PREWARM_MESSAGE}" >&2
                else
                    PREWARM_STATUS="ok"
                    PREWARM_MESSAGE="Install-time prewarm completed; persistent MIGraphX cache files, if generated, are under /var/cache/howy."
                    echo "${PREWARM_MESSAGE}"
                fi
            else
                status=$?
                printf '%s\n' "${output}" >&2
                PREWARM_STATUS="failed"
                PREWARM_MESSAGE="Install-time prewarm failed with exit ${status}; the install continues and runtime CPU fallback remains available."
                printf 'Warning: %s\n' "${PREWARM_MESSAGE}" >&2
            fi
            ;;
        *)
            PREWARM_STATUS="skipped"
            PREWARM_MESSAGE="Skipped install-time prewarm because provider '${provider}' is not MIGraphX-targeted."
            echo "${PREWARM_MESSAGE}"
            ;;
    esac
}

print_next_steps() {
    cat <<EOF

Local howy install complete.

Install-time prewarm: ${PREWARM_MESSAGE}

Next manual steps:
  1. Review /etc/howy/config.toml and make sure the model paths and camera device
     match this machine.
  2. Start the socket-activated daemon when ready:
       sudo systemctl enable --now howy.socket
  3. Test daemon connectivity:
       sudo howy status
  4. Enroll a face model for a user:
       sudo howy --user <username> add
  5. Update an existing PAM service file manually (for example /etc/pam.d/sudo)
     by inserting:
        auth    sufficient    pam_howy.so
      before the distro's normal auth include.

This script does NOT modify /etc/pam.d/ files automatically.
EOF

    case "${PREWARM_STATUS}" in
        ok)
            cat <<'EOF'

If you need to regenerate MIGraphX compiled cache later, clear:
  /var/cache/howy/*.mxr

If provider auto-selection needs to be rediscovered, also clear:
  /var/cache/howy/provider-selection.txt

Common reasons to clear it: model updates, ONNX Runtime updates, ROCm/MIGraphX updates,
or a different GPU architecture.
EOF
            ;;
        fallback|failed)
            cat <<'EOF'

If you later want to regenerate MIGraphX cache, clear any stale files first:
  /var/cache/howy/*.mxr
  /var/cache/howy/provider-selection.txt

Then rerun a one-shot prewarm with the service environment:
  sudo RUST_LOG=info HSA_OVERRIDE_GFX_VERSION=11.0.2 \
       ORT_MIGRAPHX_MODEL_CACHE_PATH=/var/cache/howy \
       ORT_MIGRAPHX_CACHE_PATH=/var/cache/howy \
       /usr/bin/howyd --prewarm-only
EOF
            ;;
    esac
}

main() {
    require_root
    require_command cargo
    require_command install
    require_command systemctl

    build_release_artifacts
    install_files
    run_install_prewarm

    echo "Reloading systemd manager configuration..."
    systemctl daemon-reload

    print_next_steps
}

main "$@"
