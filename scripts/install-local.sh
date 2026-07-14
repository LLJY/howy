#!/bin/bash
# Install local howy artifacts for conservative PAM/systemd testing.

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(dirname "${SCRIPT_DIR}")
TARGET_DIR="${REPO_ROOT}/target/release"

HOWYD_SRC="${TARGET_DIR}/howyd"
HOWY_SRC="${TARGET_DIR}/howy"
PAM_SRC="${TARGET_DIR}/libpam_howy.so"
SYSUSERS_SRC="${REPO_ROOT}/sysusers.d/howy.conf"

HOWYD_DEST="${HOWYD_DEST:-/usr/bin/howyd}"
HOWY_DEST="${HOWY_DEST:-/usr/bin/howy}"
PAM_DEST="${PAM_DEST:-/lib/security/pam_howy.so}"
SERVICE_DEST="${SERVICE_DEST:-/etc/systemd/system/howy.service}"
SOCKET_DEST="${SOCKET_DEST:-/etc/systemd/system/howy.socket}"
CONFIG_DEST="${CONFIG_DEST:-/etc/howy/config.toml}"
CONFIG_DIR="${CONFIG_DIR:-/etc/howy}"
MODELS_DIR="${MODELS_DIR:-/etc/howy/models}"
CACHE_DIR="${CACHE_DIR:-/var/cache/howy}"
LOG_DIR="${LOG_DIR:-/var/log/howy}"
SYSUSERS_DEST="${SYSUSERS_DEST:-/usr/lib/sysusers.d/howy.conf}"
SYSTEMD_SYSUSERS="${SYSTEMD_SYSUSERS:-systemd-sysusers}"

PREWARM_STATUS="not-run"
PREWARM_MESSAGE="Install-time prewarm was not attempted."
STATE_CAPTURED=0
STATE_RESTORED=0
PRIOR_SERVICE_ACTIVE=0
PRIOR_SOCKET_ACTIVE=0
PRIOR_SERVICE_ENABLED=0
PRIOR_SOCKET_ENABLED=0
SERVICE_STOPPED_BY_INSTALLER=0
SOCKET_STOPPED_BY_INSTALLER=0
SYSUSERS_BACKUP_DIR=""
SYSUSERS_DEST_EXISTED=0
SYSUSERS_FILE_TOUCHED=0
SYSUSERS_TEMP=""
INSTALL_COMMITTED=0

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

confirm_all_overwrites() {
    confirm_overwrite "${HOWYD_DEST}"
    confirm_overwrite "${HOWY_DEST}"
    confirm_overwrite "${PAM_DEST}"
    confirm_overwrite "${SERVICE_DEST}"
    confirm_overwrite "${SOCKET_DEST}"
    confirm_overwrite "${CONFIG_DEST}"
}

build_release_artifacts() {
    echo "Building release artifacts for this checkout..."
    export ORT_LIB_PATH="${ORT_LIB_PATH:-/usr/lib}"
    export ORT_PREFER_DYNAMIC_LINK="${ORT_PREFER_DYNAMIC_LINK:-1}"
    cargo build --release -p howy-daemon -p howy-cli -p howy-pam
}

capture_active_states() {
    if systemctl is-active --quiet howy.service; then
        PRIOR_SERVICE_ACTIVE=1
    fi
    if systemctl is-active --quiet howy.socket; then
        PRIOR_SOCKET_ACTIVE=1
    fi
    if systemctl is-enabled --quiet howy.service; then
        PRIOR_SERVICE_ENABLED=1
    fi
    if systemctl is-enabled --quiet howy.socket; then
        PRIOR_SOCKET_ENABLED=1
    fi
    STATE_CAPTURED=1
    echo "Recorded unit state: howy.service active=${PRIOR_SERVICE_ACTIVE} enabled=${PRIOR_SERVICE_ENABLED}; howy.socket active=${PRIOR_SOCKET_ACTIVE} enabled=${PRIOR_SOCKET_ENABLED}"
}

restore_active_states() {
    [ "${STATE_CAPTURED}" -eq 1 ] || return 0
    [ "${STATE_RESTORED}" -eq 0 ] || return 0

    echo "Restoring prior active states without changing enablement..."
    if [ "${PRIOR_SOCKET_ACTIVE}" -eq 1 ] && [ "${SOCKET_STOPPED_BY_INSTALLER}" -eq 1 ]; then
        systemctl start howy.socket
    fi
    if [ "${PRIOR_SERVICE_ACTIVE}" -eq 1 ] && [ "${SERVICE_STOPPED_BY_INSTALLER}" -eq 1 ]; then
        systemctl start howy.service
    fi
    STATE_RESTORED=1
}

restore_on_exit() {
    local status=$?
    trap - EXIT INT TERM
    set +e
    if [ "${status}" -ne 0 ] && [ "${INSTALL_COMMITTED}" -eq 0 ]; then
        rollback_sysusers_definition
    fi
    cleanup_sysusers_backup
    restore_active_states
    exit "${status}"
}

preflight_ffmpeg_account() {
    local present=0

    if getent passwd howy-ffmpeg >/dev/null 2>&1; then
        present=1
    fi
    if getent group howy-ffmpeg >/dev/null 2>&1; then
        present=1
    fi
    if getent shadow howy-ffmpeg >/dev/null 2>&1; then
        present=1
    fi
    if [ "${present}" -eq 1 ]; then
        echo "Validating preexisting howy-ffmpeg account before adoption..."
        "${HOWYD_SRC}" --validate-ffmpeg-account \
            || die "Preexisting howy-ffmpeg account/group is nonconforming; refusing silent adoption"
    fi
}

prepare_sysusers_backup() {
    SYSUSERS_BACKUP_DIR=$(mktemp -d)
    if [ -L "${SYSUSERS_DEST}" ]; then
        die "Refusing symlinked sysusers destination: ${SYSUSERS_DEST}"
    fi
    if [ -e "${SYSUSERS_DEST}" ]; then
        [ -f "${SYSUSERS_DEST}" ] || die "Sysusers destination is not a regular file: ${SYSUSERS_DEST}"
        cp -a -- "${SYSUSERS_DEST}" "${SYSUSERS_BACKUP_DIR}/howy.conf"
        SYSUSERS_DEST_EXISTED=1
    fi
}

rollback_sysusers_definition() {
    [ "${SYSUSERS_FILE_TOUCHED}" -eq 1 ] || return 0
    echo "Rolling back installed sysusers definition..." >&2
    if [ "${SYSUSERS_DEST_EXISTED}" -eq 1 ]; then
        cp -a -- "${SYSUSERS_BACKUP_DIR}/howy.conf" "${SYSUSERS_DEST}"
    else
        rm -f -- "${SYSUSERS_DEST}"
    fi
    SYSUSERS_FILE_TOUCHED=0
}

cleanup_sysusers_backup() {
    if [ -n "${SYSUSERS_TEMP}" ]; then
        rm -f -- "${SYSUSERS_TEMP}"
        SYSUSERS_TEMP=""
    fi
    if [ -n "${SYSUSERS_BACKUP_DIR}" ]; then
        rm -rf -- "${SYSUSERS_BACKUP_DIR}"
        SYSUSERS_BACKUP_DIR=""
    fi
}

install_sysusers_definition() {
    local temporary

    echo "Installing dedicated FFmpeg sysusers definition..."
    install -d -o root -g root -m 0755 "$(dirname "${SYSUSERS_DEST}")"
    temporary=$(mktemp "${SYSUSERS_DEST}.tmp.XXXXXX")
    SYSUSERS_TEMP="${temporary}"
    if ! install -o root -g root -m 0644 "${SYSUSERS_SRC}" "${temporary}"; then
        rm -f -- "${temporary}"
        return 1
    fi
    SYSUSERS_FILE_TOUCHED=1
    if ! mv -fT -- "${temporary}" "${SYSUSERS_DEST}"; then
        rm -f -- "${temporary}"
        return 1
    fi
    SYSUSERS_TEMP=""
}

run_sysusers_definition() {
    echo "Creating or verifying the dedicated howy-ffmpeg account..."
    "${SYSTEMD_SYSUSERS}" "${SYSUSERS_DEST}"
}

validate_installed_ffmpeg_account() {
    "${HOWYD_SRC}" --validate-ffmpeg-account \
        || die "Installed howy-ffmpeg account/group does not match the exact policy"
}

verify_sysusers_metadata() {
    [ "$(stat -c '%a' "${SYSUSERS_DEST}")" = "644" ] \
        || die "${SYSUSERS_DEST} must be mode 0644"
    [ "$(stat -c '%u:%g' "${SYSUSERS_DEST}")" = "0:0" ] \
        || die "${SYSUSERS_DEST} must be owned by root:root"
}

stop_runtime_units() {
    echo "Stopping active runtime units before artifact replacement..."
    stop_runtime_unit howy.service SERVICE_STOPPED_BY_INSTALLER
    stop_runtime_unit howy.socket SOCKET_STOPPED_BY_INSTALLER
}

stop_runtime_unit() {
    local unit="$1"
    local stopped_variable="$2"

    # `is-active` is non-zero for inactive and absent units, which makes a first
    # install a no-op here instead of an error under `set -e`.
    if ! systemctl is-active --quiet "${unit}"; then
        return 0
    fi

    systemctl stop "${unit}" || true
    if systemctl is-active --quiet "${unit}"; then
        die "${unit} remained active after stop"
    fi
    printf -v "${stopped_variable}" '%s' 1
}

verify_exact_artifact() {
    local source_path="$1"
    local installed_path="$2"
    local source_hash
    local installed_hash

    source_hash=$(sha256sum "${source_path}" | cut -d' ' -f1)
    installed_hash=$(sha256sum "${installed_path}" | cut -d' ' -f1)
    printf '  %s  %s\n' "${source_hash}" "${installed_path}"
    [ "${source_hash}" = "${installed_hash}" ] || die "Installed artifact hash mismatch: ${installed_path}"
}

verify_installed_artifacts() {
    echo "Verifying exact worktree artifact hashes:"
    verify_exact_artifact "${HOWYD_SRC}" "${HOWYD_DEST}"
    verify_exact_artifact "${HOWY_SRC}" "${HOWY_DEST}"
    verify_exact_artifact "${PAM_SRC}" "${PAM_DEST}"
    verify_exact_artifact "${REPO_ROOT}/howy.config" "${CONFIG_DEST}"
    verify_exact_artifact "${REPO_ROOT}/systemd/howy.service" "${SERVICE_DEST}"
    verify_exact_artifact "${REPO_ROOT}/systemd/howy.socket" "${SOCKET_DEST}"
    verify_exact_artifact "${SYSUSERS_SRC}" "${SYSUSERS_DEST}"
    verify_sysusers_metadata
    [ "$(stat -c '%a' "${CACHE_DIR}")" = "700" ] || die "${CACHE_DIR} must be mode 0700"
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
    install -D -m 0755 "${HOWYD_SRC}" "${HOWYD_DEST}"
    install -D -m 0755 "${HOWY_SRC}" "${HOWY_DEST}"

    echo "Installing PAM module..."
    install -D -m 0644 "${PAM_SRC}" "${PAM_DEST}"

    echo "Installing systemd units..."
    install -D -m 0644 "${REPO_ROOT}/systemd/howy.service" "${SERVICE_DEST}"
    install -D -m 0644 "${REPO_ROOT}/systemd/howy.socket" "${SOCKET_DEST}"

    echo "Preparing local test directories..."
    install -d -m 0755 "${CONFIG_DIR}"
    install -d -m 0755 "${MODELS_DIR}"
    install -d -m 0700 "${CACHE_DIR}"
    install -d -m 0755 "${LOG_DIR}"

    echo "Installing local test config..."
    install -m 0644 "${REPO_ROOT}/howy.config" "${CONFIG_DEST}"
}

run_install_prewarm() {
    local provider
    local output
    local status

    provider=$(read_ml_provider "${CONFIG_DEST}")
    provider=${provider,,}

    if systemctl is-active --quiet howy.service || systemctl is-active --quiet howy.socket; then
        die "Refusing prewarm while production service/socket is active"
    fi

    case "${provider}" in
        migraphx|auto)
            echo "Running one-shot accelerator registration+self-test for provider '${provider}' (node placement remains unverified)..."
            if output=$( (umask 0077; RUST_LOG=info HSA_OVERRIDE_GFX_VERSION=11.0.2 ORT_MIGRAPHX_MODEL_CACHE_PATH="${CACHE_DIR}" ORT_MIGRAPHX_CACHE_PATH="${CACHE_DIR}" "${HOWYD_DEST}" --prewarm-only) 2>&1); then
                printf '%s\n' "${output}"
                if [[ "${output}" == *"fallback_to_cpu=true"* ]]; then
                    PREWARM_STATUS="fallback"
                    PREWARM_MESSAGE="Accelerator registration+self-test completed with CPU fallback; node placement was not verified. The PAM deployment remains usable, but MIGraphX cache may need regeneration later."
                    printf 'Warning: %s\n' "${PREWARM_MESSAGE}" >&2
                else
                    PREWARM_STATUS="ok"
                    PREWARM_MESSAGE="Accelerator registration+self-test completed; any generated MIGraphX cache files are under /var/cache/howy, but node placement remains unverified without ORT profiling."
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
  2. Choose and enable an activation policy manually. Socket-only is the
     lower-resource/on-demand option:
       sudo systemctl enable --now howy.socket
     For the lowest first-auth latency, start both units so model/provider
     initialization and detector+recognizer warmups finish before PAM:
       sudo systemctl enable --now howy.socket howy.service
     This installer intentionally enables neither policy automatically.
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

Common reasons to clear it: model updates, ONNX Runtime updates, ROCm/MIGraphX updates,
or a different GPU architecture.
EOF
            ;;
        fallback|failed)
            cat <<'EOF'

If you later want to regenerate MIGraphX cache, clear any stale files first:
  /var/cache/howy/*.mxr

Then rerun a one-shot prewarm with the service environment:
  sudo sh -c 'umask 0077; RUST_LOG=info HSA_OVERRIDE_GFX_VERSION=11.0.2 \
       ORT_MIGRAPHX_MODEL_CACHE_PATH=/var/cache/howy \
       ORT_MIGRAPHX_CACHE_PATH=/var/cache/howy \
       /usr/bin/howyd --prewarm-only'
EOF
            ;;
    esac
}

main() {
    require_root
    require_command cargo
    require_command install
    require_command sha256sum
    require_command stat
    require_command systemctl
    require_command getent
    require_command cp
    require_command mktemp
    require_command mv
    require_command "${SYSTEMD_SYSUSERS}"

    build_release_artifacts
    preflight_ffmpeg_account
    confirm_all_overwrites
    trap restore_on_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    prepare_sysusers_backup
    install_sysusers_definition
    run_sysusers_definition
    validate_installed_ffmpeg_account
    verify_exact_artifact "${SYSUSERS_SRC}" "${SYSUSERS_DEST}"
    verify_sysusers_metadata

    capture_active_states
    stop_runtime_units
    install_files

    echo "Reloading systemd manager configuration..."
    systemctl daemon-reload
    verify_installed_artifacts
    run_install_prewarm
    restore_active_states
    INSTALL_COMMITTED=1
    cleanup_sysusers_backup

    print_next_steps
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
