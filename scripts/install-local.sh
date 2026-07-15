#!/bin/bash
# Install local howy artifacts for conservative PAM/systemd testing.

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(dirname "${SCRIPT_DIR}")
TARGET_DIR="${REPO_ROOT}/target/release"

HOWYD_SRC="${TARGET_DIR}/howyd"
HOWY_SRC="${TARGET_DIR}/howy"
PAM_SRC="${TARGET_DIR}/libpam_howy.so"
BRIDGE_SRC="${TARGET_DIR}/howy-config-bridge"
SYSUSERS_SRC="${REPO_ROOT}/sysusers.d/howy.conf"
BOOTSTRAP_SRC="${REPO_ROOT}/packaging/config.bootstrap.toml"
ALPM_HOOK_SRC="${REPO_ROOT}/packaging/05-howy-config-stash.hook"

HOWYD_DEST="${HOWYD_DEST:-/usr/bin/howyd}"
HOWY_DEST="${HOWY_DEST:-/usr/bin/howy}"
PAM_DEST="${PAM_DEST:-/usr/lib/security/pam_howy.so}"
SERVICE_DEST="${SERVICE_DEST:-/etc/systemd/system/howy.service}"
SOCKET_DEST="${SOCKET_DEST:-/etc/systemd/system/howy.socket}"
CONFIG_DEST="${CONFIG_DEST:-/etc/howy/config.toml}"
CONFIG_DIR="${CONFIG_DIR:-/etc/howy}"
MODELS_DIR="${MODELS_DIR:-/etc/howy/models}"
CACHE_DIR="${CACHE_DIR:-/var/cache/howy}"
LOG_DIR="${LOG_DIR:-/var/log/howy}"
SYSUSERS_DEST="${SYSUSERS_DEST:-/usr/lib/sysusers.d/howy.conf}"
BRIDGE_DEST="${BRIDGE_DEST:-/usr/lib/howy/howy-config-bridge}"
BOOTSTRAP_DEST="${BOOTSTRAP_DEST:-/usr/share/howy/config.bootstrap.toml}"
ALPM_HOOK_DEST="${ALPM_HOOK_DEST:-/usr/share/libalpm/hooks/05-howy-config-stash.hook}"
SERVICE_DROPIN_DIR="${SERVICE_DROPIN_DIR:-/etc/systemd/system/howy.service.d}"
MODE1_MODELS_DIR="${MODE1_MODELS_DIR:-/etc/howy/models/mode1}"
CREDSTORE_DIR="${CREDSTORE_DIR:-/etc/credstore.encrypted}"
STATE_DIR="${STATE_DIR:-/var/lib/howy}"
SECURITY_STATE_DIR="${SECURITY_STATE_DIR:-/var/lib/howy/security-state}"
UNADOPTED_DIR="${UNADOPTED_DIR:-/var/lib/howy/security-state/unadopted}"
BRIDGE_STATE_DIR="${BRIDGE_STATE_DIR:-/var/lib/howy/config-bridge}"
SYSTEMD_SYSUSERS="${SYSTEMD_SYSUSERS:-systemd-sysusers}"
CONFIG_EXPECTED_UID="${CONFIG_EXPECTED_UID:-0}"
CONFIG_EXPECTED_GID="${CONFIG_EXPECTED_GID:-0}"

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
SERVICE_RESTARTED_BY_INSTALLER=0
SOCKET_RESTARTED_BY_INSTALLER=0
SYSUSERS_BACKUP_DIR=""
SYSUSERS_DEST_EXISTED=0
SYSUSERS_FILE_TOUCHED=0
SYSUSERS_TEMP=""
INSTALL_COMMITTED=0
DAEMON_RELOADED=0
RECOVERY_RESTART_ALLOWED=1
MARKER_COMMITTED=0
PRIOR_SERVICE_MANAGER_POLICY=""
PRIOR_SOCKET_MANAGER_POLICY=""
ARTIFACT_BACKUP_DIR=""
ARTIFACTS_TOUCHED=0
CONFIG_WAS_PRESENT=0
CONFIG_CREATED=0
CONFIG_SNAPSHOT_METADATA=""
CONFIG_SNAPSHOT_HASH=""
CONFIG_SNAPSHOT_LINK=""
CONFIG_SNAPSHOT_KIND="absent"
declare -a ARTIFACT_DESTINATIONS=()
declare -a ARTIFACT_BACKUP_PRESENT=()

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

run_bridge() {
    "$@"
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
}

parse_arguments() {
    case "$#:$*" in
        0:)
            ;;
        1:--migrate|1:--migrate-security)
            die "Security migration is intentionally outside the installer artifact transaction. Run exactly: sudo howy security provision --mode 1"
            ;;
        *)
            die "Usage: scripts/install-local.sh"
            ;;
    esac
}

build_release_artifacts() {
    echo "Building release artifacts for this checkout..."
    export ORT_LIB_PATH="${ORT_LIB_PATH:-/usr/lib}"
    export ORT_PREFER_DYNAMIC_LINK="${ORT_PREFER_DYNAMIC_LINK:-1}"
    cargo build --release -p howy-config-bridge -p howy-daemon -p howy-cli -p howy-pam
}

snapshot_existing_config() {
    local metadata_before
    local metadata_after
    local object_type
    local descriptor

    if [ ! -e "${CONFIG_DEST}" ] && [ ! -L "${CONFIG_DEST}" ]; then
        CONFIG_WAS_PRESENT=0
        return 0
    fi

    CONFIG_WAS_PRESENT=1
    metadata_before=$(stat -c '%d:%i:%F:%u:%g:%a:%h:%s:%y:%z' -- "${CONFIG_DEST}")
    object_type=$(stat -c '%F' -- "${CONFIG_DEST}")
    CONFIG_SNAPSHOT_KIND="${object_type}"
    case "${object_type}" in
        "regular file")
            exec {descriptor}<"${CONFIG_DEST}"
            metadata_after=$(stat -Lc '%d:%i:%F:%u:%g:%a:%h:%s:%y:%z' -- "/proc/self/fd/${descriptor}")
            [ "${metadata_before}" = "${metadata_after}" ] \
                || die "Configuration changed while opening its snapshot descriptor"
            CONFIG_SNAPSHOT_HASH=$(sha256sum "/proc/self/fd/${descriptor}" | cut -d' ' -f1)
            CONFIG_SNAPSHOT_METADATA=$(stat -Lc '%d:%i:%F:%u:%g:%a:%h:%s:%y:%z' -- "/proc/self/fd/${descriptor}")
            metadata_after=$(stat -Lc '%d:%i:%F:%u:%g:%a:%h:%s:%y:%z' -- "/proc/self/fd/${descriptor}")
            exec {descriptor}<&-
            [ "${CONFIG_SNAPSHOT_METADATA}" = "${metadata_after}" ] \
                || die "Configuration changed while hashing its snapshot descriptor"
            ;;
        "symbolic link")
            CONFIG_SNAPSHOT_LINK=$(readlink -- "${CONFIG_DEST}")
            CONFIG_SNAPSHOT_METADATA="${metadata_before}"
            ;;
        *)
            CONFIG_SNAPSHOT_METADATA="${metadata_before}"
            ;;
    esac
    echo "Recorded existing configuration bytes and metadata before runtime changes."
}

verify_preserved_config() {
    local object_type
    local descriptor
    local current_metadata
    local current_hash

    [ "${CONFIG_WAS_PRESENT}" -eq 1 ] || return 0
    [ -e "${CONFIG_DEST}" ] || [ -L "${CONFIG_DEST}" ] \
        || die "Preserved configuration object disappeared"
    object_type=$(stat -c '%F' -- "${CONFIG_DEST}")
    case "${object_type}" in
        "regular file")
            exec {descriptor}<"${CONFIG_DEST}"
            current_hash=$(sha256sum "/proc/self/fd/${descriptor}" | cut -d' ' -f1)
            current_metadata=$(stat -Lc '%d:%i:%F:%u:%g:%a:%h:%s:%y:%z' -- "/proc/self/fd/${descriptor}")
            exec {descriptor}<&-
            [ "${current_hash}" = "${CONFIG_SNAPSHOT_HASH}" ] \
                || die "Preserved configuration byte hash changed"
            [ "${current_metadata}" = "${CONFIG_SNAPSHOT_METADATA}" ] \
                || die "Preserved configuration metadata changed"
            ;;
        "symbolic link")
            [ "$(readlink -- "${CONFIG_DEST}")" = "${CONFIG_SNAPSHOT_LINK}" ] \
                || die "Preserved configuration symlink changed"
            [ "$(stat -c '%d:%i:%F:%u:%g:%a:%h:%s:%y:%z' -- "${CONFIG_DEST}")" = "${CONFIG_SNAPSHOT_METADATA}" ] \
                || die "Preserved configuration symlink metadata changed"
            ;;
        *)
            [ "$(stat -c '%d:%i:%F:%u:%g:%a:%h:%s:%y:%z' -- "${CONFIG_DEST}")" = "${CONFIG_SNAPSHOT_METADATA}" ] \
                || die "Preserved configuration object metadata changed"
            ;;
    esac
}

prepare_artifact_backup() {
    local index
    local path

    ARTIFACT_DESTINATIONS=(
        "${HOWYD_DEST}" "${HOWY_DEST}" "${PAM_DEST}" "${SERVICE_DEST}" "${SOCKET_DEST}"
        "${BRIDGE_DEST}" "${BOOTSTRAP_DEST}" "${ALPM_HOOK_DEST}"
    )
    ARTIFACT_BACKUP_DIR=$(mktemp -d)
    ARTIFACT_BACKUP_PRESENT=()
    for index in "${!ARTIFACT_DESTINATIONS[@]}"; do
        path=${ARTIFACT_DESTINATIONS[${index}]}
        if [ -e "${path}" ] || [ -L "${path}" ]; then
            cp -a -- "${path}" "${ARTIFACT_BACKUP_DIR}/${index}"
            ARTIFACT_BACKUP_PRESENT[${index}]=1
        else
            ARTIFACT_BACKUP_PRESENT[${index}]=0
        fi
    done
}

rollback_artifacts() {
    local index
    local path

    [ "${ARTIFACTS_TOUCHED}" -eq 1 ] || return 0
    echo "Rolling back installed runtime artifacts without touching configuration or data..." >&2
    for index in "${!ARTIFACT_DESTINATIONS[@]}"; do
        path=${ARTIFACT_DESTINATIONS[${index}]}
        rm -rf -- "${path}"
        if [ "${ARTIFACT_BACKUP_PRESENT[${index}]}" -eq 1 ]; then
            cp -a -- "${ARTIFACT_BACKUP_DIR}/${index}" "${path}"
        fi
    done
    ARTIFACTS_TOUCHED=0
}

cleanup_artifact_backup() {
    if [ -n "${ARTIFACT_BACKUP_DIR}" ]; then
        rm -rf -- "${ARTIFACT_BACKUP_DIR}"
        ARTIFACT_BACKUP_DIR=""
    fi
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
    PRIOR_SERVICE_MANAGER_POLICY=$(manager_policy_snapshot howy.service)
    PRIOR_SOCKET_MANAGER_POLICY=$(manager_policy_snapshot howy.socket)
    echo "Recorded unit state: howy.service active=${PRIOR_SERVICE_ACTIVE} enabled=${PRIOR_SERVICE_ENABLED}; howy.socket active=${PRIOR_SOCKET_ACTIVE} enabled=${PRIOR_SOCKET_ENABLED}"
}

restore_active_states() {
    [ "${STATE_CAPTURED}" -eq 1 ] || return 0
    [ "${STATE_RESTORED}" -eq 0 ] || return 0

    echo "Restoring prior active states without changing enablement..."
    if [ "${PRIOR_SOCKET_ACTIVE}" -eq 1 ] && [ "${SOCKET_STOPPED_BY_INSTALLER}" -eq 1 ]; then
        if ! systemctl start howy.socket; then
            RECOVERY_RESTART_ALLOWED=0
            return 1
        fi
        SOCKET_RESTARTED_BY_INSTALLER=1
    fi
    if [ "${PRIOR_SERVICE_ACTIVE}" -eq 1 ] && [ "${SERVICE_STOPPED_BY_INSTALLER}" -eq 1 ]; then
        if ! systemctl start howy.service; then
            if [ "${SOCKET_RESTARTED_BY_INSTALLER}" -eq 1 ]; then
                systemctl stop howy.socket || true
                SOCKET_RESTARTED_BY_INSTALLER=0
            fi
            RECOVERY_RESTART_ALLOWED=0
            return 1
        fi
        SERVICE_RESTARTED_BY_INSTALLER=1
    fi
    STATE_RESTORED=1
}

restore_on_exit() {
    local status=$?
    trap - EXIT INT TERM
    set +e
    if [ "${status}" -ne 0 ] && [ "${INSTALL_COMMITTED}" -eq 0 ]; then
        if [ "${MARKER_COMMITTED}" -eq 1 ] && [ -x "${BRIDGE_DEST}" ]; then
            if ! run_bridge "${BRIDGE_DEST}" stash-release-n >/dev/null; then
                printf '%s\n' 'Recovery warning: failed to consume the newly committed package-bootstrap marker; units will remain stopped.' >&2
                RECOVERY_RESTART_ALLOWED=0
            fi
        fi
        rollback_artifacts
        rollback_sysusers_definition
        if [ "${DAEMON_RELOADED}" -eq 1 ]; then
            if ! systemctl daemon-reload; then
                printf '%s\n' 'Recovery warning: daemon-reload of restored unit definitions failed; units remain stopped.' >&2
                RECOVERY_RESTART_ALLOWED=0
            elif ! verify_prior_manager_policies; then
                printf '%s\n' 'Recovery warning: systemd did not load the exact prior unit policy; units remain stopped.' >&2
                RECOVERY_RESTART_ALLOWED=0
            fi
        fi
    fi
    cleanup_artifact_backup
    cleanup_sysusers_backup
    if [ "${RECOVERY_RESTART_ALLOWED}" -eq 1 ]; then
        restore_active_states
    else
        printf '%s\n' 'Manual recovery required: verify restored unit files, run systemctl daemon-reload, then restart only previously active Howy units.' >&2
    fi
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
    echo "Stopping socket activation before the service and settling both units..."
    stop_runtime_unit howy.socket SOCKET_STOPPED_BY_INSTALLER
    settle_inactive howy.socket
    stop_runtime_unit howy.service SERVICE_STOPPED_BY_INSTALLER
    settle_inactive howy.service
    settle_inactive howy.socket
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
    settle_inactive "${unit}"
    printf -v "${stopped_variable}" '%s' 1
}

settle_inactive() {
    local unit="$1"
    local attempt

    for attempt in {1..50}; do
        if ! systemctl is-active --quiet "${unit}"; then
            return 0
        fi
        sleep 0.1
    done
    die "${unit} remained active after stop/settle"
}

manager_policy_snapshot() {
    local unit="$1"
    systemctl show --all \
        --property=LoadState \
        --property=FragmentPath \
        --property=DropInPaths \
        --property=Conditions \
        --property=ExecStart \
        --property=Listen \
        -- "${unit}"
}

verify_prior_manager_policies() {
    [ "$(manager_policy_snapshot howy.service)" = "${PRIOR_SERVICE_MANAGER_POLICY}" ] \
        && [ "$(manager_policy_snapshot howy.socket)" = "${PRIOR_SOCKET_MANAGER_POLICY}" ]
}

verify_manager_loaded_installed_units() {
    local conditions

    [ "$(systemctl show --property=NeedDaemonReload --value -- howy.service)" = "no" ] \
        || die "systemd still reports howy.service needs daemon-reload"
    [ "$(systemctl show --property=NeedDaemonReload --value -- howy.socket)" = "no" ] \
        || die "systemd still reports howy.socket needs daemon-reload"
    [ "$(systemctl show --property=FragmentPath --value -- howy.service)" = "${SERVICE_DEST}" ] \
        || die "systemd did not load the installed service fragment"
    [ "$(systemctl show --property=FragmentPath --value -- howy.socket)" = "${SOCKET_DEST}" ] \
        || die "systemd did not load the installed socket fragment"
    for unit in howy.service howy.socket; do
        conditions=$(systemctl show --property=Conditions --value -- "${unit}")
        [[ "${conditions}" == *"/var/lib/howy-security-transaction.guard"* ]] \
            || die "systemd effective ${unit} policy is missing the transaction guard"
        [[ "${conditions}" == *"/var/lib/howy-package-bootstrap.complete"* ]] \
            || die "systemd effective ${unit} policy is missing the package-bootstrap marker"
        [[ "${conditions}" == *"/var/lib/howy-security-transaction.guard"*"/var/lib/howy-package-bootstrap.complete"* ]] \
            || die "systemd effective ${unit} condition order differs from policy"
    done
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
    verify_exact_artifact "${BRIDGE_SRC}" "${BRIDGE_DEST}"
    verify_exact_artifact "${BOOTSTRAP_SRC}" "${BOOTSTRAP_DEST}"
    verify_exact_artifact "${ALPM_HOOK_SRC}" "${ALPM_HOOK_DEST}"
    verify_exact_artifact "${REPO_ROOT}/systemd/howy.service" "${SERVICE_DEST}"
    verify_exact_artifact "${REPO_ROOT}/systemd/howy.socket" "${SOCKET_DEST}"
    verify_exact_artifact "${SYSUSERS_SRC}" "${SYSUSERS_DEST}"
    verify_sysusers_metadata
    verify_preserved_config
    if [ "${CONFIG_CREATED}" -eq 1 ]; then
        verify_exact_artifact "${BOOTSTRAP_SRC}" "${CONFIG_DEST}"
        [ "$(stat -c '%a' "${CONFIG_DEST}")" = "600" ] || die "${CONFIG_DEST} must be mode 0600"
        [ "$(stat -c '%u:%g' "${CONFIG_DEST}")" = "${CONFIG_EXPECTED_UID}:${CONFIG_EXPECTED_GID}" ] \
            || die "${CONFIG_DEST} must have the expected root ownership"
    fi
    [ "$(stat -c '%a' "${CONFIG_DIR}")" = "700" ] || die "${CONFIG_DIR} must be mode 0700"
    [ "$(stat -c '%a' "${MODELS_DIR}")" = "700" ] || die "${MODELS_DIR} must be mode 0700"
    [ "$(stat -c '%a' "${MODE1_MODELS_DIR}")" = "700" ] || die "${MODE1_MODELS_DIR} must be mode 0700"
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
    [ -x "${BRIDGE_SRC}" ] || die "Missing artifact: ${BRIDGE_SRC}"
    [ -f "${BOOTSTRAP_SRC}" ] || die "Missing artifact: ${BOOTSTRAP_SRC}"
    [ -f "${ALPM_HOOK_SRC}" ] || die "Missing artifact: ${ALPM_HOOK_SRC}"

    ARTIFACTS_TOUCHED=1

    echo "Installing binaries..."
    install -D -m 0755 "${HOWYD_SRC}" "${HOWYD_DEST}"
    install -D -m 0755 "${HOWY_SRC}" "${HOWY_DEST}"
    install -D -m 0755 "${BRIDGE_SRC}" "${BRIDGE_DEST}"

    echo "Installing PAM module..."
    install -D -m 0644 "${PAM_SRC}" "${PAM_DEST}"

    echo "Installing systemd units..."
    install -D -m 0644 "${REPO_ROOT}/systemd/howy.service" "${SERVICE_DEST}"
    install -D -m 0644 "${REPO_ROOT}/systemd/howy.socket" "${SOCKET_DEST}"
    install -D -m 0644 "${BOOTSTRAP_SRC}" "${BOOTSTRAP_DEST}"
    install -D -m 0644 "${ALPM_HOOK_SRC}" "${ALPM_HOOK_DEST}"

}

ensure_local_config() {
    local output

    output=$(run_bridge "${BRIDGE_DEST}" create-if-absent) \
        || die "Descriptor-safe bootstrap create/occupancy check failed"
    case "${output}" in
        HOWY_CONFIG_RESULT=Created)
            [ "${CONFIG_WAS_PRESENT}" -eq 0 ] \
                || die "Bridge reported Created for a configuration that was already occupied"
            CONFIG_CREATED=1
            ;;
        HOWY_CONFIG_RESULT=Occupied)
            if [ "${CONFIG_WAS_PRESENT}" -eq 0 ]; then
                snapshot_existing_config
                verify_preserved_config
                die "Configuration became occupied after the initial snapshot; refusing the race without ownership"
            fi
            verify_preserved_config
            echo "Preserving the descriptor-verified existing configuration without rewrite."
            ;;
        *)
            die "Unexpected create-if-absent result: ${output}"
            ;;
    esac
}

ensure_sensitive_layout() {
    run_bridge "${BRIDGE_SRC}" ensure-layout
}

complete_local_marker() {
    local output

    output=$(run_bridge "${BRIDGE_DEST}" complete-local-install) \
        || die "Bridge could not verify the final config and create the package-bootstrap marker"
    [ "${output}" = "HOWY_LOCAL_RESULT=Complete" ] \
        || die "Unexpected local completion result: ${output}"
    MARKER_COMMITTED=1
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
  1. Provision and then explicitly enable Mode1:
       sudo howy security provision --mode 1
       sudo howy security enable
  2. Review /etc/howy/config.toml and make sure the model paths and camera device
     match this machine.
  3. Choose and enable an activation policy manually. Socket-only is the
     lower-resource/on-demand option:
       sudo systemctl enable --now howy.socket
     For the lowest first-auth latency, start both units so model/provider
     initialization and detector+recognizer warmups finish before PAM:
       sudo systemctl enable --now howy.socket howy.service
     This installer intentionally enables neither policy automatically.
   4. Test daemon connectivity:
       sudo howy status
   5. Enroll a face model for a user:
       sudo howy --user <username> add
   6. Update an existing PAM service file manually (for example /etc/pam.d/sudo)
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
    parse_arguments "$@"
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
    require_command readlink
    require_command "${SYSTEMD_SYSUSERS}"

    build_release_artifacts
    preflight_ffmpeg_account
    confirm_all_overwrites
    snapshot_existing_config
    ensure_sensitive_layout \
        || die "Descriptor-safe sensitive layout verification failed before sysusers side effects"
    trap restore_on_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    prepare_sysusers_backup
    install_sysusers_definition
    run_sysusers_definition
    validate_installed_ffmpeg_account
    verify_exact_artifact "${SYSUSERS_SRC}" "${SYSUSERS_DEST}"
    verify_sysusers_metadata

    prepare_artifact_backup

    capture_active_states
    stop_runtime_units
    install_files
    ensure_local_config || die "Descriptor-safe bootstrap creation failed; runtime artifacts will be rolled back and configuration remains untouched"

    echo "Reloading systemd manager configuration..."
    systemctl daemon-reload
    DAEMON_RELOADED=1
    verify_installed_artifacts
    verify_manager_loaded_installed_units
    if [ "${CONFIG_CREATED}" -eq 1 ]; then
        PREWARM_STATUS="skipped"
        PREWARM_MESSAGE="Skipped install-time prewarm because the fresh disabled Mode1 bootstrap is not provisioned yet."
    elif [ "${CONFIG_SNAPSHOT_KIND}" != "regular file" ]; then
        PREWARM_STATUS="skipped"
        PREWARM_MESSAGE="Skipped install-time prewarm because the preserved configuration object is not a regular file."
    else
        run_install_prewarm
    fi
    verify_preserved_config
    complete_local_marker
    restore_active_states
    INSTALL_COMMITTED=1
    ARTIFACTS_TOUCHED=0
    cleanup_sysusers_backup
    cleanup_artifact_backup

    print_next_steps
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
