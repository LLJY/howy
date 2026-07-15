#!/bin/bash

set -euo pipefail

TEST_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INSTALL_SCRIPT=$(dirname "${TEST_DIR}")/install-local.sh
UNINSTALL_SCRIPT=$(dirname "${TEST_DIR}")/uninstall-local.sh

# shellcheck source=../install-local.sh
source "${INSTALL_SCRIPT}"

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

assert_contains() {
    local value="$1"
    local expected="$2"
    [[ "${value}" == *"${expected}"* ]] || fail "expected '${expected}' in '${value}'"
}

assert_not_contains() {
    local value="$1"
    local unexpected="$2"
    [[ "${value}" != *"${unexpected}"* ]] || fail "did not expect '${unexpected}' in '${value}'"
}

assert_order() {
    local value="$1"
    local first="$2"
    local second="$3"
    local after_first

    assert_contains "${value}" "${first}"
    after_first="${value#*"${first}"}"
    [[ "${after_first}" == *"${second}"* ]] \
        || fail "expected '${first}' before '${second}' in '${value}'"
}

assert_no_enablement_changes() {
    local log="$1"
    [[ "${log}" != enable\ * && "${log}" != *$'\nenable '* ]] \
        || fail "installer enabled a unit"
    [[ "${log}" != disable\ * && "${log}" != *$'\ndisable '* ]] \
        || fail "installer disabled a unit"
}

set_case_paths() {
    local root="$1"

    REPO_ROOT="${root}/repo"
    TARGET_DIR="${REPO_ROOT}/target/release"
    HOWYD_SRC="${TARGET_DIR}/howyd"
    HOWY_SRC="${TARGET_DIR}/howy"
    PAM_SRC="${TARGET_DIR}/libpam_howy.so"
    BRIDGE_SRC="${TARGET_DIR}/howy-config-bridge"
    SYSUSERS_SRC="${REPO_ROOT}/sysusers.d/howy.conf"
    BOOTSTRAP_SRC="${REPO_ROOT}/packaging/config.bootstrap.toml"
    ALPM_HOOK_SRC="${REPO_ROOT}/packaging/05-howy-config-stash.hook"

    HOWYD_DEST="${root}/dest/usr/bin/howyd"
    HOWY_DEST="${root}/dest/usr/bin/howy"
    PAM_DEST="${root}/dest/usr/lib/security/pam_howy.so"
    SERVICE_DEST="${root}/dest/etc/systemd/system/howy.service"
    SOCKET_DEST="${root}/dest/etc/systemd/system/howy.socket"
    CONFIG_DEST="${root}/dest/etc/howy/config.toml"
    CONFIG_DIR="${root}/dest/etc/howy"
    MODELS_DIR="${root}/dest/etc/howy/models"
    CACHE_DIR="${root}/dest/var/cache/howy"
    LOG_DIR="${root}/dest/var/log/howy"
    SYSUSERS_DEST="${root}/dest/usr/lib/sysusers.d/howy.conf"
    BRIDGE_DEST="${root}/dest/usr/lib/howy/howy-config-bridge"
    BOOTSTRAP_DEST="${root}/dest/usr/share/howy/config.bootstrap.toml"
    ALPM_HOOK_DEST="${root}/dest/usr/share/libalpm/hooks/05-howy-config-stash.hook"
    SERVICE_DROPIN_DIR="${root}/dest/etc/systemd/system/howy.service.d"
    MODE1_MODELS_DIR="${root}/dest/etc/howy/models/mode1"
    CREDSTORE_DIR="${root}/dest/etc/credstore.encrypted"
    STATE_DIR="${root}/dest/var/lib/howy"
    SECURITY_STATE_DIR="${root}/dest/var/lib/howy/security-state"
    UNADOPTED_DIR="${root}/dest/var/lib/howy/security-state/unadopted"
    BRIDGE_STATE_DIR="${root}/dest/var/lib/howy/config-bridge"
    MARKER_DEST="${root}/dest/var/lib/howy-package-bootstrap.complete"
    CONFIG_EXPECTED_UID=$(id -u)
    CONFIG_EXPECTED_GID=$(id -g)
    SYSTEMD_SYSUSERS="mock-systemd-sysusers"
    SYSTEMCTL_LOG="${root}/systemctl.log"
    SYSUSERS_LOG="${root}/sysusers.log"
    TRANSACTION_LOG="${root}/transaction.log"
    SEEDED_HASHES="${root}/seeded-artifacts.sha256"
}

prepare_case() {
    local root="$1"

    set_case_paths "${root}"

    mkdir -p "${TARGET_DIR}" "${REPO_ROOT}/systemd" "${REPO_ROOT}/sysusers.d" "${REPO_ROOT}/packaging"
    printf 'new-howyd\n' > "${HOWYD_SRC}"
    printf 'new-howy\n' > "${HOWY_SRC}"
    printf 'new-pam\n' > "${PAM_SRC}"
    printf 'new-bridge\n' > "${BRIDGE_SRC}"
    printf '[Unit]\nConditionPathExists=!/var/lib/howy-security-transaction.guard\nConditionPathExists=/var/lib/howy-package-bootstrap.complete\n[Service]\nExecStart=/usr/bin/howyd\n' > "${REPO_ROOT}/systemd/howy.service"
    printf '[Unit]\nConditionPathExists=!/var/lib/howy-security-transaction.guard\nConditionPathExists=/var/lib/howy-package-bootstrap.complete\n[Socket]\nListenStream=/run/howy/howy.sock\n' > "${REPO_ROOT}/systemd/howy.socket"
    printf 'u! howy-ffmpeg - "Howy FFmpeg sandbox" - /usr/bin/nologin\n' > "${SYSUSERS_SRC}"
    printf '[ml]\nprovider = "cpu"\n' > "${REPO_ROOT}/howy.config"
    printf '[core]\ndisabled = true\n[security]\nembedding_mode = 1\nkey_epoch = 1\n[presence]\nmode = "confirm"\n' > "${BOOTSTRAP_SRC}"
    printf '[Trigger]\nOperation = Upgrade\nOperation = Remove\nType = Package\nTarget = howy-cpu-git\n[Action]\nWhen = PreTransaction\nExec = /usr/lib/howy/howy-config-bridge stash-release-n\nAbortOnFail\n' > "${ALPM_HOOK_SRC}"
    chmod 0755 "${HOWYD_SRC}" "${HOWY_SRC}" "${BRIDGE_SRC}"
    : > "${SYSTEMCTL_LOG}"
    : > "${SYSUSERS_LOG}"
    : > "${TRANSACTION_LOG}"

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
    PREWARM_STATUS="not-run"
    PREWARM_MESSAGE="mock prewarm not run"
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
    ARTIFACT_DESTINATIONS=()
    ARTIFACT_BACKUP_PRESENT=()
    MOCK_ACCOUNT_STATE="absent"
    MOCK_SYSUSERS_FAIL=0
    MOCK_SYSUSERS_RESULT="conforming"
    STOP_FAIL_UNIT=""
    START_FAIL_UNIT=""
    BRIDGE_CREATE_FAIL=0
    BRIDGE_FORCE_OCCUPIED_RACE=0
    BRIDGE_COMPLETE_FAIL=0
    DAEMON_RELOAD_COUNT=0
    FAIL_DAEMON_RELOAD_AT=0
    declare -gA MOCK_UNIT_STATE=(
        [howy.service]="missing"
        [howy.socket]="missing"
    )
    declare -gA MOCK_UNIT_ENABLED=(
        [howy.service]="disabled"
        [howy.socket]="disabled"
    )
}

seed_installed_artifacts() {
    mkdir -p \
        "$(dirname "${HOWYD_DEST}")" \
        "$(dirname "${PAM_DEST}")" \
        "$(dirname "${SERVICE_DEST}")" \
        "$(dirname "${SYSUSERS_DEST}")" \
        "$(dirname "${BRIDGE_DEST}")" \
        "$(dirname "${BOOTSTRAP_DEST}")" \
        "$(dirname "${ALPM_HOOK_DEST}")" \
        "${CONFIG_DIR}"
    printf 'old-howyd\n' > "${HOWYD_DEST}"
    printf 'old-howy\n' > "${HOWY_DEST}"
    printf 'old-pam\n' > "${PAM_DEST}"
    printf 'old-service\n' > "${SERVICE_DEST}"
    printf 'old-socket\n' > "${SOCKET_DEST}"
    printf 'old-config\n' > "${CONFIG_DEST}"
    printf 'old-sysusers\n' > "${SYSUSERS_DEST}"
    printf '#!/bin/sh\nexit 99\n' > "${BRIDGE_DEST}"
    printf 'old-bootstrap\n' > "${BOOTSTRAP_DEST}"
    printf 'old-hook\n' > "${ALPM_HOOK_DEST}"
    chmod 0600 "${SYSUSERS_DEST}"
    chmod 0755 "${BRIDGE_DEST}"
    sha256sum \
        "${HOWYD_DEST}" \
        "${HOWY_DEST}" \
        "${PAM_DEST}" \
        "${SERVICE_DEST}" \
        "${SOCKET_DEST}" \
        "${CONFIG_DEST}" \
        "${SYSUSERS_DEST}" \
        "${BRIDGE_DEST}" \
        "${BOOTSTRAP_DEST}" \
        "${ALPM_HOOK_DEST}" > "${SEEDED_HASHES}"
}

assert_seeded_artifacts_unchanged() {
    sha256sum --check --status "${SEEDED_HASHES}" \
        || fail "seeded runtime/sysusers hashes changed before commit"
    [ "$(<"${HOWYD_DEST}")" = "old-howyd" ] || fail "howyd changed before runtime commit"
    [ "$(<"${HOWY_DEST}")" = "old-howy" ] || fail "howy changed before runtime commit"
    [ "$(<"${PAM_DEST}")" = "old-pam" ] || fail "PAM changed before runtime commit"
    [ "$(<"${SERVICE_DEST}")" = "old-service" ] || fail "service changed before runtime commit"
    [ "$(<"${SOCKET_DEST}")" = "old-socket" ] || fail "socket changed before runtime commit"
    [ "$(<"${CONFIG_DEST}")" = "old-config" ] || fail "config changed before runtime commit"
    [ "$(<"${SYSUSERS_DEST}")" = "old-sysusers" ] || fail "sysusers definition was not restored"
    [ "$(stat -c '%a' "${SYSUSERS_DEST}")" = "600" ] || fail "sysusers mode was not restored"
}

require_root() { :; }
require_command() { :; }
build_release_artifacts() { :; }
run_install_prewarm() { PREWARM_MESSAGE="mock prewarm skipped"; }
print_next_steps() { :; }
userdel() { fail "installer attempted userdel"; }
groupdel() { fail "installer attempted groupdel"; }

run_bridge() {
    local binary="$1"
    local operation="$2"
    local directory
    : "${binary}"
    printf 'bridge:%s\n' "${operation}" >> "${TRANSACTION_LOG}"
    case "${operation}" in
        ensure-layout)
            for directory in \
                "${CONFIG_DIR}" "${MODELS_DIR}" "${MODE1_MODELS_DIR}" "${CREDSTORE_DIR}" \
                "${STATE_DIR}" "${SECURITY_STATE_DIR}" "${UNADOPTED_DIR}" "${BRIDGE_STATE_DIR}" \
                "${CACHE_DIR}" "${LOG_DIR}"; do
                mkdir -p "${directory}"
                chmod 0700 "${directory}"
            done
            for directory in \
                "${SERVICE_DROPIN_DIR}" "$(dirname "${BRIDGE_DEST}")" \
                "$(dirname "${PAM_DEST}")" "$(dirname "${SYSUSERS_DEST}")" \
                "$(dirname "${BOOTSTRAP_DEST}")" "$(dirname "${ALPM_HOOK_DEST}")"; do
                mkdir -p "${directory}"
                chmod 0755 "${directory}"
            done
            ;;
        create-if-absent)
            [ "${BRIDGE_CREATE_FAIL}" -eq 0 ] || return 1
            if [ "${BRIDGE_FORCE_OCCUPIED_RACE}" -eq 1 ] && [ ! -e "${CONFIG_DEST}" ]; then
                printf 'racer\n' > "${CONFIG_DEST}"
                chmod 0600 "${CONFIG_DEST}"
            fi
            if [ -e "${CONFIG_DEST}" ] || [ -L "${CONFIG_DEST}" ]; then
                printf 'HOWY_CONFIG_RESULT=Occupied\n'
            else
                command install -m 0600 "${BOOTSTRAP_SRC}" "${CONFIG_DEST}"
                printf 'HOWY_CONFIG_RESULT=Created\n'
            fi
            ;;
        complete-local-install)
            [ "${BRIDGE_COMPLETE_FAIL}" -eq 0 ] || return 1
            [ -f "${CONFIG_DEST}" ] && [ ! -L "${CONFIG_DEST}" ] || return 1
            printf 'complete\n' > "${MARKER_DEST}"
            chmod 0600 "${MARKER_DEST}"
            printf 'HOWY_LOCAL_RESULT=Complete\n'
            ;;
        stash-release-n)
            rm -f -- "${MARKER_DEST}"
            printf 'HOWY_STASH_RESULT=Created\n'
            ;;
        *)
            fail "unexpected bridge operation: ${operation}"
            ;;
    esac
}

install() {
    local -a filtered=()
    while [ "$#" -gt 0 ]; do
        case "$1" in
            -o|-g)
                shift 2
                ;;
            *)
                filtered+=("$1")
                shift
                ;;
        esac
    done
    command install "${filtered[@]}"
}

preflight_ffmpeg_account() {
    printf 'preflight:%s\n' "${MOCK_ACCOUNT_STATE}" >> "${SYSUSERS_LOG}"
    printf 'preflight:%s\n' "${MOCK_ACCOUNT_STATE}" >> "${TRANSACTION_LOG}"
    case "${MOCK_ACCOUNT_STATE}" in
        absent|conforming)
            ;;
        *)
            die "Preexisting howy-ffmpeg account/group is nonconforming; refusing silent adoption"
            ;;
    esac
}

run_sysusers_definition() {
    printf 'run:%s\n' "${SYSUSERS_DEST}" >> "${SYSUSERS_LOG}"
    printf 'sysusers:run\n' >> "${TRANSACTION_LOG}"
    [ "${MOCK_SYSUSERS_FAIL}" -eq 0 ] || return 1
    if [ "${MOCK_ACCOUNT_STATE}" = "absent" ]; then
        MOCK_ACCOUNT_STATE="${MOCK_SYSUSERS_RESULT}"
    fi
    printf 'account-state:%s\n' "${MOCK_ACCOUNT_STATE}" >> "${TRANSACTION_LOG}"
}

validate_installed_ffmpeg_account() {
    printf 'validate:%s\n' "${MOCK_ACCOUNT_STATE}" >> "${SYSUSERS_LOG}"
    printf 'sysusers:validate:%s\n' "${MOCK_ACCOUNT_STATE}" >> "${TRANSACTION_LOG}"
    [ "${MOCK_ACCOUNT_STATE}" = "conforming" ] \
        || die "Installed howy-ffmpeg account/group does not match the exact policy"
}

verify_sysusers_metadata() {
    [ "$(stat -c '%a' "${SYSUSERS_DEST}")" = "644" ] \
        || die "mock sysusers definition mode mismatch"
}

systemctl() {
    local unit
    local fragment
    local property=""
    local value_only=0
    local argument
    printf '%s\n' "$*" >> "${SYSTEMCTL_LOG}"
    printf 'systemctl:%s\n' "$*" >> "${TRANSACTION_LOG}"
    case "$1" in
        is-active)
            [ "${MOCK_UNIT_STATE[$3]:-missing}" = "active" ]
            ;;
        is-enabled)
            [ "${MOCK_UNIT_ENABLED[$3]:-disabled}" = "enabled" ]
            ;;
        stop)
            if [ "$2" = "${STOP_FAIL_UNIT}" ]; then
                return 1
            fi
            MOCK_UNIT_STATE[$2]="inactive"
            ;;
        start)
            if [ "$2" = "${START_FAIL_UNIT}" ]; then
                return 1
            fi
            MOCK_UNIT_STATE[$2]="active"
            ;;
        daemon-reload)
            DAEMON_RELOAD_COUNT=$((DAEMON_RELOAD_COUNT + 1))
            if [ "${FAIL_DAEMON_RELOAD_AT}" -eq "${DAEMON_RELOAD_COUNT}" ]; then
                return 1
            fi
            ;;
        show)
            unit="${!#}"
            case "${unit}" in
                howy.service) fragment="${SERVICE_DEST}" ;;
                howy.socket) fragment="${SOCKET_DEST}" ;;
                *) fail "unexpected show unit: ${unit}" ;;
            esac
            for argument in "$@"; do
                case "${argument}" in
                    --property=*) property=${argument#--property=} ;;
                    --value) value_only=1 ;;
                esac
            done
            if [ "${value_only}" -eq 1 ]; then
                case "${property}" in
                    NeedDaemonReload) printf 'no\n' ;;
                    FragmentPath) printf '%s\n' "${fragment}" ;;
                    Conditions)
                        printf 'ConditionPathExists=!/var/lib/howy-security-transaction.guard ConditionPathExists=/var/lib/howy-package-bootstrap.complete\n'
                        ;;
                    *) fail "unexpected value property: ${property}" ;;
                esac
            elif [ -e "${fragment}" ]; then
                printf 'LoadState=loaded\nFragmentPath=%s\nFragmentSHA256=%s\nDropInPaths=\nConditions=ConditionPathExists=!/var/lib/howy-security-transaction.guard ConditionPathExists=/var/lib/howy-package-bootstrap.complete\n' \
                    "${fragment}" "$(sha256sum "${fragment}" | cut -d' ' -f1)"
            else
                printf 'LoadState=not-found\nFragmentPath=\nFragmentSHA256=absent\nDropInPaths=\nConditions=\n'
            fi
            ;;
        *)
            fail "unexpected systemctl invocation: $*"
            ;;
    esac
}

assert_exact_install() {
    cmp -s "${HOWYD_SRC}" "${HOWYD_DEST}" || fail "howyd was not installed exactly"
    cmp -s "${HOWY_SRC}" "${HOWY_DEST}" || fail "howy was not installed exactly"
    cmp -s "${PAM_SRC}" "${PAM_DEST}" || fail "PAM module was not installed exactly"
    cmp -s "${BRIDGE_SRC}" "${BRIDGE_DEST}" || fail "bridge helper mismatch"
    cmp -s "${BOOTSTRAP_SRC}" "${BOOTSTRAP_DEST}" || fail "bootstrap payload mismatch"
    cmp -s "${ALPM_HOOK_SRC}" "${ALPM_HOOK_DEST}" || fail "ALPM hook mismatch"
    cmp -s "${REPO_ROOT}/systemd/howy.service" "${SERVICE_DEST}" || fail "service unit mismatch"
    cmp -s "${REPO_ROOT}/systemd/howy.socket" "${SOCKET_DEST}" || fail "socket unit mismatch"
    cmp -s "${SYSUSERS_SRC}" "${SYSUSERS_DEST}" || fail "sysusers definition mismatch"
}

test_first_install() {
    local root
    local log
    local transaction
    root=$(mktemp -d)
    (
        prepare_case "${root}"
        main </dev/null
    ) >"${root}/output" 2>&1 || fail "first install failed"
    set_case_paths "${root}"
    assert_exact_install
    cmp -s "${BOOTSTRAP_SRC}" "${CONFIG_DEST}" || fail "fresh bootstrap config mismatch"
    [ "$(stat -c '%a' "${CONFIG_DEST}")" = "600" ] || fail "fresh config mode mismatch"
    [ -e "${MARKER_DEST}" ] || fail "fresh install did not commit bootstrap marker"
    log=$(<"${SYSTEMCTL_LOG}")
    assert_not_contains "${log}" "stop howy.service"
    assert_not_contains "${log}" "stop howy.socket"
    assert_contains "${log}" "daemon-reload"
    assert_contains "${log}" "is-enabled --quiet howy.service"
    assert_contains "${log}" "is-enabled --quiet howy.socket"
    log=$(<"${SYSUSERS_LOG}")
    assert_contains "${log}" "preflight:absent"
    assert_contains "${log}" "run:${SYSUSERS_DEST}"
    assert_contains "${log}" "validate:conforming"
    transaction=$(<"${TRANSACTION_LOG}")
    assert_order "${transaction}" "sysusers:validate:conforming" "systemctl:is-active --quiet howy.service"
    rm -rf "${root}"
}

test_existing_config_has_no_prompt_and_is_preserved() {
    local root
    local log
    root=$(mktemp -d)
    (
        prepare_case "${root}"
        seed_installed_artifacts
        main <<'EOF'
y
y
y
y
y
EOF
    ) >"${root}/output" 2>&1 || fail "reinstall with existing config failed"
    set_case_paths "${root}"
    assert_exact_install
    [ "$(<"${CONFIG_DEST}")" = "old-config" ] || fail "existing config was overwritten"
    [ -e "${MARKER_DEST}" ] || fail "preserved config was not marked complete"
    log=$(<"${SYSTEMCTL_LOG}")
    assert_contains "$(<"${TRANSACTION_LOG}")" "bridge:create-if-absent"
    assert_not_contains "$(<"${root}/output")" "${CONFIG_DEST} already exists. Overwrite?"
    assert_contains "${log}" "daemon-reload"
    rm -rf "${root}"
}

test_existing_config_symlink_is_preserved_but_not_marked_complete() {
    local root
    root=$(mktemp -d)
    if (
        prepare_case "${root}"
        seed_installed_artifacts
        rm -f "${CONFIG_DEST}"
        ln -s "administrator-target" "${CONFIG_DEST}"
        main <<'EOF'
y
y
y
y
y
EOF
    ) >"${root}/output" 2>&1; then
        fail "symlinked config unexpectedly completed installation"
    fi
    set_case_paths "${root}"
    [ -L "${CONFIG_DEST}" ] || fail "installer replaced config symlink"
    [ "$(readlink "${CONFIG_DEST}")" = "administrator-target" ] \
        || fail "installer changed config symlink"
    [ ! -e "${MARKER_DEST}" ] || fail "installer marked an unsafe config complete"
    rm -rf "${root}"
}

test_fresh_bridge_failure_rolls_back_artifacts_without_touching_config() {
    local root
    root=$(mktemp -d)
    if (
        prepare_case "${root}"
        seed_installed_artifacts
        rm -f "${CONFIG_DEST}"
        BRIDGE_CREATE_FAIL=1
        MOCK_UNIT_STATE[howy.service]="active"
        MOCK_UNIT_STATE[howy.socket]="active"
        main <<'EOF'
y
y
y
y
y
EOF
    ) >"${root}/output" 2>&1; then
        fail "bridge creation failure unexpectedly succeeded"
    fi
    set_case_paths "${root}"
    [ "$(<"${HOWYD_DEST}")" = "old-howyd" ] || fail "failure did not restore howyd"
    [ "$(<"${HOWY_DEST}")" = "old-howy" ] || fail "failure did not restore howy"
    grep -q 'exit 99' "${BRIDGE_DEST}" || fail "failure did not restore bridge"
    [ "$(<"${BOOTSTRAP_DEST}")" = "old-bootstrap" ] || fail "failure did not restore bootstrap"
    [ "$(<"${ALPM_HOOK_DEST}")" = "old-hook" ] || fail "failure did not restore hook"
    [ ! -e "${CONFIG_DEST}" ] || fail "artifact rollback created or restored config"
    rm -rf "${root}"
}

test_unexpected_config_occupancy_race_fails_closed_without_ownership() {
    local root
    root=$(mktemp -d)
    if (
        prepare_case "${root}"
        BRIDGE_FORCE_OCCUPIED_RACE=1
        main </dev/null
    ) >"${root}/output" 2>&1; then
        fail "unexpected occupancy race completed installation"
    fi
    set_case_paths "${root}"
    [ "$(<"${CONFIG_DEST}")" = "racer" ] || fail "occupancy race object was changed"
    [ ! -e "${MARKER_DEST}" ] || fail "occupancy race received a bootstrap marker"
    assert_contains "$(<"${root}/output")" "became occupied after the initial snapshot"
    rm -rf "${root}"
}

test_migrate_flag_is_explicitly_unsupported_before_side_effects() {
    local root
    root=$(mktemp -d)
    if (
        prepare_case "${root}"
        main --migrate
    ) >"${root}/output" 2>&1; then
        fail "unsupported migrate flag unexpectedly succeeded"
    fi
    assert_contains "$(<"${root}/output")" "sudo howy security provision --mode 1"
    [ ! -e "${root}/dest" ] || fail "unsupported migrate flag had install side effects"
    rm -rf "${root}"
}

test_successful_upgrade_restores_active_state() {
    local root
    local log
    local transaction
    root=$(mktemp -d)
    (
        prepare_case "${root}"
        seed_installed_artifacts
        MOCK_UNIT_STATE[howy.service]="active"
        MOCK_UNIT_STATE[howy.socket]="active"
        MOCK_UNIT_ENABLED[howy.service]="enabled"
        MOCK_UNIT_ENABLED[howy.socket]="enabled"
        main <<'EOF'
y
y
y
y
y
EOF
    ) >"${root}/output" 2>&1 || fail "upgrade failed"
    set_case_paths "${root}"
    assert_exact_install
    [ "$(<"${CONFIG_DEST}")" = "old-config" ] || fail "upgrade replaced config"
    log=$(<"${SYSTEMCTL_LOG}")
    assert_contains "${log}" "stop howy.service"
    assert_contains "${log}" "stop howy.socket"
    assert_order "${log}" "stop howy.socket" "stop howy.service"
    assert_contains "${log}" "start howy.socket"
    assert_contains "${log}" "start howy.service"
    assert_contains "${log}" "daemon-reload"
    assert_no_enablement_changes "${log}"
    transaction=$(<"${TRANSACTION_LOG}")
    assert_order "${transaction}" "sysusers:validate:conforming" "systemctl:is-active --quiet howy.service"
    rm -rf "${root}"
}

test_stop_failure_prevents_replacement() {
    local root
    local log
    root=$(mktemp -d)
    if (
        prepare_case "${root}"
        seed_installed_artifacts
        MOCK_UNIT_STATE[howy.service]="active"
        MOCK_UNIT_STATE[howy.socket]="inactive"
        MOCK_UNIT_ENABLED[howy.service]="enabled"
        MOCK_UNIT_ENABLED[howy.socket]="enabled"
        STOP_FAIL_UNIT="howy.service"
        main <<'EOF'
y
y
y
y
y
EOF
    ) >"${root}/output" 2>&1; then
        fail "stop failure unexpectedly succeeded"
    fi
    set_case_paths "${root}"
    assert_seeded_artifacts_unchanged
    log=$(<"${SYSTEMCTL_LOG}")
    assert_contains "${log}" "stop howy.service"
    assert_not_contains "${log}" "start howy.service"
    assert_not_contains "${log}" "daemon-reload"
    assert_no_enablement_changes "${log}"
    rm -rf "${root}"
}

test_partial_stop_failure_restarts_only_unit_stopped_by_this_install() {
    local root
    local log
    root=$(mktemp -d)
    if (
        prepare_case "${root}"
        seed_installed_artifacts
        MOCK_UNIT_STATE[howy.service]="active"
        MOCK_UNIT_STATE[howy.socket]="active"
        MOCK_UNIT_ENABLED[howy.service]="enabled"
        MOCK_UNIT_ENABLED[howy.socket]="enabled"
        STOP_FAIL_UNIT="howy.service"
        main <<'EOF'
y
y
y
y
y
EOF
    ) >"${root}/output" 2>&1; then
        fail "partial stop failure unexpectedly succeeded"
    fi
    set_case_paths "${root}"
    assert_seeded_artifacts_unchanged
    log=$(<"${SYSTEMCTL_LOG}")
    assert_contains "${log}" "stop howy.service"
    assert_contains "${log}" "stop howy.socket"
    assert_contains "${log}" "start howy.socket"
    assert_not_contains "${log}" "start howy.service"
    assert_not_contains "${log}" "daemon-reload"
    assert_no_enablement_changes "${log}"
    rm -rf "${root}"
}

test_conforming_preexisting_account_and_reinstall_are_idempotent() {
    local root
    local log
    local transaction
    root=$(mktemp -d)
    (
        prepare_case "${root}"
        seed_installed_artifacts
        MOCK_ACCOUNT_STATE="conforming"
        MOCK_UNIT_STATE[howy.service]="active"
        MOCK_UNIT_STATE[howy.socket]="active"
        MOCK_UNIT_ENABLED[howy.service]="enabled"
        MOCK_UNIT_ENABLED[howy.socket]="enabled"
        main <<'EOF'
y
y
y
y
y
EOF
    ) >"${root}/output" 2>&1 || fail "conforming reinstall failed"
    set_case_paths "${root}"
    assert_exact_install
    [ "$(<"${CONFIG_DEST}")" = "old-config" ] || fail "reinstall replaced config"
    log=$(<"${SYSUSERS_LOG}")
    assert_contains "${log}" "preflight:conforming"
    assert_contains "${log}" "validate:conforming"
    transaction=$(<"${TRANSACTION_LOG}")
    assert_order "${transaction}" "sysusers:validate:conforming" "systemctl:is-active --quiet howy.service"
    log=$(<"${SYSTEMCTL_LOG}")
    assert_no_enablement_changes "${log}"
    rm -rf "${root}"
}

test_post_reload_failure_restores_manager_policy_before_restart() {
    local root
    local log
    root=$(mktemp -d)
    if (
        prepare_case "${root}"
        seed_installed_artifacts
        MOCK_UNIT_STATE[howy.service]="active"
        MOCK_UNIT_STATE[howy.socket]="active"
        BRIDGE_COMPLETE_FAIL=1
        main <<'EOF'
y
y
y
y
y
EOF
    ) >"${root}/output" 2>&1; then
        fail "post-reload completion failure unexpectedly succeeded"
    fi
    set_case_paths "${root}"
    assert_seeded_artifacts_unchanged
    log=$(<"${SYSTEMCTL_LOG}")
    [ "$(grep -c '^daemon-reload$' "${SYSTEMCTL_LOG}")" -eq 2 ] \
        || fail "rollback did not reload restored unit definitions exactly once"
    assert_order "${log}" "daemon-reload" "start howy.socket"
    assert_contains "${log}" "start howy.service"
    rm -rf "${root}"
}

test_failed_rollback_reload_retains_units_stopped() {
    local root
    local log
    root=$(mktemp -d)
    if (
        prepare_case "${root}"
        seed_installed_artifacts
        MOCK_UNIT_STATE[howy.service]="active"
        MOCK_UNIT_STATE[howy.socket]="active"
        BRIDGE_COMPLETE_FAIL=1
        FAIL_DAEMON_RELOAD_AT=2
        main <<'EOF'
y
y
y
y
y
EOF
    ) >"${root}/output" 2>&1; then
        fail "rollback reload failure unexpectedly succeeded"
    fi
    set_case_paths "${root}"
    log=$(<"${SYSTEMCTL_LOG}")
    assert_not_contains "${log}" "start howy.socket"
    assert_not_contains "${log}" "start howy.service"
    assert_contains "$(<"${root}/output")" "units remain stopped"
    rm -rf "${root}"
}

test_conflicting_accounts_fail_before_install() {
    local state
    local root
    local log
    for state in conflict-uid conflict-gid conflict-shell conflict-lock conflict-group; do
        root=$(mktemp -d)
        if (
            prepare_case "${root}"
            seed_installed_artifacts
            MOCK_ACCOUNT_STATE="${state}"
            MOCK_UNIT_STATE[howy.service]="active"
            MOCK_UNIT_STATE[howy.socket]="active"
            MOCK_UNIT_ENABLED[howy.service]="enabled"
            MOCK_UNIT_ENABLED[howy.socket]="enabled"
            main </dev/null
        ) >"${root}/output" 2>&1; then
            fail "${state} account unexpectedly installed"
        fi
        set_case_paths "${root}"
        assert_seeded_artifacts_unchanged
        log=$(<"${SYSTEMCTL_LOG}")
        [ -z "${log}" ] || fail "${state} changed runtime state: ${log}"
        log=$(<"${SYSUSERS_LOG}")
        assert_contains "${log}" "preflight:${state}"
        assert_not_contains "${log}" "run:"
        rm -rf "${root}"
    done
}

test_sysusers_failure_rolls_back_definition() {
    local root
    root=$(mktemp -d)
    if (
        prepare_case "${root}"
        seed_installed_artifacts
        MOCK_ACCOUNT_STATE="absent"
        MOCK_SYSUSERS_FAIL=1
        MOCK_UNIT_STATE[howy.service]="active"
        MOCK_UNIT_STATE[howy.socket]="active"
        MOCK_UNIT_ENABLED[howy.service]="enabled"
        MOCK_UNIT_ENABLED[howy.socket]="enabled"
        main <<'EOF'
y
y
y
y
y
EOF
    ) >"${root}/output" 2>&1; then
        fail "sysusers failure unexpectedly succeeded"
    fi
    set_case_paths "${root}"
    assert_seeded_artifacts_unchanged
    [ ! -s "${SYSTEMCTL_LOG}" ] || fail "sysusers failure touched unit state"
    rm -rf "${root}"
}

test_fresh_sysusers_failure_removes_new_definition_without_runtime_touch() {
    local root
    root=$(mktemp -d)
    if (
        prepare_case "${root}"
        seed_installed_artifacts
        rm -f "${SYSUSERS_DEST}"
        sha256sum \
            "${HOWYD_DEST}" \
            "${HOWY_DEST}" \
            "${PAM_DEST}" \
            "${SERVICE_DEST}" \
            "${SOCKET_DEST}" \
            "${CONFIG_DEST}" > "${SEEDED_HASHES}"
        MOCK_ACCOUNT_STATE="absent"
        MOCK_SYSUSERS_FAIL=1
        MOCK_UNIT_STATE[howy.service]="active"
        MOCK_UNIT_STATE[howy.socket]="active"
        MOCK_UNIT_ENABLED[howy.service]="enabled"
        MOCK_UNIT_ENABLED[howy.socket]="enabled"
        main <<'EOF'
y
y
y
y
y
EOF
    ) >"${root}/output" 2>&1; then
        fail "fresh sysusers failure unexpectedly succeeded"
    fi
    set_case_paths "${root}"
    sha256sum --check --status "${SEEDED_HASHES}" \
        || fail "fresh sysusers failure changed runtime artifact hashes"
    [ ! -e "${SYSUSERS_DEST}" ] || fail "fresh failed sysusers definition was not removed"
    [ ! -s "${SYSTEMCTL_LOG}" ] || fail "fresh sysusers failure touched unit state"
    rm -rf "${root}"
}

test_post_creation_validation_failure_rolls_back_definition_without_account_delete() {
    local root
    local log
    root=$(mktemp -d)
    if (
        prepare_case "${root}"
        seed_installed_artifacts
        MOCK_ACCOUNT_STATE="absent"
        MOCK_SYSUSERS_RESULT="conflict-lock"
        MOCK_UNIT_STATE[howy.service]="active"
        MOCK_UNIT_STATE[howy.socket]="active"
        MOCK_UNIT_ENABLED[howy.service]="enabled"
        MOCK_UNIT_ENABLED[howy.socket]="enabled"
        main <<'EOF'
y
y
y
y
y
EOF
    ) >"${root}/output" 2>&1; then
        fail "post-creation validation failure unexpectedly succeeded"
    fi
    set_case_paths "${root}"
    assert_seeded_artifacts_unchanged
    [ ! -s "${SYSTEMCTL_LOG}" ] || fail "post-validation failure touched unit state"
    log=$(<"${SYSUSERS_LOG}")
    assert_contains "${log}" "validate:conflict-lock"
    assert_not_contains "${log}" "userdel"
    assert_not_contains "${log}" "groupdel"
    log=$(<"${TRANSACTION_LOG}")
    assert_contains "${log}" "account-state:conflict-lock"
    assert_not_contains "${log}" "userdel"
    assert_not_contains "${log}" "groupdel"
    rm -rf "${root}"
}

test_uninstall_removes_only_definition_not_account() {
    local root
    root=$(mktemp -d)
    (
        set_case_paths "${root}"
        mkdir -p "$(dirname "${SYSUSERS_DEST}")"
        printf 'installed\n' > "${SYSUSERS_DEST}"
        mkdir -p "$(dirname "${BRIDGE_DEST}")" "$(dirname "${BOOTSTRAP_DEST}")" "$(dirname "${ALPM_HOOK_DEST}")"
        printf 'installed\n' > "${BRIDGE_DEST}"
        printf 'installed\n' > "${BOOTSTRAP_DEST}"
        printf 'installed\n' > "${ALPM_HOOK_DEST}"
        mkdir -p "${BRIDGE_STATE_DIR}" "${MODELS_DIR}"
        printf 'retain\n' > "${BRIDGE_STATE_DIR}/manifest-v1.json"
        printf 'retain\n' > "${CONFIG_DEST}"
        printf 'complete\n' > "${MARKER_DEST}"
        chmod 0755 "${BRIDGE_DEST}"
        printf 'account-must-remain\n' > "${root}/account-state"
        # shellcheck source=../uninstall-local.sh
        source "${UNINSTALL_SCRIPT}"
        require_root() { :; }
        systemctl() {
            if [ "$1" = "is-active" ]; then
                return 1
            fi
            return 0
        }
        run_bridge() {
            [ "$2" = "stash-release-n" ] || fail "unexpected uninstall bridge command"
            rm -f -- "${MARKER_DEST}"
        }
        userdel() { fail "uninstall attempted userdel"; }
        groupdel() { fail "uninstall attempted groupdel"; }
        uninstall_main
        [ ! -e "${SYSUSERS_DEST}" ] || fail "uninstall retained sysusers definition"
        [ ! -e "${BRIDGE_DEST}" ] || fail "uninstall retained bridge binary"
        [ ! -e "${BOOTSTRAP_DEST}" ] || fail "uninstall retained bootstrap payload"
        [ ! -e "${ALPM_HOOK_DEST}" ] || fail "uninstall retained ALPM hook"
        [ -e "${CONFIG_DEST}" ] || fail "uninstall removed config"
        [ -e "${BRIDGE_STATE_DIR}/manifest-v1.json" ] || fail "uninstall removed bridge stash"
        [ ! -e "${MARKER_DEST}" ] || fail "uninstall retained bootstrap marker"
        [ "$(<"${root}/account-state")" = "account-must-remain" ] \
            || fail "uninstall changed account state"
    ) >"${root}/output" 2>&1 || fail "mock uninstall failed"
    rm -rf "${root}"
}

test_pkgbuild_installs_release_n_bridge_for_all_variants() {
    local pkgbuild
    pkgbuild=$(<"$(dirname "${TEST_DIR}")/../PKGBUILD")
    assert_contains "${pkgbuild}" 'sysusers.d/howy.conf "${pkgdir}/usr/lib/sysusers.d/howy.conf"'
    assert_contains "${pkgbuild}" 'packaging/config-release-n-legacy.toml "${pkgdir}/etc/howy/config.toml"'
    assert_contains "${pkgbuild}" 'howy-config-bridge" "${pkgdir}/usr/lib/howy/howy-config-bridge"'
    [ "$(grep -c '_package_common "${pkgname}"' "$(dirname "${TEST_DIR}")/../PKGBUILD")" -eq 3 ] \
        || fail "every split package must use the sysusers-installing common path"
    [ "$(grep -c "'systemd>=261'" "$(dirname "${TEST_DIR}")/../PKGBUILD")" -eq 4 ] \
        || fail "build and every split package must require systemd>=261"
    [ "$(grep -c 'backup=(' "$(dirname "${TEST_DIR}")/../PKGBUILD")" -eq 3 ] \
        || fail "every split package must retain config backup ownership"
    [ "$(grep -c 'install=howy.install' "$(dirname "${TEST_DIR}")/../PKGBUILD")" -eq 3 ] \
        || fail "every split package must use howy.install"
}

test_first_install
test_existing_config_has_no_prompt_and_is_preserved
test_existing_config_symlink_is_preserved_but_not_marked_complete
test_successful_upgrade_restores_active_state
test_fresh_bridge_failure_rolls_back_artifacts_without_touching_config
test_unexpected_config_occupancy_race_fails_closed_without_ownership
test_migrate_flag_is_explicitly_unsupported_before_side_effects
test_stop_failure_prevents_replacement
test_partial_stop_failure_restarts_only_unit_stopped_by_this_install
test_conforming_preexisting_account_and_reinstall_are_idempotent
test_post_reload_failure_restores_manager_policy_before_restart
test_failed_rollback_reload_retains_units_stopped
test_conflicting_accounts_fail_before_install
test_sysusers_failure_rolls_back_definition
test_fresh_sysusers_failure_removes_new_definition_without_runtime_touch
test_post_creation_validation_failure_rolls_back_definition_without_account_delete
test_uninstall_removes_only_definition_not_account
test_pkgbuild_installs_release_n_bridge_for_all_variants
printf 'install-local mock tests: 18 passed\n'
