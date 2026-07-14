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
    SYSUSERS_SRC="${REPO_ROOT}/sysusers.d/howy.conf"

    HOWYD_DEST="${root}/dest/usr/bin/howyd"
    HOWY_DEST="${root}/dest/usr/bin/howy"
    PAM_DEST="${root}/dest/lib/security/pam_howy.so"
    SERVICE_DEST="${root}/dest/etc/systemd/system/howy.service"
    SOCKET_DEST="${root}/dest/etc/systemd/system/howy.socket"
    CONFIG_DEST="${root}/dest/etc/howy/config.toml"
    CONFIG_DIR="${root}/dest/etc/howy"
    MODELS_DIR="${root}/dest/etc/howy/models"
    CACHE_DIR="${root}/dest/var/cache/howy"
    LOG_DIR="${root}/dest/var/log/howy"
    SYSUSERS_DEST="${root}/dest/usr/lib/sysusers.d/howy.conf"
    SYSTEMD_SYSUSERS="mock-systemd-sysusers"
    SYSTEMCTL_LOG="${root}/systemctl.log"
    SYSUSERS_LOG="${root}/sysusers.log"
    TRANSACTION_LOG="${root}/transaction.log"
    SEEDED_HASHES="${root}/seeded-artifacts.sha256"
}

prepare_case() {
    local root="$1"

    set_case_paths "${root}"

    mkdir -p "${TARGET_DIR}" "${REPO_ROOT}/systemd" "${REPO_ROOT}/sysusers.d"
    printf 'new-howyd\n' > "${HOWYD_SRC}"
    printf 'new-howy\n' > "${HOWY_SRC}"
    printf 'new-pam\n' > "${PAM_SRC}"
    printf 'new-service\n' > "${REPO_ROOT}/systemd/howy.service"
    printf 'new-socket\n' > "${REPO_ROOT}/systemd/howy.socket"
    printf 'u! howy-ffmpeg - "Howy FFmpeg sandbox" - /usr/bin/nologin\n' > "${SYSUSERS_SRC}"
    printf '[ml]\nprovider = "cpu"\n' > "${REPO_ROOT}/howy.config"
    chmod 0755 "${HOWYD_SRC}" "${HOWY_SRC}"
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
    PREWARM_STATUS="not-run"
    PREWARM_MESSAGE="mock prewarm not run"
    SYSUSERS_BACKUP_DIR=""
    SYSUSERS_DEST_EXISTED=0
    SYSUSERS_FILE_TOUCHED=0
    SYSUSERS_TEMP=""
    INSTALL_COMMITTED=0
    MOCK_ACCOUNT_STATE="absent"
    MOCK_SYSUSERS_FAIL=0
    MOCK_SYSUSERS_RESULT="conforming"
    STOP_FAIL_UNIT=""
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
        "${CONFIG_DIR}"
    printf 'old-howyd\n' > "${HOWYD_DEST}"
    printf 'old-howy\n' > "${HOWY_DEST}"
    printf 'old-pam\n' > "${PAM_DEST}"
    printf 'old-service\n' > "${SERVICE_DEST}"
    printf 'old-socket\n' > "${SOCKET_DEST}"
    printf 'old-config\n' > "${CONFIG_DEST}"
    printf 'old-sysusers\n' > "${SYSUSERS_DEST}"
    chmod 0600 "${SYSUSERS_DEST}"
    sha256sum \
        "${HOWYD_DEST}" \
        "${HOWY_DEST}" \
        "${PAM_DEST}" \
        "${SERVICE_DEST}" \
        "${SOCKET_DEST}" \
        "${CONFIG_DEST}" \
        "${SYSUSERS_DEST}" > "${SEEDED_HASHES}"
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
            MOCK_UNIT_STATE[$2]="active"
            ;;
        daemon-reload)
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
    cmp -s "${REPO_ROOT}/systemd/howy.service" "${SERVICE_DEST}" || fail "service unit mismatch"
    cmp -s "${REPO_ROOT}/systemd/howy.socket" "${SOCKET_DEST}" || fail "socket unit mismatch"
    cmp -s "${REPO_ROOT}/howy.config" "${CONFIG_DEST}" || fail "config mismatch"
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

test_declined_config_precedes_replacement() {
    local root
    local log
    root=$(mktemp -d)
    if (
        prepare_case "${root}"
        seed_installed_artifacts
        main <<'EOF'
y
y
y
y
y
n
EOF
    ) >"${root}/output" 2>&1; then
        fail "declined config overwrite unexpectedly succeeded"
    fi
    set_case_paths "${root}"
    assert_seeded_artifacts_unchanged
    log=$(<"${SYSTEMCTL_LOG}")
    [ -z "${log}" ] || fail "runtime state changed before config decision: ${log}"
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
y
EOF
    ) >"${root}/output" 2>&1 || fail "upgrade failed"
    set_case_paths "${root}"
    assert_exact_install
    log=$(<"${SYSTEMCTL_LOG}")
    assert_contains "${log}" "stop howy.service"
    assert_contains "${log}" "stop howy.socket"
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
        STOP_FAIL_UNIT="howy.socket"
        main <<'EOF'
y
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
    assert_contains "${log}" "start howy.service"
    assert_not_contains "${log}" "start howy.socket"
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
y
EOF
    ) >"${root}/output" 2>&1 || fail "conforming reinstall failed"
    set_case_paths "${root}"
    assert_exact_install
    log=$(<"${SYSUSERS_LOG}")
    assert_contains "${log}" "preflight:conforming"
    assert_contains "${log}" "validate:conforming"
    transaction=$(<"${TRANSACTION_LOG}")
    assert_order "${transaction}" "sysusers:validate:conforming" "systemctl:is-active --quiet howy.service"
    log=$(<"${SYSTEMCTL_LOG}")
    assert_no_enablement_changes "${log}"
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
        printf 'account-must-remain\n' > "${root}/account-state"
        # shellcheck source=../uninstall-local.sh
        source "${UNINSTALL_SCRIPT}"
        require_root() { :; }
        systemctl() { :; }
        userdel() { fail "uninstall attempted userdel"; }
        groupdel() { fail "uninstall attempted groupdel"; }
        uninstall_main
        [ ! -e "${SYSUSERS_DEST}" ] || fail "uninstall retained sysusers definition"
        [ "$(<"${root}/account-state")" = "account-must-remain" ] \
            || fail "uninstall changed account state"
    ) >"${root}/output" 2>&1 || fail "mock uninstall failed"
    rm -rf "${root}"
}

test_pkgbuild_installs_sysusers_for_all_variants() {
    local pkgbuild
    pkgbuild=$(<"$(dirname "${TEST_DIR}")/../PKGBUILD")
    assert_contains "${pkgbuild}" 'sysusers.d/howy.conf "${pkgdir}/usr/lib/sysusers.d/howy.conf"'
    [ "$(grep -c '_package_common "${pkgname}"' "$(dirname "${TEST_DIR}")/../PKGBUILD")" -eq 3 ] \
        || fail "every split package must use the sysusers-installing common path"
    [ "$(grep -c "'systemd>=257'" "$(dirname "${TEST_DIR}")/../PKGBUILD")" -eq 4 ] \
        || fail "build and every split package must require systemd>=257"
}

test_first_install
test_declined_config_precedes_replacement
test_successful_upgrade_restores_active_state
test_stop_failure_prevents_replacement
test_partial_stop_failure_restarts_only_unit_stopped_by_this_install
test_conforming_preexisting_account_and_reinstall_are_idempotent
test_conflicting_accounts_fail_before_install
test_sysusers_failure_rolls_back_definition
test_fresh_sysusers_failure_removes_new_definition_without_runtime_touch
test_post_creation_validation_failure_rolls_back_definition_without_account_delete
test_uninstall_removes_only_definition_not_account
test_pkgbuild_installs_sysusers_for_all_variants
printf 'install-local mock tests: 12 passed\n'
