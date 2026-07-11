#!/bin/bash

set -euo pipefail

TEST_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INSTALL_SCRIPT=$(dirname "${TEST_DIR}")/install-local.sh

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

set_case_paths() {
    local root="$1"

    REPO_ROOT="${root}/repo"
    TARGET_DIR="${REPO_ROOT}/target/release"
    HOWYD_SRC="${TARGET_DIR}/howyd"
    HOWY_SRC="${TARGET_DIR}/howy"
    PAM_SRC="${TARGET_DIR}/libpam_howy.so"

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
    SYSTEMCTL_LOG="${root}/systemctl.log"
}

prepare_case() {
    local root="$1"

    set_case_paths "${root}"

    mkdir -p "${TARGET_DIR}" "${REPO_ROOT}/systemd"
    printf 'new-howyd\n' > "${HOWYD_SRC}"
    printf 'new-howy\n' > "${HOWY_SRC}"
    printf 'new-pam\n' > "${PAM_SRC}"
    printf 'new-service\n' > "${REPO_ROOT}/systemd/howy.service"
    printf 'new-socket\n' > "${REPO_ROOT}/systemd/howy.socket"
    printf '[ml]\nprovider = "cpu"\n' > "${REPO_ROOT}/howy.config"
    chmod 0755 "${HOWYD_SRC}" "${HOWY_SRC}"
    : > "${SYSTEMCTL_LOG}"

    STATE_CAPTURED=0
    STATE_RESTORED=0
    PRIOR_SERVICE_ACTIVE=0
    PRIOR_SOCKET_ACTIVE=0
    PREWARM_STATUS="not-run"
    PREWARM_MESSAGE="mock prewarm not run"
    STOP_FAIL_UNIT=""
    declare -gA MOCK_UNIT_STATE=(
        [howy.service]="missing"
        [howy.socket]="missing"
    )
}

seed_installed_artifacts() {
    mkdir -p \
        "$(dirname "${HOWYD_DEST}")" \
        "$(dirname "${PAM_DEST}")" \
        "$(dirname "${SERVICE_DEST}")" \
        "${CONFIG_DIR}"
    for path in \
        "${HOWYD_DEST}" \
        "${HOWY_DEST}" \
        "${PAM_DEST}" \
        "${SERVICE_DEST}" \
        "${SOCKET_DEST}" \
        "${CONFIG_DEST}"
    do
        printf 'old-artifact\n' > "${path}"
    done
}

require_root() { :; }
require_command() { :; }
build_release_artifacts() { :; }
run_install_prewarm() { PREWARM_MESSAGE="mock prewarm skipped"; }
print_next_steps() { :; }

systemctl() {
    printf '%s\n' "$*" >> "${SYSTEMCTL_LOG}"
    case "$1" in
        is-active)
            [ "${MOCK_UNIT_STATE[$3]:-missing}" = "active" ]
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
}

test_first_install() {
    local root
    local log
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
    rm -rf "${root}"
}

test_declined_config_precedes_replacement() {
    local root
    local path
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
    for path in \
        "${HOWYD_DEST}" \
        "${HOWY_DEST}" \
        "${PAM_DEST}" \
        "${SERVICE_DEST}" \
        "${SOCKET_DEST}" \
        "${CONFIG_DEST}"
    do
        [ "$(<"${path}")" = "old-artifact" ] || fail "artifact changed before config decision: ${path}"
    done
    log=$(<"${SYSTEMCTL_LOG}")
    [ -z "${log}" ] || fail "runtime state changed before config decision: ${log}"
    rm -rf "${root}"
}

test_successful_upgrade_restores_active_state() {
    local root
    local log
    root=$(mktemp -d)
    (
        prepare_case "${root}"
        seed_installed_artifacts
        MOCK_UNIT_STATE[howy.service]="active"
        MOCK_UNIT_STATE[howy.socket]="active"
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
    assert_not_contains "${log}" "enable"
    rm -rf "${root}"
}

test_stop_failure_prevents_replacement() {
    local root
    local path
    local log
    root=$(mktemp -d)
    if (
        prepare_case "${root}"
        seed_installed_artifacts
        MOCK_UNIT_STATE[howy.service]="active"
        MOCK_UNIT_STATE[howy.socket]="inactive"
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
    for path in \
        "${HOWYD_DEST}" \
        "${HOWY_DEST}" \
        "${PAM_DEST}" \
        "${SERVICE_DEST}" \
        "${SOCKET_DEST}" \
        "${CONFIG_DEST}"
    do
        [ "$(<"${path}")" = "old-artifact" ] || fail "artifact changed after stop failure: ${path}"
    done
    log=$(<"${SYSTEMCTL_LOG}")
    assert_contains "${log}" "stop howy.service"
    assert_contains "${log}" "start howy.service"
    assert_not_contains "${log}" "daemon-reload"
    rm -rf "${root}"
}

test_first_install
test_declined_config_precedes_replacement
test_successful_upgrade_restores_active_state
test_stop_failure_prevents_replacement
printf 'install-local mock tests: 4 passed\n'
