#!/bin/bash

set -euo pipefail

TEST_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(dirname "$(dirname "${TEST_DIR}")")
UPDATER="${REPO_ROOT}/scripts/howy-v2-update"
ADMISSION_HELPER="${REPO_ROOT}/scripts/howy-v2-update-admission"
REMOVE_HELPER="${REPO_ROOT}/scripts/howy-v2-remove-prepare"
ALPM_TEST="${REPO_ROOT}/scripts/tests/package-v2-alpm.sh"
INSTALL_SCRIPT="${REPO_ROOT}/howy.install"
PKGBUILD_PATH="${REPO_ROOT}/PKGBUILD"
SRCINFO_PATH="${REPO_ROOT}/.SRCINFO"
HOOK_PATH="${REPO_ROOT}/packaging/05-howy-config-stash.hook"
ADMISSION_HOOK_PATH="${REPO_ROOT}/packaging/00-howy-update-admission.hook"
REMOVE_HOOK_PATH="${REPO_ROOT}/packaging/10-howy-remove-prepare.hook"
PASSED=0

fail() {
    printf 'package v2 updater FAIL: %s\n' "$*" >&2
    exit 1
}

pass() {
    PASSED=$((PASSED + 1))
}

expect_success() {
    local label="$1"
    shift
    if "$@"; then
        pass
    else
        fail "${label} unexpectedly failed"
    fi
}

expect_failure() {
    local label="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        fail "${label} unexpectedly succeeded"
    else
        pass
    fi
}

assert_contains() {
    local label="$1"
    local value="$2"
    local expected="$3"

    [[ "${value}" == *"${expected}"* ]] || fail "${label} lacks '${expected}'"
    pass
}

assert_not_contains() {
    local label="$1"
    local value="$2"
    local unexpected="$3"

    [[ "${value}" != *"${unexpected}"* ]] || fail "${label} contains '${unexpected}'"
    pass
}

assert_order() {
    local label="$1"
    local value="$2"
    local first="$3"
    local second="$4"
    local remainder

    [[ "${value}" == *"${first}"* ]] || fail "${label} lacks '${first}'"
    remainder=${value#*"${first}"}
    [[ "${remainder}" == *"${second}"* ]] \
        || fail "${label} does not place '${first}' before '${second}'"
    pass
}

assert_count() {
    local label="$1"
    local value="$2"
    local pattern="$3"
    local expected="$4"
    local count=0 remainder="${value}"

    while [[ "${remainder}" == *"${pattern}"* ]]; do
        count=$((count + 1))
        remainder=${remainder#*"${pattern}"}
    done
    [[ "${count}" -eq "${expected}" ]] \
        || fail "${label} expected ${expected} occurrences of '${pattern}', got ${count}"
    pass
}

if /usr/bin/bash -n "${UPDATER}"; then
    pass
else
    fail 'updater syntax check failed'
fi
if /usr/bin/bash -n "${INSTALL_SCRIPT}"; then
    pass
else
    fail 'install-script syntax check failed'
fi
if /usr/bin/bash -n "${ADMISSION_HELPER}"; then
    pass
else
    fail 'update-admission-helper syntax check failed'
fi
if /usr/bin/bash -n "${REMOVE_HELPER}"; then
    pass
else
    fail 'removal-helper syntax check failed'
fi
if /usr/bin/bash -n "${ALPM_TEST}"; then
    pass
else
    fail 'isolated ALPM test syntax check failed'
fi

HOWY_V2_UPDATE_INTERNAL_TEST=1
# shellcheck source=../howy-v2-update
source "${UPDATER}"

run_unit_intent_case() (
    local socket_active_raw="$1"
    local socket_substate_raw="$2"
    local service_active_raw="$3"
    local service_substate_raw="$4"
    local expected_socket_active="$5"
    local expected_service_active="$6"
    local socket_enabled="${7:-enabled}"
    local service_enabled="${8:-enabled}"

    unit_snapshot_output() {
        case "$1" in
            howy.socket)
                printf 'ActiveState=%s\nSubState=%s\nUnitFileState=%s\n' \
                    "${socket_active_raw}" "${socket_substate_raw}" "${socket_enabled}"
                ;;
            howy.service)
                printf 'ActiveState=%s\nSubState=%s\nUnitFileState=%s\n' \
                    "${service_active_raw}" "${service_substate_raw}" "${service_enabled}"
                ;;
            *) return 99 ;;
        esac
    }

    capture_unit_intent || return 1
    [[ "${SOCKET_ACTIVE}:${SERVICE_ACTIVE}" == \
        "${expected_socket_active}:${expected_service_active}" ]] || return 1
    [[ "${SOCKET_ACTIVE_RAW}:${SOCKET_SUBSTATE_RAW}" == \
        "${socket_active_raw}:${socket_substate_raw}" ]] || return 1
    [[ "${SERVICE_ACTIVE_RAW}:${SERVICE_SUBSTATE_RAW}" == \
        "${service_active_raw}:${service_substate_raw}" ]] || return 1
    [[ "${SOCKET_ENABLED}:${SERVICE_ENABLED}" == \
        "${socket_enabled}:${service_enabled}" ]]
)

for active_state in active activating reloading refreshing; do
    expect_success "${active_state} normalizes both units to active intent" \
        run_unit_intent_case \
        "${active_state}" socket-any-substate \
        "${active_state}" service-any-substate \
        active active
done
for active_state in inactive failed deactivating maintenance; do
    expect_success "${active_state} normalizes both units to inactive intent" \
        run_unit_intent_case \
        "${active_state}" socket-any-substate \
        "${active_state}" service-any-substate \
        inactive inactive
done
expect_success 'arbitrary nonempty substates and mixed enablement are retained' \
    run_unit_intent_case refreshing custom-socket maintenance custom-service \
    active inactive disabled enabled
expect_failure 'unknown socket active state' \
    run_unit_intent_case unknown listening active running active active
expect_failure 'unknown service active state' \
    run_unit_intent_case active listening unknown running active active
expect_failure 'empty active state' \
    run_unit_intent_case '' listening active running active active
expect_failure 'empty substate' \
    run_unit_intent_case active '' active running active active
expect_failure 'unsupported socket enablement' \
    run_unit_intent_case active listening active running active active static enabled
expect_failure 'unsupported service enablement' \
    run_unit_intent_case active listening active running active active enabled masked

run_malformed_unit_snapshot_case() (
    unit_snapshot_output() {
        printf '%s\n' \
            'ActiveState=active' \
            'ActiveState=inactive' \
            'SubState=running' \
            'UnitFileState=enabled'
    }
    capture_unit_snapshot howy.service
)
expect_failure 'duplicate unit snapshot property' run_malformed_unit_snapshot_case

backup_function=$(declare -f create_backup)
assert_contains 'backup normalized socket activity metadata' "${backup_function}" \
    "printf 'socket_active=%s\\n' \"\${SOCKET_ACTIVE}\""
assert_contains 'backup raw socket activity metadata' "${backup_function}" \
    "printf 'socket_active_raw=%s\\n' \"\${SOCKET_ACTIVE_RAW}\""
assert_contains 'backup raw socket substate metadata' "${backup_function}" \
    "printf 'socket_substate_raw=%s\\n' \"\${SOCKET_SUBSTATE_RAW}\""
assert_contains 'backup normalized service activity metadata' "${backup_function}" \
    "printf 'service_active=%s\\n' \"\${SERVICE_ACTIVE}\""
assert_contains 'backup raw service activity metadata' "${backup_function}" \
    "printf 'service_active_raw=%s\\n' \"\${SERVICE_ACTIVE_RAW}\""
assert_contains 'backup raw service substate metadata' "${backup_function}" \
    "printf 'service_substate_raw=%s\\n' \"\${SERVICE_SUBSTATE_RAW}\""
assert_order 'backup v1 normalized fields precede additive raw fields' "${backup_function}" \
    "printf 'service_active=%s\\n' \"\${SERVICE_ACTIVE}\"" \
    "printf 'socket_active_raw=%s\\n' \"\${SOCKET_ACTIVE_RAW}\""

pkginfo_text() {
    printf 'pkgname = %s\npkgbase = %s\npkgver = %s\narch = %s' \
        "$1" "$2" "$3" "$4"
}

expect_valid_pkginfo() {
    local name="$1"
    local text

    text=$(pkginfo_text "${name}" howy 2.0.0-1 x86_64)
    parse_pkginfo_text "${text}" || fail "valid ${name} metadata was rejected"
    [[ "${ARCHIVE_PKGNAME}:${ARCHIVE_PKGBASE}:${ARCHIVE_PKGVER}:${ARCHIVE_ARCH}" \
        == "${name}:howy:2.0.0-1:x86_64" ]] \
        || fail "valid ${name} metadata populated the wrong fields"
    pass
}

for package in howy-cpu howy-rocm howy-cuda; do
    expect_valid_pkginfo "${package}"
done

valid_pkginfo=$(pkginfo_text howy-cpu howy 2.0.0-1 x86_64)
for field in pkgname pkgbase pkgver arch; do
    duplicate="${valid_pkginfo}"$'\n'"${field} = duplicate"
    expect_failure "duplicate ${field}" parse_pkginfo_text "${duplicate}"
done
expect_failure 'missing pkgname' parse_pkginfo_text $'pkgbase = howy\npkgver = 2.0.0-1\narch = x86_64'
expect_failure 'missing pkgbase' parse_pkginfo_text $'pkgname = howy-cpu\npkgver = 2.0.0-1\narch = x86_64'
expect_failure 'missing pkgver' parse_pkginfo_text $'pkgname = howy-cpu\npkgbase = howy\narch = x86_64'
expect_failure 'missing arch' parse_pkginfo_text $'pkgname = howy-cpu\npkgbase = howy\npkgver = 2.0.0-1'
expect_failure 'wrong package name' parse_pkginfo_text "$(pkginfo_text howy-git howy 2.0.0-1 x86_64)"
expect_failure 'wrong package base' parse_pkginfo_text "$(pkginfo_text howy-cpu howy-git 2.0.0-1 x86_64)"
expect_failure 'wrong package version' parse_pkginfo_text "$(pkginfo_text howy-cpu howy 2.0.0-2 x86_64)"
expect_failure 'wrong package architecture' parse_pkginfo_text "$(pkginfo_text howy-cpu howy 2.0.0-1 any)"
expect_failure 'non-exact field whitespace' parse_pkginfo_text "${valid_pkginfo/pkgname = howy-cpu/pkgname = howy-cpu }"

expect_transition() {
    local label="$1"
    local source_package="$2"
    local source_version="$3"
    local target_package="$4"
    local expected_kind="$5"

    transition_allowed "${source_package}" "${source_version}" "${target_package}" \
        || fail "${label} was rejected"
    [[ "${TRANSITION_KIND}" == "${expected_kind}" ]] \
        || fail "${label} was classified as ${TRANSITION_KIND}"
    pass
}

expect_transition release-cpu howy-cpu-git 0.1.0.r26.g2dfe39e-1 howy-cpu release-n
expect_transition release-rocm howy-rocm-git 0.1.0.r26.g2dfe39e-1 howy-rocm release-n
expect_transition release-cuda howy-cuda-git 0.1.0.r26.g2dfe39e-1 howy-cuda release-n
for release in 4 5 6 7; do
    expect_transition "candidate-rev${release}" howy-rocm-mode0 \
        "0.1.0.r27.g0b76fa2-${release}" howy-rocm candidate
done
expect_transition stable-cpu howy-cpu 2.0.0-1 howy-cpu stable
expect_transition stable-rocm howy-rocm 2.0.0-1 howy-rocm stable
expect_transition stable-cuda howy-cuda 2.0.0-1 howy-cuda stable

expect_failure 'release cross-variant' transition_allowed \
    howy-cpu-git 0.1.0.r26.g2dfe39e-1 howy-rocm
expect_failure 'candidate cross-variant' transition_allowed \
    howy-rocm-mode0 0.1.0.r27.g0b76fa2-7 howy-cpu
expect_failure 'stable cross-variant' transition_allowed howy-cpu 2.0.0-1 howy-cuda
expect_failure 'unknown predecessor' transition_allowed howdy-git 1-1 howy-cpu
expect_failure 'wrong release-N version' transition_allowed howy-cpu-git 0.1.0-1 howy-cpu
expect_failure 'skipped candidate version' transition_allowed \
    howy-rocm-mode0 0.1.0.r27.g0b76fa2-8 howy-rocm
expect_failure 'wrong stable version' transition_allowed howy-cpu 2.0.0-2 howy-cpu
expect_failure 'empty stable version' transition_allowed howy-cpu '' howy-cpu
expect_failure 'unknown target package' transition_allowed \
    howy-cpu-git 0.1.0.r26.g2dfe39e-1 howy

WORK=$(/usr/bin/mktemp -d)
cleanup() {
    /usr/bin/rm -rf -- "${WORK}"
}
trap cleanup EXIT INT TERM

# Exercise complete validation functions while they are called from tested
# status contexts, where Bash intentionally suppresses errexit for the entire
# function body. These fixtures catch a refusal that accidentally continues.
archive_tree="${WORK}/archive-tree"
valid_archive="${WORK}/howy-cpu-2.0.0-1-x86_64.pkg.tar"
/usr/bin/mkdir "${archive_tree}"
printf '%s\n' \
    'pkgname = howy-cpu' \
    'pkgbase = howy' \
    'pkgver = 2.0.0-1' \
    'arch = x86_64' > "${archive_tree}/.PKGINFO"
/usr/bin/bsdtar -cf "${valid_archive}" -C "${archive_tree}" .PKGINFO
expect_success 'complete valid archive validation' validate_archive "${valid_archive}"
[[ "${ARCHIVE_PATH}" == "${valid_archive}" \
    && "${ARCHIVE_PKGNAME}:${ARCHIVE_PKGBASE}:${ARCHIVE_PKGVER}:${ARCHIVE_ARCH}" \
        == 'howy-cpu:howy:2.0.0-1:x86_64' \
    && "${ARCHIVE_SHA256}" =~ ^[0-9a-f]{64}$ ]] \
    || fail 'complete archive validation populated incorrect evidence'
pass

invalid_archive="${WORK}/howy-invalid.pkg.tar"
printf '%s\n' \
    'pkgname = howy-git' \
    'pkgbase = howy' \
    'pkgver = 2.0.0-1' \
    'arch = x86_64' > "${archive_tree}/.PKGINFO"
/usr/bin/bsdtar -cf "${invalid_archive}" -C "${archive_tree}" .PKGINFO
expect_failure 'complete invalid archive metadata validation' validate_archive "${invalid_archive}"
expect_failure 'complete missing archive validation' validate_archive "${WORK}/missing.pkg.tar"
/usr/bin/ln -s "${valid_archive}" "${WORK}/archive-link"
expect_failure 'complete symlink archive validation' validate_archive "${WORK}/archive-link"

snapshot_file="${WORK}/snapshot-file"
printf 'snapshot\n' > "${snapshot_file}"
snapshot_function=$(declare -f require_snapshot_file)
snapshot_function=${snapshot_function//\/usr\/bin\/stat/snapshot_stat_mock}
snapshot_stat_mock() {
    if [[ "$1:$2" == '-c:%u:%g:%h:%s' ]]; then
        printf '0:0:1:%s\n' "$(/usr/bin/stat -c '%s' -- "${!#}")"
        return 0
    fi
    /usr/bin/stat "$@"
}
eval "${snapshot_function}"
expect_success 'complete snapshot-file validation' \
    require_snapshot_file "${snapshot_file}" snapshot 1024
expect_failure 'complete missing snapshot validation stops immediately' \
    require_snapshot_file "${WORK}/missing-snapshot" snapshot 1024
/usr/bin/ln -s "${snapshot_file}" "${WORK}/snapshot-link"
expect_failure 'complete symlink snapshot validation' \
    require_snapshot_file "${WORK}/snapshot-link" snapshot 1024
expect_failure 'complete oversized snapshot validation' \
    require_snapshot_file "${snapshot_file}" snapshot 1

candidate_config="${WORK}/candidate-config.toml"
printf 'candidate config\n' > "${candidate_config}"
run_candidate_config_case() (
    local expected_mode="$1"
    local candidate_function snapshot_requirement_function

    /usr/bin/chmod "${expected_mode}" "${candidate_config}"
    snapshot_requirement_function=$(declare -f require_snapshot_file)
    snapshot_requirement_function=${snapshot_requirement_function//\/usr\/bin\/stat/candidate_config_stat_mock}
    candidate_function=$(declare -f require_candidate_config)
    candidate_function=${candidate_function//CONFIG_PATH/TEST_CANDIDATE_CONFIG_PATH}
    candidate_function=${candidate_function//\/usr\/bin\/stat/candidate_config_stat_mock}
    eval "${snapshot_requirement_function}"
    eval "${candidate_function}"

    TEST_CANDIDATE_CONFIG_PATH=${candidate_config}
    candidate_config_stat_mock() {
        case "$1:$2" in
            '-c:%u:%g:%h:%s')
                printf '0:0:1:%s\n' "$(/usr/bin/stat -c '%s' -- "${!#}")"
                ;;
            *) /usr/bin/stat "$@" ;;
        esac
    }

    require_candidate_config
)
expect_success 'candidate mode 0600 config preflight' run_candidate_config_case 0600
expect_failure 'candidate mode 0644 config preflight refusal' \
    run_candidate_config_case 0644

provider_function=$(declare -f query_single_provider)
provider_function=${provider_function//\/usr\/bin\/pacman/provider_pacman_mock}
PROVIDER_MODE=success
PROVIDER_LOG="${WORK}/provider.log"
provider_pacman_mock() {
    printf '%s\n' "$*" >> "${PROVIDER_LOG}"
    case "$1" in
        -Qq)
            case "${PROVIDER_MODE}" in
                enumerate-failure) return 1 ;;
                multiple) printf '%s\n' howy-cpu howy-rocm ;;
                *) printf '%s\n' howy-cpu ;;
            esac
            ;;
        -Qqo)
            if [[ "${PROVIDER_MODE}" == owner-failure ]]; then
                return 1
            elif [[ "${PROVIDER_MODE}" == owner-mismatch ]]; then
                printf '%s\n' howy-rocm
            else
                printf '%s\n' howy-cpu
            fi
            ;;
        *) return 99 ;;
    esac
}
query_package_version() {
    [[ "${PROVIDER_MODE}" != version-failure ]] || return 1
    printf '%s\n' "${TARGET_VERSION}"
}
eval "${provider_function}"

: > "${PROVIDER_LOG}"
expect_success 'complete provider preflight' query_single_provider
[[ "${SOURCE_PACKAGE}:${SOURCE_VERSION}" == "howy-cpu:${TARGET_VERSION}" ]] \
    || fail 'complete provider preflight populated the wrong identity'
pass

PROVIDER_MODE=enumerate-failure
: > "${PROVIDER_LOG}"
expect_failure 'provider enumeration refusal returns immediately' query_single_provider
[[ "$(<"${PROVIDER_LOG}")" == '-Qq' ]] \
    || fail 'provider enumeration refusal continued to an owner query'
pass

PROVIDER_MODE=multiple
: > "${PROVIDER_LOG}"
expect_failure 'multiple-provider refusal returns immediately' query_single_provider
[[ "$(<"${PROVIDER_LOG}")" == '-Qq' ]] \
    || fail 'multiple-provider refusal continued to an owner query'
pass

PROVIDER_MODE=owner-mismatch
: > "${PROVIDER_LOG}"
expect_failure 'provider owner mismatch returns immediately' query_single_provider
[[ "$(<"${PROVIDER_LOG}")" == $'-Qq\n-Qqo -- /usr/bin/howy' ]] \
    || fail 'provider owner mismatch ran an unexpected pacman query'
pass

PROVIDER_MODE=version-failure
expect_failure 'provider version query failure returns nonzero' query_single_provider

# Transform only the absolute production marker and bridge references so the
# complete transition preflight can run against temporary files without touching
# /var/lib or an installed predecessor bridge.
TEST_MARKER_PATH="${WORK}/release-marker"
marker_requirement_function=$(declare -f require_package_marker)
marker_requirement_function=${marker_requirement_function//MARKER_PATH/TEST_MARKER_PATH}
eval "${marker_requirement_function}"
transition_preflight_function=$(declare -f preflight_transition_state)
production_transition_preflight_function=${transition_preflight_function}
transition_preflight_function=${transition_preflight_function//MARKER_PATH/TEST_MARKER_PATH}
transition_preflight_function=${transition_preflight_function//\/usr\/lib\/howy\/howy-config-bridge/preflight_bridge_mock}
eval "${transition_preflight_function}"
PREFLIGHT_BRIDGE_MODE=valid
PREFLIGHT_LOG="${WORK}/preflight.log"
preflight_bridge_mock() {
    printf '%s\n' "$1" >> "${PREFLIGHT_LOG}"
    case "$1" in
        complete-release-n)
            case "${PREFLIGHT_BRIDGE_MODE}" in
                valid|stash-retains) return 0 ;;
                complete-removes)
                    /usr/bin/rm -- "${TEST_MARKER_PATH}"
                    return 0
                    ;;
                wrong-binding)
                    write_release_marker normalized-binding
                    return 0
                    ;;
                config-drift)
                    write_release_marker normalized-drift
                    return 0
                    ;;
                malformed|wrong-release) return 1 ;;
                *) return 99 ;;
            esac
            ;;
        validate-current-marker)
            [[ "${PREFLIGHT_BRIDGE_MODE}" != stable-invalid ]]
            ;;
        stash-release-n)
            if [[ "${PREFLIGHT_BRIDGE_MODE}" != stash-retains ]]; then
                /usr/bin/rm -- "${TEST_MARKER_PATH}"
            fi
            ;;
        *) return 99 ;;
    esac
}

write_release_marker() {
    case "$1" in
        valid)
            printf '%s\n' '{"schema_version":1,"release_id":"release-n","transaction_id":"11111111111111111111111111111111","generation":null,"config":{"state":"absent","absence":{"parent_device":1,"parent_inode":2}}}'
            ;;
        generated)
            printf '%s\n' '{"schema_version":1,"release_id":"release-n","transaction_id":"11111111111111111111111111111111","generation":1,"config":{"state":"absent","absence":{"parent_device":1,"parent_inode":2}}}'
            ;;
        malformed)
            printf '%s\n' '{"schema_version":1,"release_id":"release-n","transaction_id":"11111111111111111111111111111111","generation":null,"config":{"state":}}'
            ;;
        wrong-release)
            printf '%s\n' '{"schema_version":1,"release_id":"candidate","transaction_id":"11111111111111111111111111111111","generation":null,"config":{"state":"absent","absence":{"parent_device":1,"parent_inode":2}}}'
            ;;
        normalized-binding)
            printf '%s\n' '{"schema_version":1,"release_id":"release-n","transaction_id":"22222222222222222222222222222222","generation":null,"config":{"state":"absent","absence":{"parent_device":1,"parent_inode":2}}}'
            ;;
        normalized-drift)
            printf '%s\n' '{"schema_version":1,"release_id":"release-n","transaction_id":"33333333333333333333333333333333","generation":null,"config":{"state":"absent","absence":{"parent_device":3,"parent_inode":4}}}'
            ;;
        *) return 99 ;;
    esac > "${TEST_MARKER_PATH}"
    /usr/bin/chmod 0600 "${TEST_MARKER_PATH}"
}

TRANSITION_KIND=release-n
: > "${PREFLIGHT_LOG}"
expect_failure 'release-N missing marker preflight' preflight_transition_state
[[ ! -s "${PREFLIGHT_LOG}" ]] || fail 'missing marker preflight invoked the bridge'
pass

write_release_marker valid
/usr/bin/chmod 0644 "${TEST_MARKER_PATH}"
: > "${PREFLIGHT_LOG}"
expect_failure 'release-N wrong marker metadata preflight' preflight_transition_state
[[ ! -s "${PREFLIGHT_LOG}" ]] || fail 'unsafe marker metadata reached the bridge'
pass
/usr/bin/rm -- "${TEST_MARKER_PATH}"

write_release_marker generated
: > "${PREFLIGHT_LOG}"
expect_failure 'generated release-N marker is unsupported before bridge' \
    preflight_transition_state
[[ ! -s "${PREFLIGHT_LOG}" ]] || fail 'generated release-N marker reached the bridge'
pass
/usr/bin/rm -- "${TEST_MARKER_PATH}"

for marker_mode in malformed wrong-release; do
    write_release_marker "${marker_mode}"
    PREFLIGHT_BRIDGE_MODE=${marker_mode}
    : > "${PREFLIGHT_LOG}"
    expect_failure "release-N ${marker_mode} marker preflight" preflight_transition_state
    [[ "$(<"${PREFLIGHT_LOG}")" == complete-release-n ]] \
        || fail "${marker_mode} marker preflight continued after bridge refusal"
    pass
    /usr/bin/rm -- "${TEST_MARKER_PATH}"
done

for marker_mode in wrong-binding config-drift; do
    write_release_marker valid
    PREFLIGHT_BRIDGE_MODE=${marker_mode}
    : > "${PREFLIGHT_LOG}"
    expect_failure "release-N ${marker_mode} normalization is refused" \
        preflight_transition_state
    [[ "$(<"${PREFLIGHT_LOG}")" == complete-release-n ]] \
        || fail "${marker_mode} normalization continued to stash"
    [[ -f "${TEST_MARKER_PATH}" ]] \
        || fail "${marker_mode} normalization marker was not retained for review"
    pass
    /usr/bin/rm -- "${TEST_MARKER_PATH}"
done

write_release_marker valid
PREFLIGHT_BRIDGE_MODE=complete-removes
: > "${PREFLIGHT_LOG}"
expect_failure 'release-N validation must retain marker' preflight_transition_state
[[ "$(<"${PREFLIGHT_LOG}")" == complete-release-n ]] \
    || fail 'missing post-completion marker did not stop before stash'
pass

write_release_marker valid
PREFLIGHT_BRIDGE_MODE=stash-retains
: > "${PREFLIGHT_LOG}"
expect_failure 'release-N stash must consume marker' preflight_transition_state
[[ "$(<"${PREFLIGHT_LOG}")" == $'complete-release-n\nstash-release-n' ]] \
    || fail 'marker-retaining stash did not run the exact bridge sequence'
pass
/usr/bin/rm -- "${TEST_MARKER_PATH}"

write_release_marker valid
TRANSITION_KIND=release-n
PREFLIGHT_BRIDGE_MODE=valid
: > "${PREFLIGHT_LOG}"
expect_success 'release-N exact marker preflight' preflight_transition_state
[[ "$(<"${PREFLIGHT_LOG}")" == $'complete-release-n\nstash-release-n' ]] \
    || fail 'release-N preflight bridge ordering differs'
[[ ! -e "${TEST_MARKER_PATH}" && ! -L "${TEST_MARKER_PATH}" ]] \
    || fail 'release-N preflight retained its marker'
pass

write_release_marker valid
TRANSITION_KIND=stable
PREFLIGHT_BRIDGE_MODE=stable-invalid
: > "${PREFLIGHT_LOG}"
expect_failure 'stable marker validator refusal stops before stash' preflight_transition_state
[[ "$(<"${PREFLIGHT_LOG}")" == validate-current-marker ]] \
    || fail 'stable validator refusal continued to another bridge command'
pass
/usr/bin/rm -- "${TEST_MARKER_PATH}"

write_release_marker valid
PREFLIGHT_BRIDGE_MODE=valid
: > "${PREFLIGHT_LOG}"
expect_success 'stable read-only marker validation preflight' preflight_transition_state
[[ "$(<"${PREFLIGHT_LOG}")" == $'validate-current-marker\nstash-release-n' ]] \
    || fail 'stable preflight did not validate-current-marker before stash'
[[ ! -e "${TEST_MARKER_PATH}" && ! -L "${TEST_MARKER_PATH}" ]] \
    || fail 'stable preflight retained its marker'
pass

marker="${WORK}/candidate.marker"
printf '%s\n' \
    'schema=howy-package-capability-v1' \
    'package=howy-rocm-mode0' \
    'source_commit=0b76fa23ad3883ccfa8edd38210766f97cdbb71a' \
    'supported_modes=0,1' > "${marker}"
/usr/bin/chmod 0600 "${marker}"
expect_success 'candidate marker bytes and hash' \
    candidate_marker_bytes_and_hash_are_exact "${marker}"
printf 'x' >> "${marker}"
expect_failure 'candidate marker changed bytes' \
    candidate_marker_bytes_and_hash_are_exact "${marker}"
printf '%s\n' \
    'schema=howy-package-capability-v1' \
    'package=howy-rocm-mode0' \
    'source_commit=0b76fa23ad3883ccfa8edd38210766f97cdbb71a' \
    'supported_modes=0,1' > "${marker}"
if [[ "$(/usr/bin/id -u)" -eq 0 ]]; then
    expect_success 'candidate marker production metadata' candidate_marker_is_exact "${marker}"
else
    expect_failure 'candidate marker production function keeps root metadata check' \
        candidate_marker_is_exact "${marker}"
    marker_function=$(declare -f candidate_marker_is_exact)
    assert_contains 'candidate metadata contract' "${marker_function}" "0:0:600:1:133"
    assert_order 'candidate metadata-before-bytes contract' "${marker_function}" \
        "/usr/bin/stat" "candidate_marker_bytes_and_hash_are_exact"
fi

available_path="${WORK}/availability"
expect_success 'absent backup path is available' backup_path_available "${available_path}"
printf 'occupied\n' > "${available_path}"
expect_failure 'existing backup file collides' backup_path_available "${available_path}"
/usr/bin/rm -- "${available_path}"
/usr/bin/ln -s missing-target "${available_path}"
expect_failure 'dangling backup symlink collides' backup_path_available "${available_path}"
/usr/bin/rm -- "${available_path}"
/usr/bin/mkdir "${available_path}"
expect_failure 'existing backup directory collides' backup_path_available "${available_path}"

backup="${WORK}/backup"
/usr/bin/mkdir "${backup}"
printf 'config\n' > "${backup}/config.toml"
printf 'metadata\n' > "${backup}/metadata"
expect_success 'minimal expected backup contents' backup_contents_are_expected "${backup}" 0 0
printf 'receipt\n' > "${backup}/receipt-v1.json"
expect_failure 'unexpected receipt is refused' backup_contents_are_expected "${backup}" 0 0
expect_success 'declared receipt is accepted' backup_contents_are_expected "${backup}" 1 0
printf 'marker\n' > "${backup}/package-bootstrap.marker"
expect_failure 'unexpected marker is refused' backup_contents_are_expected "${backup}" 1 0
expect_success 'declared receipt and marker are accepted' backup_contents_are_expected "${backup}" 1 1
printf 'unknown\n' > "${backup}/.unknown"
expect_failure 'unknown hidden backup entry is refused' backup_contents_are_expected "${backup}" 1 1
/usr/bin/rm -- "${backup}/.unknown" "${backup}/receipt-v1.json" "${backup}/package-bootstrap.marker"
/usr/bin/rm -- "${backup}/config.toml"
/usr/bin/ln -s metadata "${backup}/config.toml"
expect_failure 'symlinked expected backup entry is refused' backup_contents_are_expected "${backup}" 0 0
/usr/bin/rm -- "${backup}/config.toml"
printf 'config\n' > "${backup}/config.toml"

resume_archive_tree="${WORK}/resume-archive-tree"
resume_archive="${WORK}/howy-rocm-2.0.0-1-x86_64.pkg.tar"
/usr/bin/mkdir "${resume_archive_tree}"
printf '%s\n' \
    'pkgname = howy-rocm' \
    'pkgbase = howy' \
    'pkgver = 2.0.0-1' \
    'arch = x86_64' > "${resume_archive_tree}/.PKGINFO"
/usr/bin/bsdtar -cf "${resume_archive}" -C "${resume_archive_tree}" .PKGINFO
resume_archive_digest=$(/usr/bin/sha256sum -- "${resume_archive}")
resume_archive_sha=${resume_archive_digest%% *}

write_retained_metadata_fixture() {
    local path="$1"
    local schema="$2"
    local source_package="$3"
    local source_version="$4"
    local archive_path="$5"
    local archive_sha="$6"
    local socket_enabled="${7:-disabled}"
    local socket_active="${8:-inactive}"
    local service_enabled="${9:-enabled}"
    local service_active="${10:-active}"

    {
        printf '%s\n' \
            'format=howy-v2-update-v1' \
            "archive=${archive_path}" \
            "archive_sha256=${archive_sha}" \
            "source_package=${source_package}" \
            "source_version=${source_version}" \
            'target_package=howy-rocm' \
            'target_version=2.0.0-1' \
            "socket_enabled=${socket_enabled}" \
            "socket_active=${socket_active}" \
            "service_enabled=${service_enabled}" \
            "service_active=${service_active}"
        if [[ "${schema}" == current ]]; then
            printf '%s\n' \
                'socket_active_raw=failed' \
                'socket_substate_raw=stored-socket-history' \
                'service_active_raw=refreshing' \
                'service_substate_raw=stored-service-history'
        fi
    } > "${path}"
}

legacy_metadata="${WORK}/legacy-retained-metadata"
write_retained_metadata_fixture \
    "${legacy_metadata}" legacy howy-rocm-mode0 0.1.0.r27.g0b76fa2-6 \
    "${resume_archive}" "${resume_archive_sha}"
expect_success 'legacy eleven-field retained metadata parsing' \
    parse_retained_backup_metadata "${legacy_metadata}"
[[ "${RETAINED_SOURCE_PACKAGE}:${RETAINED_SOURCE_VERSION}" == \
    'howy-rocm-mode0:0.1.0.r27.g0b76fa2-6' \
    && "${RETAINED_ARCHIVE_PATH}:${RETAINED_ARCHIVE_SHA256}" == \
        "${resume_archive}:${resume_archive_sha}" \
    && -z "${STORED_SOCKET_ACTIVE_RAW}${STORED_SERVICE_ACTIVE_RAW}" ]] \
    || fail 'legacy retained metadata populated incorrect fields'
pass

current_metadata="${WORK}/current-retained-metadata"
write_retained_metadata_fixture \
    "${current_metadata}" current howy-rocm 2.0.0-1 \
    "${resume_archive}" "${resume_archive_sha}"
expect_success 'current additive-raw-field retained metadata parsing' \
    parse_retained_backup_metadata "${current_metadata}"
[[ "${RETAINED_SOURCE_PACKAGE}:${RETAINED_SOURCE_VERSION}" == 'howy-rocm:2.0.0-1' \
    && "${STORED_SOCKET_ACTIVE_RAW}:${STORED_SOCKET_SUBSTATE_RAW}" == \
        'failed:stored-socket-history' \
    && "${STORED_SERVICE_ACTIVE_RAW}:${STORED_SERVICE_SUBSTATE_RAW}" == \
        'refreshing:stored-service-history' ]] \
    || fail 'current retained metadata populated incorrect raw history'
pass
printf 'duplicate=field\n' >> "${current_metadata}"
expect_failure 'retained metadata rejects an extra field' \
    parse_retained_backup_metadata "${current_metadata}"
invalid_stored_intent_metadata="${WORK}/invalid-stored-intent-metadata"
write_retained_metadata_fixture \
    "${invalid_stored_intent_metadata}" current \
    howy-rocm-mode0 0.1.0.r27.g0b76fa2-6 \
    "${resume_archive}" "${resume_archive_sha}" masked inactive enabled active
expect_failure 'retained metadata rejects non-exact stored enablement' \
    parse_retained_backup_metadata "${invalid_stored_intent_metadata}"
write_retained_metadata_fixture \
    "${invalid_stored_intent_metadata}" current \
    howy-rocm-mode0 0.1.0.r27.g0b76fa2-6 \
    "${resume_archive}" "${resume_archive_sha}" disabled failed enabled active
expect_failure 'retained metadata rejects non-normalized stored activity' \
    parse_retained_backup_metadata "${invalid_stored_intent_metadata}"
metadata_parser_function=$(declare -f parse_retained_backup_metadata)
assert_not_contains 'retained metadata parser does not evaluate metadata' \
    "${metadata_parser_function}" 'eval '
assert_not_contains 'retained metadata parser does not source metadata' \
    "${metadata_parser_function}" 'source '

prepare_resume_case() {
    local name="$1"
    local schema="$2"
    local source_package="$3"
    local source_version="$4"
    local installed_state="$5"
    local behavior="$6"
    local metadata_archive=${resume_archive}
    local metadata_sha=${resume_archive_sha}

    RESUME_CASE_ROOT="${WORK}/resume-${name}"
    RESUME_SCHEMA=${schema}
    RESUME_SOURCE_PACKAGE=${source_package}
    RESUME_SOURCE_VERSION=${source_version}
    RESUME_INITIAL_INSTALLED_STATE=${installed_state}
    RESUME_BEHAVIOR=${behavior}
    RESUME_LOG="${RESUME_CASE_ROOT}/commands.log"
    /usr/bin/rm -rf -- "${RESUME_CASE_ROOT}"
    /usr/bin/mkdir -p "${RESUME_CASE_ROOT}/backup"
    /usr/bin/chmod 0700 "${RESUME_CASE_ROOT}/backup"
    printf 'saved config\n' > "${RESUME_CASE_ROOT}/backup/config.toml"
    printf 'saved receipt\n' > "${RESUME_CASE_ROOT}/backup/receipt-v1.json"
    printf 'saved marker\n' > "${RESUME_CASE_ROOT}/backup/package-bootstrap.marker"
    case "${installed_state}" in
        source|source-version-mismatch)
            printf 'saved config\n' > "${RESUME_CASE_ROOT}/config.toml"
            printf 'saved receipt\n' > "${RESUME_CASE_ROOT}/receipt-v1.json"
            printf 'live candidate marker\n' > "${RESUME_CASE_ROOT}/live-marker"
            ;;
        *)
            printf 'live config from completed pacman\n' > "${RESUME_CASE_ROOT}/config.toml"
            printf 'live receipt from completed pacman\n' > "${RESUME_CASE_ROOT}/receipt-v1.json"
            ;;
    esac
    case "${behavior}" in
        archive-path-mismatch) metadata_archive="${resume_archive}.different" ;;
        archive-hash-mismatch)
            metadata_sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            ;;
    esac
    write_retained_metadata_fixture \
        "${RESUME_CASE_ROOT}/backup/metadata" "${schema}" \
        "${source_package}" "${source_version}" \
        "${metadata_archive}" "${metadata_sha}"
    /usr/bin/chmod 0600 \
        "${RESUME_CASE_ROOT}/backup/metadata" \
        "${RESUME_CASE_ROOT}/backup/receipt-v1.json" \
        "${RESUME_CASE_ROOT}/backup/package-bootstrap.marker"
    : > "${RESUME_LOG}"
}

run_resume_main_case() (
    local transformed

    transformed=$(<"${UPDATER}")
    transformed=${transformed//\/etc\/howy\/config.toml/${RESUME_CASE_ROOT}\/config.toml}
    transformed=${transformed//\/var\/lib\/howy\/security-state\/receipt-v1.json/${RESUME_CASE_ROOT}\/receipt-v1.json}
    transformed=${transformed//\/var\/lib\/howy-package-bootstrap.complete/${RESUME_CASE_ROOT}\/live-marker}
    transformed=${transformed//\/var\/lib\/howy\/v2-update-backup-v1/${RESUME_CASE_ROOT}\/backup}
    transformed=${transformed//\/run\/howy-v2-update-v1.prepared/${RESUME_CASE_ROOT}\/prepared}
    transformed=${transformed//\/usr\/lib\/howy\/howy-config-bridge/resume_bridge_mock}
    transformed=${transformed//\/usr\/bin\/systemctl/resume_systemctl_mock}
    transformed=${transformed//\/usr\/bin\/pacman/resume_pacman_mock}
    transformed=${transformed//\/usr\/bin\/stat/resume_stat_mock}
    transformed=${transformed//\/usr\/bin\/install/resume_install_mock}
    transformed=${transformed//\/usr\/bin\/howy/resume_howy_mock}
    transformed=${transformed//\/usr\/bin\/id/resume_id_mock}

    RESUME_CASE_ROOT="${RESUME_CASE_ROOT}" \
    RESUME_SOURCE_PACKAGE="${RESUME_SOURCE_PACKAGE}" \
    RESUME_SOURCE_VERSION="${RESUME_SOURCE_VERSION}" \
    RESUME_INITIAL_INSTALLED_STATE="${RESUME_INITIAL_INSTALLED_STATE}" \
    RESUME_BEHAVIOR="${RESUME_BEHAVIOR}" \
    RESUME_LOG="${RESUME_LOG}" \
    RESUME_UPDATER_TEXT="${transformed}" \
        /usr/bin/bash -s -- "${resume_archive}" <<'RESUME_HARNESS'
    set -euo pipefail
    HOWY_V2_UPDATE_INTERNAL_TEST=1
    # shellcheck source=/dev/null
    source <(printf '%s\n' "${RESUME_UPDATER_TEXT}")

    RESUME_INSTALLED_FIXTURE=${RESUME_INITIAL_INSTALLED_STATE}
    RESUME_SOCKET_ENABLED=enabled
    RESUME_SOCKET_ACTIVE=reloading
    RESUME_SOCKET_SUBSTATE=custom-socket-live
    RESUME_SERVICE_ENABLED=disabled
    RESUME_SERVICE_ACTIVE=maintenance
    RESUME_SERVICE_SUBSTATE=custom-service-live

    resume_id_mock() {
        printf '0\n'
    }
    resume_stat_mock() {
        local path=${!#}

        if [[ "${path}" == "${BACKUP_PATH}" ]]; then
            case "$1:$2" in
                '-c:%u:%g:%a') printf '0:0:700\n'; return 0 ;;
            esac
        elif [[ "${path}" == "${BACKUP_PATH}/"* ]]; then
            case "$1:$2" in
                '-c:%u:%g:%h') printf '0:0:1\n'; return 0 ;;
            esac
        elif [[ "${path}" == "${SENTINEL_PATH}" ]]; then
            case "$1:$2" in
                '-c:%u:%g:%a') printf '0:0:600\n'; return 0 ;;
            esac
        elif [[ "${path}" == "${CONFIG_PATH}" ]]; then
            case "$1:$2" in
                '-c:%u:%g:%a:%h')
                    printf '0:0:%s:1\n' "$(/usr/bin/stat -c '%a' -- "${path}")"
                    return 0
                    ;;
            esac
        fi
        /usr/bin/stat "$@"
    }
    resume_install_mock() {
        [[ "$1:$2:$3:$4:$5:$7:$8:$9" == \
            "-o:root:-g:root:-m:--:${BACKUP_PATH}/config.toml:${CONFIG_PATH}" ]] \
            || return 89
        /usr/bin/install -m "$6" -- "$8" "$9"
    }
    resume_pacman_mock() {
        printf 'pacman:%s\n' "$*" >> "${RESUME_LOG}"
        case "$1" in
            -Qq)
                case "${RESUME_INSTALLED_FIXTURE}" in
                    source|source-version-mismatch) printf '%s\n' howy-rocm-mode0 ;;
                    target|target-version-mismatch) printf '%s\n' howy-rocm ;;
                    ambiguous) printf '%s\n' howy-rocm-mode0 howy-rocm ;;
                    absent) : ;;
                    *) return 98 ;;
                esac
                ;;
            -Qqo)
                case "${RESUME_INSTALLED_FIXTURE}" in
                    source|source-version-mismatch) printf '%s\n' howy-rocm-mode0 ;;
                    target|target-version-mismatch) printf '%s\n' howy-rocm ;;
                    *) return 97 ;;
                esac
                ;;
            -Q)
                case "$3:${RESUME_INSTALLED_FIXTURE}" in
                    howy-rocm-mode0:source)
                        printf 'howy-rocm-mode0 %s\n' "${RESUME_SOURCE_VERSION}"
                        ;;
                    howy-rocm-mode0:source-version-mismatch)
                        printf 'howy-rocm-mode0 0.1.0.r27.g0b76fa2-5\n'
                        ;;
                    howy-rocm:target) printf 'howy-rocm 2.0.0-1\n' ;;
                    howy-rocm:target-version-mismatch) printf 'howy-rocm 2.0.0-2\n' ;;
                    *) return 1 ;;
                esac
                ;;
            --ask=4)
                [[ "$*" == "--ask=4 -U --noconfirm -- ${ARCHIVE_PATH}" ]] || return 96
                [[ -f "${SENTINEL_PATH}" && ! -L "${SENTINEL_PATH}" ]] || return 95
                mapfile -t resume_sentinel_lines < "${SENTINEL_PATH}" || return 94
                [[ "${#resume_sentinel_lines[@]}" -eq 7 ]] || return 93
                [[ "${HOWY_V2_UPDATE_FORMAT}:${HOWY_V2_UPDATE_ARCHIVE}:${HOWY_V2_UPDATE_ARCHIVE_SHA256}" == \
                    "${UPDATE_FORMAT}:${ARCHIVE_PATH}:${ARCHIVE_SHA256}" ]] || return 92
                [[ "${HOWY_V2_UPDATE_TARGET_PACKAGE}:${HOWY_V2_UPDATE_TARGET_VERSION}" == \
                    "${ARCHIVE_PKGNAME}:${ARCHIVE_PKGVER}" ]] || return 91
                printf 'pacman-binding:source=%s:%s:target=%s:%s:sentinel-source=%s:%s\n' \
                    "${HOWY_V2_UPDATE_SOURCE_PACKAGE}" \
                    "${HOWY_V2_UPDATE_SOURCE_VERSION}" \
                    "${HOWY_V2_UPDATE_TARGET_PACKAGE}" \
                    "${HOWY_V2_UPDATE_TARGET_VERSION}" \
                    "${resume_sentinel_lines[3]#source_package=}" \
                    "${resume_sentinel_lines[4]#source_version=}" >> "${RESUME_LOG}"
                [[ "${RESUME_BEHAVIOR}" != pacman-failure ]] || return 90
                if [[ "${RESUME_INSTALLED_FIXTURE}" == source ]]; then
                    printf 'stable package config payload\n' > "${CONFIG_PATH}"
                fi
                /usr/bin/rm -f -- "${MARKER_PATH}"
                RESUME_INSTALLED_FIXTURE=target
                ;;
            *) return 99 ;;
        esac
    }
    resume_systemctl_mock() {
        local argument property='' unit=${!#}

        printf 'systemctl:%s\n' "$*" >> "${RESUME_LOG}"
        case "$1" in
            show)
                if [[ " $* " == *' --value '* ]]; then
                    for argument in "$@"; do
                        case "${argument}" in
                            --property=*) property=${argument#--property=} ;;
                        esac
                    done
                    case "${unit}:${property}" in
                        howy.socket:UnitFileState) printf '%s\n' "${RESUME_SOCKET_ENABLED}" ;;
                        howy.socket:ActiveState) printf '%s\n' "${RESUME_SOCKET_ACTIVE}" ;;
                        howy.service:UnitFileState) printf '%s\n' "${RESUME_SERVICE_ENABLED}" ;;
                        howy.service:ActiveState) printf '%s\n' "${RESUME_SERVICE_ACTIVE}" ;;
                        *) return 96 ;;
                    esac
                else
                    case "${unit}" in
                        howy.socket)
                            printf 'SubState=%s\nUnitFileState=%s\nActiveState=%s\n' \
                                "${RESUME_SOCKET_SUBSTATE}" \
                                "${RESUME_SOCKET_ENABLED}" \
                                "${RESUME_SOCKET_ACTIVE}"
                            ;;
                        howy.service)
                            printf 'SubState=%s\nUnitFileState=%s\nActiveState=%s\n' \
                                "${RESUME_SERVICE_SUBSTATE}" \
                                "${RESUME_SERVICE_ENABLED}" \
                                "${RESUME_SERVICE_ACTIVE}"
                            ;;
                        *) return 95 ;;
                    esac
                fi
                ;;
            stop)
                case "$2" in
                    howy.socket) RESUME_SOCKET_ACTIVE=inactive ;;
                    howy.service) RESUME_SERVICE_ACTIVE=inactive ;;
                    *) return 94 ;;
                esac
                ;;
            enable)
                case "$2" in
                    howy.socket) RESUME_SOCKET_ENABLED=enabled ;;
                    howy.service) RESUME_SERVICE_ENABLED=enabled ;;
                    *) return 93 ;;
                esac
                ;;
            disable)
                case "$2" in
                    howy.socket) RESUME_SOCKET_ENABLED=disabled ;;
                    howy.service) RESUME_SERVICE_ENABLED=disabled ;;
                    *) return 92 ;;
                esac
                ;;
            start)
                case "$2" in
                    howy.socket) RESUME_SOCKET_ACTIVE=active ;;
                    howy.service) RESUME_SERVICE_ACTIVE=active ;;
                    *) return 91 ;;
                esac
                ;;
            *) return 90 ;;
        esac
    }
    resume_bridge_mock() {
        local marker_state=absent
        local sentinel_state=absent

        if [[ -e "${MARKER_PATH}" || -L "${MARKER_PATH}" ]]; then
            marker_state=present
        fi
        if [[ -e "${SENTINEL_PATH}" || -L "${SENTINEL_PATH}" ]]; then
            sentinel_state=present
        fi
        printf 'bridge:%s:marker-%s:sentinel-%s\n' \
            "$*" "${marker_state}" "${sentinel_state}" >> "${RESUME_LOG}"
        [[ "${RESUME_BEHAVIOR}" != bridge-failure ]] || return 1
        /usr/bin/rm -f -- "${MARKER_PATH}"
    }
    resume_howy_mock() {
        printf 'howy:%s\n' "$*" >> "${RESUME_LOG}"
    }

    main "$1"
RESUME_HARNESS
)

prepare_resume_case source-success current \
    howy-rocm-mode0 0.1.0.r27.g0b76fa2-6 source success
if source_resume_output=$(run_resume_main_case 2>&1); then
    pass
else
    fail "source-state retained-backup resume failed: ${source_resume_output}"
fi
source_resume_log=$(<"${RESUME_LOG}")
assert_contains 'source-state resume completion output' "${source_resume_output}" \
    'Howy update finalization resumed: package=howy-rocm version=2.0.0-1'
assert_count 'resume captures one coherent snapshot per unit' \
    "${source_resume_log}" \
    'systemctl:show --property=UnitFileState --property=ActiveState --property=SubState --no-pager' 2
assert_count 'source-state resume reruns pacman exactly once' \
    "${source_resume_log}" 'pacman:--ask=4 -U --noconfirm --' 1
assert_contains 'source-state pacman keeps candidate transaction binding' \
    "${source_resume_log}" \
    'pacman-binding:source=howy-rocm-mode0:0.1.0.r27.g0b76fa2-6:target=howy-rocm:2.0.0-1:sentinel-source=howy-rocm-mode0:0.1.0.r27.g0b76fa2-6'
assert_order 'source-state sentinel-backed pacman precedes bridge' \
    "${source_resume_log}" 'pacman-binding:' \
    'bridge:complete-release-n:marker-absent:sentinel-absent'
assert_contains 'source-state resume uses legacy normalization reconcile' \
    "${source_resume_log}" \
    'howy:package reconcile --allow-legacy-candidate-mode0 --normalize-legacy-candidate-mode0'
assert_contains 'stored socket disablement is restored on source resume' \
    "${source_resume_log}" 'systemctl:disable howy.socket'
assert_contains 'stored service enablement is restored on source resume' \
    "${source_resume_log}" 'systemctl:enable howy.service'
assert_not_contains 'stored inactive socket is not restarted on source resume' \
    "${source_resume_log}" 'systemctl:start howy.socket'
assert_contains 'stored active service is restarted on source resume' \
    "${source_resume_log}" 'systemctl:start howy.service'
[[ "$(<"${RESUME_CASE_ROOT}/config.toml")" == 'saved config' ]] \
    || fail 'source-state resume did not restore the backed-up config'
pass
[[ "$(<"${RESUME_CASE_ROOT}/receipt-v1.json")" == 'saved receipt' ]] \
    || fail 'source-state resume did not preserve the backed-up receipt bytes'
pass
[[ ! -e "${RESUME_CASE_ROOT}/backup" && ! -L "${RESUME_CASE_ROOT}/backup" ]] \
    || fail 'source-state resume did not remove the exact completed backup'
pass
[[ ! -e "${RESUME_CASE_ROOT}/prepared" && ! -L "${RESUME_CASE_ROOT}/prepared" ]] \
    || fail 'source-state resume left a prepared sentinel'
pass

prepare_resume_case target-success current \
    howy-rocm-mode0 0.1.0.r27.g0b76fa2-6 target success
if target_resume_output=$(run_resume_main_case 2>&1); then
    pass
else
    fail "target-state retained-backup resume failed: ${target_resume_output}"
fi
target_resume_log=$(<"${RESUME_LOG}")
assert_count 'target-state resume reruns pacman exactly once' \
    "${target_resume_log}" 'pacman:--ask=4 -U --noconfirm --' 1
assert_contains 'target-state resume rewrites transaction as stable same-name update' \
    "${target_resume_log}" \
    'pacman-binding:source=howy-rocm:2.0.0-1:target=howy-rocm:2.0.0-1:sentinel-source=howy-rocm:2.0.0-1'
assert_contains 'candidate-origin target resume retains normalization reconcile' \
    "${target_resume_log}" \
    'howy:package reconcile --allow-legacy-candidate-mode0 --normalize-legacy-candidate-mode0'
assert_contains 'target-state bridge runs without a stale sentinel' \
    "${target_resume_log}" \
    'bridge:complete-release-n:marker-absent:sentinel-absent'
assert_contains 'stored socket disablement is restored on target resume' \
    "${target_resume_log}" 'systemctl:disable howy.socket'
assert_contains 'stored service activity is restored on target resume' \
    "${target_resume_log}" 'systemctl:start howy.service'
[[ "$(<"${RESUME_CASE_ROOT}/config.toml")" == \
    'live config from completed pacman' ]] \
    || fail 'target-state resume restored the stale config snapshot'
pass
[[ "$(<"${RESUME_CASE_ROOT}/receipt-v1.json")" == \
    'live receipt from completed pacman' ]] \
    || fail 'target-state resume restored the stale receipt snapshot'
pass
[[ ! -e "${RESUME_CASE_ROOT}/backup" && ! -L "${RESUME_CASE_ROOT}/backup" ]] \
    || fail 'target-state resume did not clean its exact backup'
pass
[[ ! -e "${RESUME_CASE_ROOT}/prepared" && ! -L "${RESUME_CASE_ROOT}/prepared" ]] \
    || fail 'target-state resume left a prepared sentinel'
pass

prepare_resume_case archive-mismatch legacy \
    howy-rocm-mode0 0.1.0.r27.g0b76fa2-6 source archive-hash-mismatch
expect_failure 'retained backup exact archive hash mismatch refusal' run_resume_main_case
archive_mismatch_log=$(<"${RESUME_LOG}")
assert_not_contains 'archive mismatch refuses before installed package query' \
    "${archive_mismatch_log}" 'pacman:'
assert_not_contains 'archive mismatch refuses before unit stop' \
    "${archive_mismatch_log}" 'systemctl:stop'
[[ -d "${RESUME_CASE_ROOT}/backup" ]] \
    || fail 'archive mismatch removed the retained backup'
pass

prepare_resume_case archive-path-mismatch legacy \
    howy-rocm-mode0 0.1.0.r27.g0b76fa2-6 source archive-path-mismatch
expect_failure 'retained backup exact archive path mismatch refusal' run_resume_main_case
archive_path_mismatch_log=$(<"${RESUME_LOG}")
assert_not_contains 'archive path mismatch refuses before installed package query' \
    "${archive_path_mismatch_log}" 'pacman:'
assert_not_contains 'archive path mismatch refuses before unit stop' \
    "${archive_path_mismatch_log}" 'systemctl:stop'
[[ -d "${RESUME_CASE_ROOT}/backup" ]] \
    || fail 'archive path mismatch removed the retained backup'
pass

for installed_state in ambiguous source-version-mismatch target-version-mismatch absent; do
    prepare_resume_case "state-refusal-${installed_state}" current \
        howy-rocm-mode0 0.1.0.r27.g0b76fa2-6 "${installed_state}" success
    expect_failure "resume refuses ${installed_state} installed state" run_resume_main_case
    state_refusal_log=$(<"${RESUME_LOG}")
    assert_not_contains "${installed_state} refuses before pacman transaction" \
        "${state_refusal_log}" 'pacman:--ask=4 -U'
    assert_not_contains "${installed_state} refuses before unit stop" \
        "${state_refusal_log}" 'systemctl:stop'
    [[ -d "${RESUME_CASE_ROOT}/backup" ]] \
        || fail "${installed_state} refusal removed the retained backup"
    pass
done

prepare_resume_case pacman-failure current \
    howy-rocm-mode0 0.1.0.r27.g0b76fa2-6 source pacman-failure
expect_failure 'resumed pacman failure retains exact backup' run_resume_main_case
pacman_failure_log=$(<"${RESUME_LOG}")
assert_contains 'resumed pacman failure saw its prepared sentinel' \
    "${pacman_failure_log}" \
    'pacman-binding:source=howy-rocm-mode0:0.1.0.r27.g0b76fa2-6:target=howy-rocm:2.0.0-1:sentinel-source=howy-rocm-mode0:0.1.0.r27.g0b76fa2-6'
[[ -d "${RESUME_CASE_ROOT}/backup" ]] \
    || fail 'resumed pacman failure removed the retained backup'
pass
[[ ! -e "${RESUME_CASE_ROOT}/prepared" && ! -L "${RESUME_CASE_ROOT}/prepared" ]] \
    || fail 'resumed pacman failure left a stale prepared sentinel'
pass

prepare_resume_case bridge-failure current \
    howy-rocm-mode0 0.1.0.r27.g0b76fa2-6 source bridge-failure
expect_failure 'resume finalization failure retains exact backup' run_resume_main_case
bridge_failure_log=$(<"${RESUME_LOG}")
assert_contains 'resume finalization failure reran pacman before bridge' \
    "${bridge_failure_log}" 'pacman:--ask=4 -U --noconfirm --'
assert_contains 'resume failure reached bridge after sentinel removal' \
    "${bridge_failure_log}" \
    'bridge:complete-release-n:marker-absent:sentinel-absent'
[[ -d "${RESUME_CASE_ROOT}/backup" \
    && -f "${RESUME_CASE_ROOT}/backup/metadata" \
    && -f "${RESUME_CASE_ROOT}/backup/config.toml" ]] \
    || fail 'resume finalization failure did not retain the exact backup'
pass
[[ ! -e "${RESUME_CASE_ROOT}/prepared" && ! -L "${RESUME_CASE_ROOT}/prepared" ]] \
    || fail 'resume finalization failure left a stale prepared sentinel'
pass

ADMISSION_SENTINEL_PATH="${WORK}/howy-v2-update-v1.prepared"
admission_helper_text=$(<"${ADMISSION_HELPER}")

run_update_admission_case() (
    local mode="$1"
    local target_input="$2"
    local transformed=${admission_helper_text}
    shift 2

    transformed=${transformed//SENTINEL_PATH/ADMISSION_SENTINEL_PATH}
    transformed=${transformed//TARGET_VERSION/ADMISSION_TARGET_VERSION}
    transformed=${transformed//\/run\/howy-v2-update-v1.prepared/${ADMISSION_SENTINEL_PATH}}
    transformed=${transformed//\/usr\/bin\/id/admission_id_mock}
    transformed=${transformed//\/usr\/bin\/stat/admission_stat_mock}
    HOWY_V2_UPDATE_ADMISSION_INTERNAL_TEST=1
    # shellcheck source=/dev/null
    source <(printf '%s\n' "${transformed}")

    admission_id_mock() {
        if [[ "${mode}" == nonroot ]]; then
            printf '1000\n'
        else
            printf '0\n'
        fi
    }
    admission_stat_mock() {
        case "${mode}" in
            stat-failure) return 1 ;;
            wrong-owner) printf '1000:0:600\n' ;;
            wrong-mode) printf '0:0:640\n' ;;
            *) printf '0:0:600\n' ;;
        esac
    }

    printf '%s' "${target_input}" | main "$@"
)

write_admission_fixture() {
    local archive="$1"
    local hash="$2"
    local source_package="$3"
    local source_version="$4"
    local target_package="$5"
    local target_version="$6"

    printf '%s\n' \
        'format=howy-v2-update-v1' \
        "archive=${archive}" \
        "archive_sha256=${hash}" \
        "source_package=${source_package}" \
        "source_version=${source_version}" \
        "target_package=${target_package}" \
        "target_version=${target_version}" > "${ADMISSION_SENTINEL_PATH}"
    /usr/bin/chmod 0600 "${ADMISSION_SENTINEL_PATH}"
}

# Use the updater's actual seven-line writer so a same-name stable update is
# admitted by the installed helper rather than merely by a duplicated fixture.
sentinel_writer_function=$(declare -f write_sentinel)
sentinel_writer_function=${sentinel_writer_function//SENTINEL_PATH/ADMISSION_SENTINEL_PATH}
sentinel_writer_function=${sentinel_writer_function//\/usr\/bin\/stat/updater_sentinel_stat_mock}
eval "${sentinel_writer_function}"
updater_sentinel_stat_mock() {
    printf '0:0:600\n'
}
ARCHIVE_PATH='/tmp/howy-cpu-2.0.0-1-x86_64.pkg.tar.zst'
ARCHIVE_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
SOURCE_PACKAGE=howy-cpu
SOURCE_VERSION=2.0.0-1
ARCHIVE_PKGNAME=howy-cpu
ARCHIVE_PKGVER=2.0.0-1
SENTINEL_CREATED=0
expect_success 'updater writes same-name prepared sentinel' write_sentinel
mapfile -t updater_sentinel_lines < "${ADMISSION_SENTINEL_PATH}"
[[ "${#updater_sentinel_lines[@]}" -eq 7 \
    && "${updater_sentinel_lines[0]}" == 'format=howy-v2-update-v1' \
    && "${updater_sentinel_lines[1]}" == "archive=${ARCHIVE_PATH}" \
    && "${updater_sentinel_lines[2]}" == "archive_sha256=${ARCHIVE_SHA256}" \
    && "${updater_sentinel_lines[3]}" == "source_package=${SOURCE_PACKAGE}" \
    && "${updater_sentinel_lines[4]}" == "source_version=${SOURCE_VERSION}" \
    && "${updater_sentinel_lines[5]}" == "target_package=${ARCHIVE_PKGNAME}" \
    && "${updater_sentinel_lines[6]}" == "target_version=${ARCHIVE_PKGVER}" ]] \
    || fail 'updater prepared sentinel is not the exact seven-line schema'
pass

expect_failure 'update-admission helper rejects arguments' \
    run_update_admission_case root $'howy-cpu\n' unexpected
expect_failure 'update-admission helper is root-only' \
    run_update_admission_case nonroot $'howy-cpu\n'
expect_failure 'update-admission helper rejects zero targets' \
    run_update_admission_case root ''
expect_failure 'update-admission helper rejects multiple targets' \
    run_update_admission_case root $'howy-cpu\nhowy-rocm\n'
expect_failure 'update-admission helper rejects a predecessor target' \
    run_update_admission_case root $'howy-cpu-git\n'

sentinel_hash_before=$(/usr/bin/sha256sum -- "${ADMISSION_SENTINEL_PATH}")
expect_success 'updater-produced same-name sentinel is admitted' \
    run_update_admission_case root $'howy-cpu\n'
sentinel_hash_after=$(/usr/bin/sha256sum -- "${ADMISSION_SENTINEL_PATH}")
[[ "${sentinel_hash_after}" == "${sentinel_hash_before}" ]] \
    || fail 'valid update admission mutated the prepared sentinel'
pass

expect_failure 'update-admission helper rejects unreadable metadata' \
    run_update_admission_case stat-failure $'howy-cpu\n'
expect_failure 'update-admission helper rejects non-root sentinel ownership' \
    run_update_admission_case wrong-owner $'howy-cpu\n'
expect_failure 'update-admission helper rejects non-0600 sentinel mode' \
    run_update_admission_case wrong-mode $'howy-cpu\n'

/usr/bin/rm -- "${ADMISSION_SENTINEL_PATH}"
expect_failure 'update-admission helper rejects a missing sentinel' \
    run_update_admission_case root $'howy-cpu\n'
/usr/bin/ln -s missing-sentinel "${ADMISSION_SENTINEL_PATH}"
expect_failure 'update-admission helper rejects a sentinel symlink' \
    run_update_admission_case root $'howy-cpu\n'
/usr/bin/rm -- "${ADMISSION_SENTINEL_PATH}"

write_admission_fixture \
    /tmp/howy.pkg.tar.zst \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    howy-cpu 2.0.0-1 howy-cpu 2.0.0-1
printf 'extra=field\n' >> "${ADMISSION_SENTINEL_PATH}"
expect_failure 'update-admission helper rejects an eighth schema line' \
    run_update_admission_case root $'howy-cpu\n'
write_admission_fixture \
    /tmp/howy.pkg.tar.zst \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    howy-cpu 2.0.0-1 howy-cpu 2.0.0-1
printf '%s' "$(<"${ADMISSION_SENTINEL_PATH}")" > "${ADMISSION_SENTINEL_PATH}"
expect_failure 'update-admission helper rejects a noncanonical final line' \
    run_update_admission_case root $'howy-cpu\n'

write_admission_fixture \
    relative/howy.pkg.tar.zst \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    howy-cpu 2.0.0-1 howy-cpu 2.0.0-1
expect_failure 'update-admission helper requires an absolute archive' \
    run_update_admission_case root $'howy-cpu\n'
write_admission_fixture \
    /tmp/howy.pkg.tar.zst \
    Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    howy-cpu 2.0.0-1 howy-cpu 2.0.0-1
expect_failure 'update-admission helper rejects a non-lowercase hash' \
    run_update_admission_case root $'howy-cpu\n'
write_admission_fixture \
    /tmp/howy.pkg.tar.zst \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    howy-cpu 2.0.0-1 howy-cpu 2.0.0-1
expect_failure 'update-admission helper rejects a non-64-character hash' \
    run_update_admission_case root $'howy-cpu\n'
write_admission_fixture \
    /tmp/howy.pkg.tar.zst \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    howy-rocm 2.0.0-1 howy-cpu 2.0.0-1
expect_failure 'update-admission helper rejects source-target mismatch' \
    run_update_admission_case root $'howy-cpu\n'
write_admission_fixture \
    /tmp/howy.pkg.tar.zst \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    howy-cpu 2.0.0-1 howy-cpu 2.0.0-1
expect_failure 'update-admission helper rejects trigger-target mismatch' \
    run_update_admission_case root $'howy-rocm\n'
write_admission_fixture \
    /tmp/howy.pkg.tar.zst \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    howy-cpu 1.9.0-1 howy-cpu 2.0.0-1
expect_failure 'update-admission helper rejects source-version mismatch' \
    run_update_admission_case root $'howy-cpu\n'
write_admission_fixture \
    /tmp/howy.pkg.tar.zst \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    howy-cpu 2.0.0-1 howy-cpu 2.0.0-2
expect_failure 'update-admission helper rejects target-version mismatch' \
    run_update_admission_case root $'howy-cpu\n'

main_function=$(declare -f main)
resume_function=$(declare -f resume_retained_update)
stop_function=$(declare -f stop_units)
post_function=$(declare -f post_pacman_steps)
restore_config_function=$(declare -f restore_config)
restore_units_function=$(declare -f restore_unit_intent)
cleanup_function=$(declare -f remove_completed_backup)
retain_function=$(declare -f retain_failure)
updater_text=$(<"${UPDATER}")

assert_order 'release marker required before bridge validation' \
    "${production_transition_preflight_function}" \
    'require_package_marker' 'release_n_marker_is_schema1_generation_null'
assert_order 'release generation-null proof before identity capture' \
    "${production_transition_preflight_function}" \
    'release_n_marker_is_schema1_generation_null' "/usr/bin/stat -c '%d:%i:%s:%a:%h'"
assert_order 'release identity captured before predecessor completion' \
    "${production_transition_preflight_function}" \
    'marker_hash_before=' '/usr/lib/howy/howy-config-bridge complete-release-n'
assert_order 'release validation before stash' "${production_transition_preflight_function}" \
    '/usr/lib/howy/howy-config-bridge complete-release-n' \
    '/usr/lib/howy/howy-config-bridge stash-release-n'
assert_order 'release post-completion identity proof before stash' \
    "${production_transition_preflight_function}" \
    'marker_hash_after=' '/usr/lib/howy/howy-config-bridge stash-release-n'
assert_order 'release stash before absent-marker proof' \
    "${production_transition_preflight_function}" \
    '/usr/lib/howy/howy-config-bridge stash-release-n' 'path_is_absent "${MARKER_PATH}"'
assert_order 'stable read-only validator before stash' \
    "${production_transition_preflight_function}" \
    '/usr/lib/howy/howy-config-bridge validate-current-marker' \
    '/usr/lib/howy/howy-config-bridge stash-release-n'
assert_contains 'generated release-N marker refusal' \
    "${production_transition_preflight_function}" \
    'generated release-N package markers are unsupported by the v2 updater'
assert_contains 'candidate exact marker preflight remains exact' \
    "${production_transition_preflight_function}" 'candidate_marker_is_exact "${MARKER_PATH}"'
assert_order 'candidate marker precedes exact mode 0600 config preflight' \
    "${production_transition_preflight_function}" \
    'candidate_marker_is_exact "${MARKER_PATH}"' 'require_candidate_config'
assert_order 'transition preflight before backup' "${main_function}" \
    'preflight_transition_state' 'create_backup'
assert_order 'backup before stop' "${main_function}" 'create_backup' 'stop_units'
assert_order 'socket before service stop' "${stop_function}" \
    'stop howy.socket' 'stop howy.service'
assert_order 'archive revalidation before pacman' "${main_function}" \
    'require_archive_unchanged' '/usr/bin/pacman --ask=4 -U --noconfirm -- "${ARCHIVE_PATH}"'
assert_order 'prepared sentinel before transaction bindings' "${main_function}" \
    'write_sentinel' 'HOWY_V2_UPDATE_FORMAT="${UPDATE_FORMAT}"'
assert_order 'transaction bindings before pacman' "${main_function}" \
    'HOWY_V2_UPDATE_FORMAT="${UPDATE_FORMAT}"' \
    '/usr/bin/pacman --ask=4 -U --noconfirm -- "${ARCHIVE_PATH}"'
assert_count 'exact inline transaction binding count' "${main_function}" \
    'HOWY_V2_UPDATE_' 7
assert_order 'resume archive revalidation before sentinel' "${resume_function}" \
    'require_archive_unchanged' 'write_sentinel'
assert_order 'resume sentinel before transaction bindings' "${resume_function}" \
    'write_sentinel' 'HOWY_V2_UPDATE_FORMAT="${UPDATE_FORMAT}"'
assert_order 'resume transaction bindings before pacman' "${resume_function}" \
    'HOWY_V2_UPDATE_FORMAT="${UPDATE_FORMAT}"' \
    '/usr/bin/pacman --ask=4 -U --noconfirm -- "${ARCHIVE_PATH}"'
assert_count 'exact resumed transaction binding count' "${resume_function}" \
    'HOWY_V2_UPDATE_' 7
assert_order 'resumed pacman before sentinel removal' "${resume_function}" \
    '/usr/bin/pacman --ask=4 -U --noconfirm -- "${ARCHIVE_PATH}"' \
    '/usr/bin/rm -f -- "${SENTINEL_PATH}"'
assert_order 'resume sentinel removal before post-pacman work' "${resume_function}" \
    '/usr/bin/rm -f -- "${SENTINEL_PATH}"' 'post_pacman_steps'
assert_order 'resume post-pacman work before backup cleanup' "${resume_function}" \
    'post_pacman_steps' 'remove_completed_backup'
assert_not_contains 'transaction bindings are not persistent exports' \
    "${updater_text}" 'export HOWY_V2_UPDATE_'
assert_order 'config restore before bridge completion' "${post_function}" \
    'restore_config' '/usr/lib/howy/howy-config-bridge complete-release-n'
assert_order 'bridge completion before reconcile' "${post_function}" \
    '/usr/lib/howy/howy-config-bridge complete-release-n' '/usr/bin/howy package reconcile'
assert_contains 'restored config metadata contract' "${restore_config_function}" \
    "0:0:\${mode}:1"
assert_order 'reconcile before unit restoration' "${post_function}" \
    '/usr/bin/howy package reconcile' 'restore_unit_intent'
assert_order 'enablement before socket start' "${restore_units_function}" \
    'set_unit_enablement howy.service' '/usr/bin/systemctl start howy.socket'
assert_order 'socket start before service start' "${restore_units_function}" \
    '/usr/bin/systemctl start howy.socket' '/usr/bin/systemctl start howy.service'
assert_order 'post-pacman success before backup cleanup' "${main_function}" \
    'post_pacman_steps' 'remove_completed_backup'
assert_contains 'pacman failure contract' "${main_function}" "retain_failure 'pacman -U failed'"
assert_contains 'reconcile failure is nonzero' "${post_function}" \
    '/usr/bin/howy package reconcile || return 1'
assert_contains 'candidate legacy reconcile admission' "${post_function}" \
    '/usr/bin/howy package reconcile --allow-legacy-candidate-mode0'
assert_contains 'candidate legacy normalization option' "${post_function}" \
    '--normalize-legacy-candidate-mode0'
assert_contains 'unit restoration failure is nonzero' "${post_function}" \
    'restore_unit_intent || return 1'
assert_contains 'post-pacman failure contract' "${main_function}" \
    "retain_failure 'post-install verification, reconciliation, or unit restoration failed'"
assert_contains 'failure stop contract' "${retain_function}" 'best_effort_stop_units'
assert_not_contains 'failure path retains backup' "${retain_function}" 'remove_completed_backup'
assert_contains 'failure backup review guidance' "${retain_function}" \
    'inspect and preserve any needed backup files before recovery'
assert_contains 'failure exact-archive resume guidance' "${retain_function}" \
    'rerunning the updater with the exact archive resumes finalization'
assert_order 'cleanup validates before removal' "${cleanup_function}" \
    'backup_contents_are_expected' '/usr/bin/rm -- "${files[@]}"'
assert_contains 'cleanup exact directory removal' "${cleanup_function}" \
    '/usr/bin/rmdir -- "${BACKUP_PATH}"'
assert_not_contains 'updater success cleanup' "${updater_text}" '/usr/bin/rm -rf'
assert_not_contains 'validation refusals never rely on OR-list control flow' \
    "${updater_text}" '|| refuse'
assert_not_contains 'release-N preflight does not parse bridge manifests' \
    "${updater_text}" 'manifest'
assert_contains 'strict shell mode' "${updater_text}" 'set -euo pipefail'
assert_order 'sentinel trap precedes side effects' "${main_function}" \
    'trap cleanup_sentinel EXIT' 'validate_archive'

POST_PACMAN_LOG="${WORK}/post-pacman.log"
run_post_pacman_reconcile_sequence() (
    local strict_status="$1"
    local transition
    local transformed
    shift

    transformed=$(declare -f post_pacman_steps)
    transformed=${transformed//\/usr\/lib\/howy\/howy-config-bridge/post_pacman_bridge_mock}
    transformed=${transformed//\/usr\/bin\/howy/post_pacman_howy_mock}
    eval "${transformed}"

    verify_installed_result() { :; }
    path_is_absent() { :; }
    restore_config() { :; }
    verify_receipt_preservation() { :; }
    restore_unit_intent() { :; }
    verify_unit_intent() { :; }
    post_pacman_bridge_mock() {
        [[ "$*" == complete-release-n ]] || return 1
        printf 'bridge:%s\n' "$*" >> "${POST_PACMAN_LOG}"
    }
    post_pacman_howy_mock() {
        printf 'howy:%s\n' "$*" >> "${POST_PACMAN_LOG}"
        if [[ "$*" == 'package reconcile' ]]; then
            return "${strict_status}"
        fi
        [[ "$*" == \
            'package reconcile --allow-legacy-candidate-mode0 --normalize-legacy-candidate-mode0' ]]
    }

    RECEIPT_EXISTED=1
    : > "${POST_PACMAN_LOG}"
    for transition in "$@"; do
        TRANSITION_KIND=${transition}
        post_pacman_steps || return 1
    done
)

expect_success 'candidate invokes one locked Rust normalization reconcile' \
    run_post_pacman_reconcile_sequence 1 candidate
[[ "$(<"${POST_PACMAN_LOG}")" == \
    $'bridge:complete-release-n\nhowy:package reconcile --allow-legacy-candidate-mode0 --normalize-legacy-candidate-mode0' ]] \
    || fail 'candidate post-pacman steps did not use the exact combined reconcile flags'
pass

expect_failure 'stable damaged Mode 0 remains strict and refused' \
    run_post_pacman_reconcile_sequence 1 stable
[[ "$(<"${POST_PACMAN_LOG}")" == \
    $'bridge:complete-release-n\nhowy:package reconcile' ]] \
    || fail 'stable damaged Mode 0 used anything other than strict reconciliation'
pass

expect_success 'release-N post-pacman reconcile remains strict' \
    run_post_pacman_reconcile_sequence 0 release-n
[[ "$(<"${POST_PACMAN_LOG}")" == \
    $'bridge:complete-release-n\nhowy:package reconcile' ]] \
    || fail 'release-N post-pacman steps used anything other than strict reconciliation'
pass

expect_success 'candidate normalization to stable same-v2 branch sequence' \
    run_post_pacman_reconcile_sequence 0 candidate stable
post_pacman_log=$(<"${POST_PACMAN_LOG}")
[[ "${post_pacman_log}" == \
    $'bridge:complete-release-n\nhowy:package reconcile --allow-legacy-candidate-mode0 --normalize-legacy-candidate-mode0\nbridge:complete-release-n\nhowy:package reconcile' ]] \
    || fail 'candidate to stable same-v2 sequence used the wrong reconcile branches'
pass

SOURCE_PACKAGE=howy-cpu
SOURCE_VERSION=original-version
ARCHIVE_PKGNAME=howy-cpu
query_package_version() {
    printf '%s\n' "${TARGET_VERSION}"
}
query_single_provider() {
    SOURCE_PACKAGE=howy-cpu
    SOURCE_VERSION=${TARGET_VERSION}
}
expect_success 'installed result validation' verify_installed_result
[[ "${SOURCE_PACKAGE}:${SOURCE_VERSION}" == 'howy-cpu:original-version' ]] \
    || fail 'installed-result query clobbered predecessor identity'
pass

FAILURE_STOP_CALLED=0
best_effort_stop_units() {
    FAILURE_STOP_CALLED=1
}
expect_failure 'retain_failure is nonzero' retain_failure 'mock failure'
[[ "${FAILURE_STOP_CALLED}" -eq 1 ]] || fail 'retain_failure did not stop units'
pass

TRANSITION_KIND=candidate
if candidate_recovery=$(retain_failure 'candidate mock failure' 2>&1); then
    fail 'candidate retain_failure unexpectedly succeeded'
fi
assert_contains 'candidate recovery exact-archive resume guidance' "${candidate_recovery}" \
    'rerunning the updater with the exact archive resumes finalization'
assert_contains 'candidate recovery admission caveat' "${candidate_recovery}" \
    'retained metadata and installed source or target state are admissible'

for transition in stable release-n; do
    TRANSITION_KIND=${transition}
    if generic_recovery=$(retain_failure "${transition} mock failure" 2>&1); then
        fail "${transition} retain_failure unexpectedly succeeded"
    fi
    assert_contains "${transition} retains exact-archive resume guidance" \
        "${generic_recovery}" \
        'rerunning the updater with the exact archive resumes finalization'
done

pkgbuild_text=$(<"${PKGBUILD_PATH}")
srcinfo_text=$(<"${SRCINFO_PATH}")
hook_text=$(<"${HOOK_PATH}")
admission_hook_text=$(<"${ADMISSION_HOOK_PATH}")
remove_hook_text=$(<"${REMOVE_HOOK_PATH}")
admission_helper_text=$(<"${ADMISSION_HELPER}")
remove_helper_text=$(<"${REMOVE_HELPER}")
assert_contains 'PKGBUILD canonical base' "${pkgbuild_text}" 'pkgbase=howy'
assert_contains 'PKGBUILD canonical variants' "${pkgbuild_text}" \
    'pkgname=(howy-cpu howy-rocm howy-cuda)'
assert_contains 'PKGBUILD exact version' "${pkgbuild_text}" 'pkgver=2.0.0'
assert_not_contains 'PKGBUILD has zero automatic replacements' "${pkgbuild_text}" 'replaces='
assert_contains 'relative PAM compatibility alias' "${pkgbuild_text}" \
    'ln -s pam_howy.so "${pkgdir}/usr/lib/security/pam_howdy.so"'
assert_contains 'updater package path and mode' "${pkgbuild_text}" \
    'install -Dm755 scripts/howy-v2-update "${pkgdir}/usr/bin/howy-v2-update"'
assert_contains 'update-admission helper package path and mode' "${pkgbuild_text}" \
    'install -Dm755 scripts/howy-v2-update-admission "${pkgdir}/usr/lib/howy/howy-v2-update-admission"'
assert_contains 'update-admission hook package path and mode' "${pkgbuild_text}" \
    'install -Dm644 packaging/00-howy-update-admission.hook "${pkgdir}/usr/share/libalpm/hooks/00-howy-update-admission.hook"'
assert_contains 'removal helper package path and mode' "${pkgbuild_text}" \
    'install -Dm755 scripts/howy-v2-remove-prepare "${pkgdir}/usr/lib/howy/howy-v2-remove-prepare"'
assert_contains 'removal hook package path and mode' "${pkgbuild_text}" \
    'install -Dm644 packaging/10-howy-remove-prepare.hook "${pkgdir}/usr/share/libalpm/hooks/10-howy-remove-prepare.hook"'
assert_count 'config backup declarations' "${pkgbuild_text}" \
    "backup=('etc/howy/config.toml')" 3
assert_count 'PKGBUILD ABI-pinned virtual ONNX Runtime build dependency' "${pkgbuild_text}" \
    "  'onnxruntime=1.28.0'" 1
assert_count 'PKGBUILD ABI-pinned virtual ONNX Runtime runtime dependencies' "${pkgbuild_text}" \
    "  depends=('diffutils' 'onnxruntime=1.28.0' 'pam' 'systemd>=261')" 3
assert_count 'PKGBUILD direct diffutils runtime dependencies' "${pkgbuild_text}" \
    "'diffutils'" 3
for concrete_runtime in onnxruntime-cpu onnxruntime-rocm onnxruntime-cuda; do
    assert_not_contains "PKGBUILD concrete ONNX Runtime dependency ${concrete_runtime}" \
        "${pkgbuild_text}" "${concrete_runtime}"
done

assert_contains '.SRCINFO canonical base' "${srcinfo_text}" 'pkgbase = howy'
for package in howy-cpu howy-rocm howy-cuda; do
    assert_contains ".SRCINFO ${package}" "${srcinfo_text}" "pkgname = ${package}"
done
assert_not_contains '.SRCINFO old split identity' "${srcinfo_text}" 'pkgname = howy-cpu-git'
assert_count '.SRCINFO config backup declarations' "${srcinfo_text}" \
    $'\tbackup = etc/howy/config.toml' 3
assert_count '.SRCINFO has zero automatic replacements' "${srcinfo_text}" $'\treplaces = ' 0
assert_count '.SRCINFO ABI-pinned virtual ONNX Runtime build dependency' "${srcinfo_text}" \
    $'\tmakedepends = onnxruntime=1.28.0' 1
assert_count '.SRCINFO ABI-pinned virtual ONNX Runtime runtime dependencies' "${srcinfo_text}" \
    $'\tdepends = onnxruntime=1.28.0' 3
assert_count '.SRCINFO direct diffutils runtime dependencies' "${srcinfo_text}" \
    $'\tdepends = diffutils' 3
for concrete_runtime in onnxruntime-cpu onnxruntime-rocm onnxruntime-cuda; do
    assert_not_contains ".SRCINFO concrete ONNX Runtime dependency ${concrete_runtime}" \
        "${srcinfo_text}" "${concrete_runtime}"
done
assert_count 'stable hook target count' "${hook_text}" 'Target = ' 3
for package in howy-cpu howy-rocm howy-cuda; do
    assert_contains "stable hook ${package}" "${hook_text}" "Target = ${package}"
done
assert_not_contains 'stable hook legacy targets' "${hook_text}" 'Target = howy-cpu-git'
expected_admission_hook=$'[Trigger]\nOperation = Upgrade\nType = Package\nTarget = howy-cpu\nTarget = howy-rocm\nTarget = howy-cuda\n\n[Action]\nDescription = Verifying Howy stable update admission\nWhen = PreTransaction\nExec = /usr/lib/howy/howy-v2-update-admission\nAbortOnFail\nNeedsTargets'
[[ "${admission_hook_text}" == "${expected_admission_hook}" ]] \
    || fail 'update-admission hook differs from the exact upgrade-only contract'
pass
[[ "$(/usr/bin/basename "${ADMISSION_HOOK_PATH}")" \
    < "$(/usr/bin/basename "${HOOK_PATH}")" ]] \
    || fail 'update-admission hook does not sort before the config stash hook'
pass
assert_contains 'update-admission helper strict shell mode' \
    "${admission_helper_text}" 'set -euo pipefail'
assert_not_contains 'update-admission helper does not mutate the sentinel' \
    "${admission_helper_text}" '/usr/bin/rm'
assert_count 'removal hook stable target count' "${remove_hook_text}" 'Target = ' 3
for package in howy-cpu howy-rocm howy-cuda; do
    assert_contains "removal hook ${package}" "${remove_hook_text}" "Target = ${package}"
done
assert_contains 'removal hook remove-only trigger' "${remove_hook_text}" 'Operation = Remove'
assert_not_contains 'removal hook does not run on upgrade' "${remove_hook_text}" 'Operation = Upgrade'
assert_contains 'removal hook is pretransaction' "${remove_hook_text}" 'When = PreTransaction'
assert_contains 'removal hook aborts ALPM' "${remove_hook_text}" 'AbortOnFail'
assert_contains 'removal hook invokes exact helper' "${remove_hook_text}" \
    'Exec = /usr/lib/howy/howy-v2-remove-prepare'
[[ "$(/usr/bin/basename "${HOOK_PATH}")" < "$(/usr/bin/basename "${REMOVE_HOOK_PATH}")" ]] \
    || fail 'removal hook does not sort after the config stash hook'
pass
assert_order 'removal helper socket before service stop' "${remove_helper_text}" \
    '/usr/bin/systemctl stop howy.socket' '/usr/bin/systemctl stop howy.service'
assert_order 'removal helper stops before disable' "${remove_helper_text}" \
    '/usr/bin/systemctl stop howy.service' '/usr/bin/systemctl disable howy.socket howy.service'
assert_contains 'removal helper verifies inactive state' "${remove_helper_text}" \
    'require_unit_property howy.socket ActiveState inactive'
assert_contains 'removal helper verifies disabled state' "${remove_helper_text}" \
    'require_unit_property howy.socket UnitFileState disabled'

REMOVE_HELPER_LOG="${WORK}/remove-helper.log"
run_remove_helper_case() (
    local mode="$1"
    local transformed=${remove_helper_text}
    transformed=${transformed//\/usr\/bin\/id/helper_id_mock}
    transformed=${transformed//\/usr\/bin\/systemctl/helper_systemctl_mock}

    HOWY_V2_REMOVE_PREPARE_INTERNAL_TEST=1
    # shellcheck source=/dev/null
    source <(printf '%s\n' "${transformed}")
    helper_id_mock() {
        [[ "${mode}" != nonroot ]] || {
            printf '1000\n'
            return 0
        }
        printf '0\n'
    }
    helper_systemctl_mock() {
        local property
        printf '%s\n' "$*" >> "${REMOVE_HELPER_LOG}"
        if [[ "${mode}" == stop-failure && "$*" == 'stop howy.socket' ]]; then
            return 1
        fi
        if [[ "$1" == show ]]; then
            property=${2#--property=}
            case "${property}" in
                ActiveState)
                    if [[ "${mode}" == wrong-state && "${!#}" == howy.socket ]]; then
                        printf 'active\n'
                    else
                        printf 'inactive\n'
                    fi
                    ;;
                UnitFileState) printf 'disabled\n' ;;
                *) return 99 ;;
            esac
        fi
    }
    main
)

: > "${REMOVE_HELPER_LOG}"
expect_success 'complete removal helper success' run_remove_helper_case success
helper_log=$(<"${REMOVE_HELPER_LOG}")
assert_order 'complete helper socket/service order' "${helper_log}" \
    'stop howy.socket' 'stop howy.service'
assert_order 'complete helper stop/disable order' "${helper_log}" \
    'stop howy.service' 'disable howy.socket howy.service'
assert_contains 'complete helper active-state verification' "${helper_log}" \
    'show --property=ActiveState --value howy.socket'
assert_contains 'complete helper unit-file verification' "${helper_log}" \
    'show --property=UnitFileState --value howy.service'
: > "${REMOVE_HELPER_LOG}"
expect_failure 'removal helper root-only admission' run_remove_helper_case nonroot
[[ ! -s "${REMOVE_HELPER_LOG}" ]] || fail 'nonroot removal helper touched systemd'
pass
expect_failure 'removal helper stop failure' run_remove_helper_case stop-failure
expect_failure 'removal helper inactive verification failure' run_remove_helper_case wrong-state

MOCK_DIR="${WORK}/install-script"
/usr/bin/mkdir "${MOCK_DIR}"
prepared_path="${MOCK_DIR}/prepared"
prepared_archive="${MOCK_DIR}/howy-rocm-2.0.0-1-x86_64.pkg.tar.zst"
prepared_archive_sha=''
marker_path="${MOCK_DIR}/marker"
install_text=$(<"${INSTALL_SCRIPT}")
install_text=${install_text//\/usr\/lib\/howy\/howy-config-bridge/bridge_mock}
install_text=${install_text//\/usr\/lib\/howy\/howy-v2-remove-prepare/remove_prepare_mock}
install_text=${install_text//\/usr\/bin\/systemctl/systemctl_mock}
install_text=${install_text//\/usr\/bin\/stat/stat_mock}
install_text=${install_text//\/run\/howy-v2-update-v1.prepared/${prepared_path}}
install_text=${install_text//\/var\/lib\/howy-package-bootstrap.complete/${marker_path}}

INSTALL_LOG=''
BOOTSTRAP_STATUS=0
COMPLETE_STATUS=0
STASH_STATUS=0
SYSTEMCTL_FAILURE=''
bridge_mock() {
    INSTALL_LOG+="bridge:$1"$'\n'
    case "$1" in
        bootstrap-release-n) return "${BOOTSTRAP_STATUS}" ;;
        complete-release-n) return "${COMPLETE_STATUS}" ;;
        stash-release-n) return "${STASH_STATUS}" ;;
        *) return 99 ;;
    esac
}
systemctl_mock() {
    INSTALL_LOG+="systemctl:$*"$'\n'
    [[ "$*" != "${SYSTEMCTL_FAILURE}" ]]
}
remove_prepare_mock() {
    systemctl_mock stop howy.socket || return 1
    systemctl_mock stop howy.service || return 1
    systemctl_mock disable howy.socket howy.service
}
stat_mock() {
    if [[ "${!#}" == "${prepared_path}" ]]; then
        printf '0:0:600\n'
    else
        /usr/bin/stat "$@"
    fi
}
reset_prepared_archive() {
    local digest

    printf 'stable archive bytes\n' > "${prepared_archive}"
    digest=$(/usr/bin/sha256sum -- "${prepared_archive}")
    prepared_archive_sha=${digest%% *}
}
write_install_prepared_fixture() {
    printf '%s\n' \
        'format=howy-v2-update-v1' \
        "archive=${prepared_archive}" \
        "archive_sha256=${prepared_archive_sha}" \
        'source_package=howy-rocm-mode0' \
        'source_version=0.1.0.r27.g0b76fa2-6' \
        'target_package=howy-rocm' \
        'target_version=2.0.0-1' > "${prepared_path}"
}
run_bound_post_install() {
    local target_package="${1:-howy-rocm}"

    HOWY_V2_UPDATE_FORMAT=howy-v2-update-v1 \
    HOWY_V2_UPDATE_ARCHIVE="${prepared_archive}" \
    HOWY_V2_UPDATE_ARCHIVE_SHA256="${prepared_archive_sha}" \
    HOWY_V2_UPDATE_SOURCE_PACKAGE=howy-rocm-mode0 \
    HOWY_V2_UPDATE_SOURCE_VERSION=0.1.0.r27.g0b76fa2-6 \
    HOWY_V2_UPDATE_TARGET_PACKAGE="${target_package}" \
    HOWY_V2_UPDATE_TARGET_VERSION=2.0.0-1 \
        post_install
}
# shellcheck source=/dev/null
source <(printf '%s\n' "${install_text}")
unset \
    HOWY_V2_UPDATE_FORMAT \
    HOWY_V2_UPDATE_ARCHIVE \
    HOWY_V2_UPDATE_ARCHIVE_SHA256 \
    HOWY_V2_UPDATE_SOURCE_PACKAGE \
    HOWY_V2_UPDATE_SOURCE_VERSION \
    HOWY_V2_UPDATE_TARGET_PACKAGE \
    HOWY_V2_UPDATE_TARGET_VERSION
post_install_function=$(declare -f post_install)
assert_order 'prepared sentinel validation precedes fresh bootstrap' \
    "${post_install_function}" '_howy_prepared_update_exists' \
    'bridge_mock bootstrap-release-n'

INSTALL_LOG=''
BOOTSTRAP_STATUS=0
post_install > "${MOCK_DIR}/fresh.output"
fresh_output=$(<"${MOCK_DIR}/fresh.output")
assert_contains 'fresh install provision guidance' "${fresh_output}" \
    'sudo howy security provision --mode 1'
assert_contains 'fresh install enable guidance' "${fresh_output}" 'sudo howy security enable'
assert_contains 'fresh install bridge call' "${INSTALL_LOG}" 'bridge:bootstrap-release-n'

INSTALL_LOG=''
BOOTSTRAP_STATUS=1
/usr/bin/rm -f -- "${prepared_path}"
expect_failure 'fresh install bridge failure without sentinel' post_install
reset_prepared_archive
write_install_prepared_fixture
INSTALL_LOG=''
BOOTSTRAP_STATUS=0
run_bound_post_install > "${MOCK_DIR}/prepared.output" 2>&1 \
    || fail 'prepared candidate replacement did not defer fresh bootstrap'
prepared_output=$(<"${MOCK_DIR}/prepared.output")
assert_contains 'prepared update deferral' "${prepared_output}" \
    'configuration completion is deferred to howy-v2-update'
[[ -z "${INSTALL_LOG}" ]] \
    || fail 'prepared candidate replacement invoked the bootstrap bridge'
pass

printf 'extra=malformed\n' >> "${prepared_path}"
INSTALL_LOG=''
BOOTSTRAP_STATUS=1
if post_install > "${MOCK_DIR}/malformed.output" 2>&1; then
    fail 'malformed prepared sentinel bypassed bootstrap refusal'
fi
malformed_output=$(<"${MOCK_DIR}/malformed.output")
assert_not_contains 'malformed sentinel does not defer' "${malformed_output}" \
    'configuration completion is deferred to howy-v2-update'
assert_contains 'malformed sentinel reaches bootstrap' "${INSTALL_LOG}" \
    'bridge:bootstrap-release-n'
assert_contains 'malformed sentinel preserves refusal' "${malformed_output}" \
    'Howy refused to replace /etc/howy/config.toml'

write_install_prepared_fixture
INSTALL_LOG=''
BOOTSTRAP_STATUS=1
expect_failure 'unbound stale sentinel does not defer' post_install
assert_contains 'stale sentinel reaches bootstrap' "${INSTALL_LOG}" \
    'bridge:bootstrap-release-n'

write_install_prepared_fixture
/usr/bin/rm -- "${prepared_archive}"
INSTALL_LOG=''
expect_failure 'missing prepared archive does not defer' run_bound_post_install
assert_contains 'missing prepared archive reaches bootstrap' "${INSTALL_LOG}" \
    'bridge:bootstrap-release-n'

reset_prepared_archive
write_install_prepared_fixture
printf 'changed\n' >> "${prepared_archive}"
INSTALL_LOG=''
expect_failure 'changed prepared archive does not defer' run_bound_post_install
assert_contains 'changed prepared archive reaches bootstrap' "${INSTALL_LOG}" \
    'bridge:bootstrap-release-n'

reset_prepared_archive
write_install_prepared_fixture
INSTALL_LOG=''
expect_failure 'mismatched transaction binding does not defer' \
    run_bound_post_install howy-cpu
assert_contains 'mismatched transaction binding reaches bootstrap' "${INSTALL_LOG}" \
    'bridge:bootstrap-release-n'

INSTALL_LOG=''
COMPLETE_STATUS=0
post_upgrade >/dev/null
assert_contains 'upgrade bridge call' "${INSTALL_LOG}" 'bridge:complete-release-n'

INSTALL_LOG=''
STASH_STATUS=0
SYSTEMCTL_FAILURE=''
pre_remove
assert_order 'remove stash before socket stop' "${INSTALL_LOG}" \
    'bridge:stash-release-n' 'systemctl:stop howy.socket'
assert_order 'remove socket before service stop' "${INSTALL_LOG}" \
    'systemctl:stop howy.socket' 'systemctl:stop howy.service'
assert_order 'remove stops before disable' "${INSTALL_LOG}" \
    'systemctl:stop howy.service' 'systemctl:disable howy.socket howy.service'

INSTALL_LOG=''
SYSTEMCTL_FAILURE='stop howy.service'
expect_failure 'remove stop failure' pre_remove
assert_not_contains 'stop failure skips disable' "${INSTALL_LOG}" \
    'systemctl:disable howy.socket howy.service'

INSTALL_LOG=''
SYSTEMCTL_FAILURE='disable howy.socket howy.service'
expect_failure 'remove disable failure' pre_remove

INSTALL_LOG=''
SYSTEMCTL_FAILURE=''
/usr/bin/rm -f -- "${marker_path}"
post_remove >/dev/null
[[ "${INSTALL_LOG}" == $'systemctl:daemon-reload\n' ]] \
    || fail "post_remove ran commands other than daemon-reload: ${INSTALL_LOG}"
pass
printf 'unexpected\n' > "${marker_path}"
INSTALL_LOG=''
expect_failure 'post_remove marker absence verification' post_remove

printf 'package v2 updater: %d focused checks passed\n' "${PASSED}"
