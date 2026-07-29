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
    '/usr/bin/howy package reconcile --allow-legacy-candidate-mode0 || return 1'
assert_contains 'unit restoration failure is nonzero' "${post_function}" \
    'restore_unit_intent || return 1'
assert_contains 'post-pacman failure contract' "${main_function}" \
    "retain_failure 'post-install verification, reconciliation, or unit restoration failed'"
assert_contains 'failure stop contract' "${retain_function}" 'best_effort_stop_units'
assert_not_contains 'failure path retains backup' "${retain_function}" 'remove_completed_backup'
assert_contains 'failure backup review guidance' "${retain_function}" \
    'inspect and preserve any needed backup files before recovery'
assert_contains 'failure backup blocks retry guidance' "${retain_function}" \
    'the retained backup blocks a new updater run'
assert_contains 'failure backup explicit-removal guidance' "${retain_function}" \
    'explicitly remove only the reviewed backup files and then its empty directory'
assert_contains 'failure path rejects automatic resume promise' "${retain_function}" \
    'will not resume or remove the retained backup automatically'
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
assert_count 'PKGBUILD virtual ONNX Runtime build dependency' "${pkgbuild_text}" \
    "  'onnxruntime'" 1
assert_count 'PKGBUILD virtual ONNX Runtime runtime dependencies' "${pkgbuild_text}" \
    "  depends=('diffutils' 'onnxruntime' 'pam' 'systemd>=261')" 3
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
assert_count '.SRCINFO virtual ONNX Runtime build dependency' "${srcinfo_text}" \
    $'\tmakedepends = onnxruntime' 1
assert_count '.SRCINFO virtual ONNX Runtime runtime dependencies' "${srcinfo_text}" \
    $'\tdepends = onnxruntime' 3
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
