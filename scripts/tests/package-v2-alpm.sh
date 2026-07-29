#!/bin/bash

# Real libalpm proofs for the v2 updater/removal contract. Every pacman command
# uses a disposable root, database, cache, hook directory, and logfile under one
# temporary tree. A mapped-root user+mount namespace prevents access to the host
# package database and installed paths.

set -euo pipefail

TEST_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(dirname "$(dirname "${TEST_DIR}")")
PACMAN=/usr/bin/pacman
UNSHARE=/usr/bin/unshare
BSDTAR=/usr/bin/bsdtar

fail() {
    printf 'v2 isolated ALPM FAIL: %s\n' "$*" >&2
    exit 1
}

skip() {
    printf 'v2 isolated ALPM SKIP: %s\n' "$*" >&2
    exit 0
}

for tool in "${PACMAN}" "${UNSHARE}" "${BSDTAR}" /usr/bin/ldd /usr/bin/true; do
    [[ -x "${tool}" ]] || skip "required isolation capability is unavailable: ${tool}"
done

if ! unshare_reason=$("${UNSHARE}" --user --map-root-user --mount -- /usr/bin/true 2>&1); then
    skip "the kernel/container blocked mapped-root user+mount namespaces: ${unshare_reason}"
fi

WORK=$(/usr/bin/mktemp -d)
cleanup() {
    /usr/bin/rm -rf -- "${WORK}"
}
trap cleanup EXIT INT TERM
PACKAGES="${WORK}/packages"
/usr/bin/mkdir -p "${PACKAGES}"

copy_runtime_file() {
    local source="$1"
    local root="$2"
    local destination="${root}${source}"

    /usr/bin/mkdir -p "$(/usr/bin/dirname "${destination}")"
    /usr/bin/cp -L -- "${source}" "${destination}"
}

copy_runtime() {
    local binary="$1"
    local root="$2"
    local line token

    copy_runtime_file "${binary}" "${root}"
    while IFS= read -r line; do
        for token in ${line}; do
            token=${token%%\(*}
            if [[ "${token}" == /* && -f "${token}" ]]; then
                copy_runtime_file "${token}" "${root}"
            fi
        done
    done < <(/usr/bin/ldd "${binary}")
}

write_pkginfo() {
    local destination="$1"
    local name="$2"
    local version="$3"
    local conflict="${4:-}"

    {
        printf 'pkgname = %s\n' "${name}"
        printf 'pkgbase = %s\n' "${name}"
        printf 'pkgver = %s\n' "${version}"
        printf 'pkgdesc = isolated v2 ALPM fixture\n'
        printf 'url = https://example.invalid/howy-v2-alpm-fixture\n'
        printf 'builddate = 1\n'
        printf 'packager = howy isolated ALPM test\n'
        printf 'size = 4096\n'
        printf 'arch = x86_64\n'
        if [[ -n "${conflict}" ]]; then
            printf 'conflict = %s\n' "${conflict}"
        fi
    } > "${destination}"
}

archive_package() {
    local tree="$1"
    local archive="$2"
    local -a entries=(.PKGINFO)

    [[ ! -f "${tree}/.INSTALL" ]] || entries+=(.INSTALL)
    [[ ! -d "${tree}/etc" ]] || entries+=(etc)
    [[ ! -d "${tree}/usr" ]] || entries+=(usr)
    [[ ! -d "${tree}/var" ]] || entries+=(var)
    "${BSDTAR}" --uid 0 --gid 0 -cf "${archive}" -C "${tree}" "${entries[@]}"
}

build_provider() {
    local name="$1"
    local version="$2"
    local conflict="${3:-}"
    local tree="${WORK}/tree-${name}-${version}"
    local archive="${PACKAGES}/${name}-${version}-x86_64.pkg.tar"

    /usr/bin/mkdir -p "${tree}/usr/share/howy-v2-alpm"
    write_pkginfo "${tree}/.PKGINFO" "${name}" "${version}" "${conflict}"
    printf '%s %s\n' "${name}" "${version}" > "${tree}/usr/share/howy-v2-alpm/provider"
    case "${name}" in
        howy-cpu|howy-rocm|howy-cuda)
            /usr/bin/mkdir -p "${tree}/usr/lib/security"
            printf 'stable pam module: %s\n' "${name}" > "${tree}/usr/lib/security/pam_howy.so"
            /usr/bin/ln -s pam_howy.so "${tree}/usr/lib/security/pam_howdy.so"
            if [[ "${name}" == howy-rocm ]]; then
                /usr/bin/mkdir -p "${tree}/etc/howy" "${tree}/usr/lib/howy"
                printf 'backup = etc/howy/config.toml\n' >> "${tree}/.PKGINFO"
                /usr/bin/install -m 0644 "${REPO_ROOT}/packaging/config-release-n-legacy.toml" \
                    "${tree}/etc/howy/config.toml"
                /usr/bin/install -m 0644 "${REPO_ROOT}/howy.install" "${tree}/.INSTALL"
                {
                    printf '#!/bin/bash\n'
                    printf 'printf "%%s\\n" "$*" >> /bridge.calls\n'
                    printf 'if [[ "$1" == bootstrap-release-n ]]; then\n'
                    printf '    umask 077\n'
                    printf '    : > /var/lib/howy-package-bootstrap.complete\n'
                    printf 'fi\n'
                    printf 'exit 0\n'
                } > "${tree}/usr/lib/howy/howy-config-bridge"
                /usr/bin/chmod 0755 "${tree}/usr/lib/howy/howy-config-bridge"
            fi
            ;;
        howy-rocm-mode0)
            /usr/bin/mkdir -p \
                "${tree}/etc/howy" \
                "${tree}/usr/lib/security" \
                "${tree}/var/lib"
            printf 'backup = etc/howy/config.toml\n' >> "${tree}/.PKGINFO"
            /usr/bin/install -m 0600 "${REPO_ROOT}/packaging/deploy/config.toml" \
                "${tree}/etc/howy/config.toml"
            /usr/bin/install -m 0600 \
                "${REPO_ROOT}/packaging/deploy/package-capability.marker" \
                "${tree}/var/lib/howy-package-bootstrap.complete"
            printf 'candidate pam module\n' > "${tree}/usr/lib/security/pam_howy.so"
            /usr/bin/ln -s pam_howy.so "${tree}/usr/lib/security/pam_howdy.so"
            ;;
    esac
    archive_package "${tree}" "${archive}"
    printf '%s\n' "${archive}"
}

build_stable_update_fixture() {
    local label="$1"
    local payload="$2"
    local package_dir="${PACKAGES}/${label}"
    local tree="${WORK}/tree-stable-${label}"
    local archive="${package_dir}/howy-cpu-2.0.0-1-x86_64.pkg.tar"

    /usr/bin/mkdir -p \
        "${package_dir}" \
        "${tree}/usr/lib/howy" \
        "${tree}/usr/share/howy-v2-alpm" \
        "${tree}/usr/share/libalpm/hooks"
    write_pkginfo "${tree}/.PKGINFO" howy-cpu 2.0.0-1
    /usr/bin/install -m 0755 "${REPO_ROOT}/scripts/howy-v2-update-admission" \
        "${tree}/usr/lib/howy/howy-v2-update-admission"
    /usr/bin/install -m 0644 "${REPO_ROOT}/packaging/00-howy-update-admission.hook" \
        "${tree}/usr/share/libalpm/hooks/00-howy-update-admission.hook"
    /usr/bin/install -m 0644 "${REPO_ROOT}/packaging/05-howy-config-stash.hook" \
        "${tree}/usr/share/libalpm/hooks/05-howy-config-stash.hook"
    {
        printf '#!/bin/bash\n'
        printf 'printf "%%s\\n" "$*" >> /config-stash.calls\n'
        printf 'exit 0\n'
    } > "${tree}/usr/lib/howy/howy-config-bridge"
    /usr/bin/chmod 0755 "${tree}/usr/lib/howy/howy-config-bridge"
    printf '%s\n' "${payload}" > "${tree}/usr/share/howy-v2-alpm/stable-update-payload"
    archive_package "${tree}" "${archive}"
    printf '%s\n' "${archive}"
}

build_removal_fixture() {
    local tree="${WORK}/tree-removal"
    local archive="${PACKAGES}/howy-cpu-2.0.0-2-x86_64.pkg.tar"

    /usr/bin/mkdir -p \
        "${tree}/usr/lib/howy" \
        "${tree}/usr/share/howy-v2-alpm" \
        "${tree}/usr/share/libalpm/hooks"
    write_pkginfo "${tree}/.PKGINFO" howy-cpu 2.0.0-2
    /usr/bin/install -m 0755 "${REPO_ROOT}/scripts/howy-v2-remove-prepare" \
        "${tree}/usr/lib/howy/howy-v2-remove-prepare"
    /usr/bin/install -m 0644 "${REPO_ROOT}/packaging/10-howy-remove-prepare.hook" \
        "${tree}/usr/share/libalpm/hooks/10-howy-remove-prepare.hook"
    printf 'removal payload must survive an aborted transaction\n' \
        > "${tree}/usr/share/howy-v2-alpm/removal-payload"
    archive_package "${tree}" "${archive}"
    printf '%s\n' "${archive}"
}

new_root() {
    local label="$1"
    local case_dir="${WORK}/case-${label}"
    local root="${case_dir}/root"

    /usr/bin/mkdir -p \
        "${root}/run/lock" \
        "${root}/tmp" \
        "${root}/var/lib/pacman/local" \
        "${root}/var/cache/pacman/pkg" \
        "${root}/var/log" \
        "${case_dir}/hooks"
    /usr/bin/chmod 1777 "${root}/tmp"
    {
        printf '[options]\n'
        printf 'Architecture = auto\n'
        printf 'SigLevel = Never\n'
        printf 'LocalFileSigLevel = Never\n'
        printf 'DisableSandbox\n'
    } > "${case_dir}/pacman.conf"
    printf '%s\n' "${case_dir}"
}

pacman_install() {
    local case_dir="$1"
    local archive="$2"
    local root="${case_dir}/root"

    "${UNSHARE}" --user --map-root-user --mount -- \
        "${PACMAN}" \
        --config "${case_dir}/pacman.conf" \
        --root "${root}" \
        --dbpath "${root}/var/lib/pacman" \
        --cachedir "${root}/var/cache/pacman/pkg" \
        --hookdir "${case_dir}/hooks" \
        --logfile "${root}/var/log/pacman.log" \
        -U --noconfirm -- "${archive}"
}

pacman_replace() {
    local case_dir="$1"
    local archive="$2"
    local root="${case_dir}/root"

    "${UNSHARE}" --user --map-root-user --mount -- \
        "${PACMAN}" --ask=4 -U --noconfirm \
        --config "${case_dir}/pacman.conf" \
        --root "${root}" \
        --dbpath "${root}/var/lib/pacman" \
        --cachedir "${root}/var/cache/pacman/pkg" \
        --hookdir "${case_dir}/hooks" \
        --logfile "${root}/var/log/pacman.log" \
        -- "${archive}"
}

pacman_query() {
    local case_dir="$1"
    local package="$2"
    local root="${case_dir}/root"

    "${UNSHARE}" --user --map-root-user --mount -- \
        "${PACMAN}" \
        --config "${case_dir}/pacman.conf" \
        --root "${root}" \
        --dbpath "${root}/var/lib/pacman" \
        --cachedir "${root}/var/cache/pacman/pkg" \
        --hookdir "${case_dir}/hooks" \
        --logfile "${root}/var/log/pacman.log" \
        -Q -- "${package}"
}

pacman_remove() {
    local case_dir="$1"
    local package="$2"
    local root="${case_dir}/root"

    "${UNSHARE}" --user --map-root-user --mount -- \
        "${PACMAN}" \
        --config "${case_dir}/pacman.conf" \
        --root "${root}" \
        --dbpath "${root}/var/lib/pacman" \
        --cachedir "${root}/var/cache/pacman/pkg" \
        --hookdir "${case_dir}/hooks" \
        --logfile "${root}/var/log/pacman.log" \
        -R --noconfirm -- "${package}"
}

assert_conflict_without_replaces() {
    local archive="$1"
    local expected_conflict="$2"
    local pkginfo

    pkginfo=$("${BSDTAR}" -xOf "${archive}" .PKGINFO) \
        || fail "could not read fixture metadata from ${archive}"
    [[ "${pkginfo}" == *"conflict = ${expected_conflict}"* ]] \
        || fail "${archive} lacks conflict with ${expected_conflict}"
    [[ "${pkginfo}" != *'replaces = '* ]] \
        || fail "${archive} unexpectedly declares automatic replacement"
}

release_archive=$(build_provider howy-cpu-git 0.1.0.r26.g2dfe39e-1)
stable_cpu_archive=$(build_provider howy-cpu 2.0.0-1 howy-cpu-git)
candidate_archive=$(build_provider howy-rocm-mode0 0.1.0.r27.g0b76fa2-6)
stable_rocm_archive=$(build_provider howy-rocm 2.0.0-1 howy-rocm-mode0)
removal_archive=$(build_removal_fixture)
stable_old_archive=$(build_stable_update_fixture old 'old stable bytes')
stable_new_archive=$(build_stable_update_fixture new 'new stable bytes')

assert_conflict_without_replaces "${stable_cpu_archive}" howy-cpu-git
assert_conflict_without_replaces "${stable_rocm_archive}" howy-rocm-mode0

archive_payload="${WORK}/stable-rocm-archive-payload"
/usr/bin/mkdir "${archive_payload}"
"${BSDTAR}" -xf "${stable_rocm_archive}" -C "${archive_payload}"
[[ -L "${archive_payload}/usr/lib/security/pam_howdy.so" ]] \
    || fail 'stable ROCm archive PAM compatibility alias is not a symlink'
[[ "$(/usr/bin/readlink "${archive_payload}/usr/lib/security/pam_howdy.so")" == pam_howy.so ]] \
    || fail 'stable ROCm archive PAM compatibility alias target is not relative pam_howy.so'

case_dir=$(new_root release-replacement)
pacman_install "${case_dir}" "${release_archive}" >/dev/null
pacman_replace "${case_dir}" "${stable_cpu_archive}" >/dev/null
pacman_query "${case_dir}" howy-cpu >/dev/null \
    || fail 'stable CPU target was not installed after release-N replacement'
if pacman_query "${case_dir}" howy-cpu-git >/dev/null 2>&1; then
    fail 'matching release-N provider remained installed after --ask=4 replacement'
fi

case_dir=$(new_root candidate-replacement)
root="${case_dir}/root"
copy_runtime /bin/bash "${root}"
copy_runtime /usr/bin/bash "${root}"
copy_runtime /usr/bin/sha256sum "${root}"
copy_runtime /usr/bin/stat "${root}"
/usr/bin/ln -s bash "${root}/bin/sh"
/usr/bin/mkdir "${root}/dev"
: > "${root}/dev/null"
/usr/bin/chmod 0666 "${root}/dev/null"
pacman_install "${case_dir}" "${candidate_archive}" >/dev/null
/usr/bin/mkdir "${WORK}/candidate-config-baseline"
"${BSDTAR}" -xf "${candidate_archive}" -C "${WORK}/candidate-config-baseline" \
    etc/howy/config.toml
/usr/bin/cmp -s -- "${WORK}/candidate-config-baseline/etc/howy/config.toml" \
    "${root}/etc/howy/config.toml" \
    || fail 'candidate fixture config was not byte-identical to its package baseline'
[[ "$(/usr/bin/stat -c '%a' -- "${root}/etc/howy/config.toml")" == 600 ]] \
    || fail 'candidate fixture config mode was not 0600'
/usr/bin/cmp -s -- "${REPO_ROOT}/packaging/deploy/package-capability.marker" \
    "${root}/var/lib/howy-package-bootstrap.complete" \
    || fail 'candidate fixture marker did not match the exact package capability marker'
[[ "$(/usr/bin/stat -c '%a' -- \
    "${root}/var/lib/howy-package-bootstrap.complete")" == 600 ]] \
    || fail 'candidate fixture marker mode was not 0600'
[[ -L "${case_dir}/root/usr/lib/security/pam_howdy.so" \
    && "$(/usr/bin/readlink "${case_dir}/root/usr/lib/security/pam_howdy.so")" == pam_howy.so ]] \
    || fail 'candidate fixture did not begin with the relative PAM compatibility alias'
stable_rocm_sha=$(/usr/bin/sha256sum -- "${stable_rocm_archive}")
stable_rocm_sha=${stable_rocm_sha%% *}
/usr/bin/mkdir -p "$(/usr/bin/dirname "${root}${stable_rocm_archive}")"
/usr/bin/cp -- "${stable_rocm_archive}" "${root}${stable_rocm_archive}"
printf '%s\n' \
    'format=howy-v2-update-v1' \
    "archive=${stable_rocm_archive}" \
    "archive_sha256=${stable_rocm_sha}" \
    'source_package=howy-rocm-mode0' \
    'source_version=0.1.0.r27.g0b76fa2-6' \
    'target_package=howy-rocm' \
    'target_version=2.0.0-1' > "${root}/run/howy-v2-update-v1.prepared"
/usr/bin/chmod 0600 "${root}/run/howy-v2-update-v1.prepared"
candidate_replace_output=$( \
    HOWY_V2_UPDATE_FORMAT=howy-v2-update-v1 \
    HOWY_V2_UPDATE_ARCHIVE="${stable_rocm_archive}" \
    HOWY_V2_UPDATE_ARCHIVE_SHA256="${stable_rocm_sha}" \
    HOWY_V2_UPDATE_SOURCE_PACKAGE=howy-rocm-mode0 \
    HOWY_V2_UPDATE_SOURCE_VERSION=0.1.0.r27.g0b76fa2-6 \
    HOWY_V2_UPDATE_TARGET_PACKAGE=howy-rocm \
    HOWY_V2_UPDATE_TARGET_VERSION=2.0.0-1 \
        pacman_replace "${case_dir}" "${stable_rocm_archive}" 2>&1
) \
    || fail 'prepared candidate replacement failed'
[[ "${candidate_replace_output}" \
    == *'configuration completion is deferred to howy-v2-update'* ]] \
    || fail "prepared candidate replacement did not report updater deferral: ${candidate_replace_output}"
[[ ! -e "${root}/bridge.calls" ]] \
    || fail 'prepared candidate replacement invoked bootstrap before deferral'
[[ ! -e "${root}/var/lib/howy-package-bootstrap.complete" ]] \
    || fail 'prepared candidate replacement retained or created a bootstrap marker'
/usr/bin/cmp -s -- "${REPO_ROOT}/packaging/config-release-n-legacy.toml" \
    "${root}/etc/howy/config.toml" \
    || fail 'candidate replacement did not install the stable legacy config payload'
pacman_query "${case_dir}" howy-rocm >/dev/null \
    || fail 'stable ROCm target was not installed after candidate replacement'
if pacman_query "${case_dir}" howy-rocm-mode0 >/dev/null 2>&1; then
    fail 'matching candidate provider remained installed after --ask=4 replacement'
fi
[[ -L "${case_dir}/root/usr/lib/security/pam_howdy.so" ]] \
    || fail 'candidate replacement did not leave pam_howdy.so as a symlink'
[[ "$(/usr/bin/readlink "${case_dir}/root/usr/lib/security/pam_howdy.so")" == pam_howy.so ]] \
    || fail 'candidate replacement PAM alias is not relative to pam_howy.so'
[[ -f "${case_dir}/root/usr/lib/security/pam_howy.so" \
    && ! -L "${case_dir}/root/usr/lib/security/pam_howy.so" ]] \
    || fail 'candidate replacement lost the real pam_howy.so module'

case_dir=$(new_root malformed-candidate-sentinel)
root="${case_dir}/root"
copy_runtime /bin/bash "${root}"
copy_runtime /usr/bin/bash "${root}"
copy_runtime /usr/bin/sha256sum "${root}"
copy_runtime /usr/bin/stat "${root}"
/usr/bin/ln -s bash "${root}/bin/sh"
/usr/bin/mkdir "${root}/dev"
: > "${root}/dev/null"
/usr/bin/chmod 0666 "${root}/dev/null"
pacman_install "${case_dir}" "${candidate_archive}" >/dev/null
printf '%s\n' \
    'format=howy-v2-update-v1' \
    "archive=${stable_rocm_archive}" \
    "archive_sha256=${stable_rocm_sha}" \
    'source_package=howy-rocm-mode0' \
    'source_version=0.1.0.r27.g0b76fa2-6' \
    'target_package=howy-rocm' \
    'target_version=2.0.0-1' \
    'extra=malformed' > "${root}/run/howy-v2-update-v1.prepared"
/usr/bin/chmod 0600 "${root}/run/howy-v2-update-v1.prepared"
malformed_replace_output=$(pacman_replace "${case_dir}" "${stable_rocm_archive}" 2>&1) \
    || fail 'candidate replacement with malformed sentinel failed fresh bootstrap'
[[ "${malformed_replace_output}" \
    != *'configuration completion is deferred to howy-v2-update'* ]] \
    || fail 'malformed candidate sentinel incorrectly deferred bootstrap'
[[ "$(<"${root}/bridge.calls")" == bootstrap-release-n ]] \
    || fail 'malformed candidate sentinel did not invoke exact fresh bootstrap'
[[ -f "${root}/var/lib/howy-package-bootstrap.complete" ]] \
    || fail 'bootstrap-capable bridge fixture did not create its marker'

case_dir=$(new_root stable-update-admission)
root="${case_dir}/root"
for binary in /bin/bash /usr/bin/id /usr/bin/stat /usr/bin/sha256sum; do
    copy_runtime "${binary}" "${root}"
done
pacman_install "${case_dir}" "${stable_old_archive}" >/dev/null
/usr/bin/cp -- "${root}/usr/share/libalpm/hooks/00-howy-update-admission.hook" \
    "${case_dir}/hooks/00-howy-update-admission.hook"
/usr/bin/cp -- "${root}/usr/share/libalpm/hooks/05-howy-config-stash.hook" \
    "${case_dir}/hooks/05-howy-config-stash.hook"
/usr/bin/cp -- "${root}/var/lib/pacman/local/howy-cpu-2.0.0-1/desc" \
    "${case_dir}/stable-old-package-db.desc"
[[ "$(<"${root}/usr/share/howy-v2-alpm/stable-update-payload")" == 'old stable bytes' ]] \
    || fail 'stable update fixture did not install its old payload bytes'

set +e
raw_update_output=$(pacman_install "${case_dir}" "${stable_new_archive}" 2>&1)
raw_update_status=$?
set -e
[[ "${raw_update_status}" -ne 0 ]] \
    || fail 'raw same-name stable update succeeded without a prepared sentinel'
[[ "${raw_update_output}" == *'prepared sentinel is not a non-symlink regular file'* ]] \
    || fail "raw same-name refusal was not reported: ${raw_update_output}"
[[ "$(<"${root}/usr/share/howy-v2-alpm/stable-update-payload")" == 'old stable bytes' ]] \
    || fail 'aborted raw same-name update changed installed payload bytes'
[[ ! -e "${root}/config-stash.calls" ]] \
    || fail 'aborted 00 update admission continued to the 05 config stash hook'
/usr/bin/cmp -s -- \
    "${case_dir}/stable-old-package-db.desc" \
    "${root}/var/lib/pacman/local/howy-cpu-2.0.0-1/desc" \
    || fail 'aborted raw same-name update changed the installed package database'

stable_new_sha=$(/usr/bin/sha256sum -- "${stable_new_archive}")
stable_new_sha=${stable_new_sha%% *}
{
    printf '%s\n' \
        'format=howy-v2-update-v1' \
        "archive=${stable_new_archive}" \
        "archive_sha256=${stable_new_sha}" \
        'source_package=howy-cpu' \
        'source_version=2.0.0-1' \
        'target_package=howy-cpu' \
        'target_version=2.0.0-1'
} > "${root}/run/howy-v2-update-v1.prepared"
/usr/bin/chmod 0600 "${root}/run/howy-v2-update-v1.prepared"
pacman_install "${case_dir}" "${stable_new_archive}" >/dev/null \
    || fail 'same-name stable update with the exact prepared sentinel failed'
pacman_query "${case_dir}" howy-cpu >/dev/null \
    || fail 'admitted same-name stable update lost its package database entry'
[[ "$(<"${root}/usr/share/howy-v2-alpm/stable-update-payload")" == 'new stable bytes' ]] \
    || fail 'admitted same-name stable update did not install new payload bytes'
[[ "$(<"${root}/config-stash.calls")" == stash-release-n ]] \
    || fail 'admitted same-name stable update did not continue to the 05 config stash hook'

case_dir=$(new_root removal-abort)
root="${case_dir}/root"
copy_runtime /bin/bash "${root}"
copy_runtime /usr/bin/id "${root}"
/usr/bin/ln -s bash "${root}/bin/sh"
pacman_install "${case_dir}" "${removal_archive}" >/dev/null
/usr/bin/cp -- "${root}/usr/share/libalpm/hooks/10-howy-remove-prepare.hook" \
    "${case_dir}/hooks/10-howy-remove-prepare.hook"
{
    printf '#!/bin/bash\n'
    printf 'printf "%%s\\n" "$*" >> /remove-helper.calls\n'
    printf 'if [[ "$1:$2" == "stop:howy.socket" ]]; then exit 1; fi\n'
    printf 'exit 0\n'
} > "${root}/usr/bin/systemctl"
/usr/bin/chmod 0755 "${root}/usr/bin/systemctl"

set +e
remove_output=$(pacman_remove "${case_dir}" howy-cpu 2>&1)
remove_status=$?
set -e
[[ "${remove_status}" -ne 0 ]] \
    || fail 'failed removal helper did not abort the real ALPM transaction'
[[ "${remove_output}" == *'howy-v2-remove-prepare: refusal: could not stop howy.socket'* ]] \
    || fail "removal helper failure was not reported: ${remove_output}"
pacman_query "${case_dir}" howy-cpu >/dev/null \
    || fail 'aborted removal changed the installed package database'
[[ -f "${root}/usr/share/howy-v2-alpm/removal-payload" ]] \
    || fail 'aborted removal deleted package payload bytes'
[[ "$(<"${root}/remove-helper.calls")" == 'stop howy.socket' ]] \
    || fail 'removal helper did not fail at the isolated socket stop as arranged'

printf '%s\n' 'v2 isolated ALPM: conflict-only predecessor replacement, PAM alias, stable update admission, and removal abort passed'
