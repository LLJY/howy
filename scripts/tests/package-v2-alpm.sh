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
GIT=/usr/bin/git
OLD_STABLE_COMMIT=4dcdf14f742d510aa1d6c43026ff62e43e8596c6

fail() {
    printf 'v2 isolated ALPM FAIL: %s\n' "$*" >&2
    exit 1
}

skip() {
    printf 'v2 isolated ALPM SKIP: %s\n' "$*" >&2
    exit 0
}

for tool in \
    "${PACMAN}" \
    "${UNSHARE}" \
    "${BSDTAR}" \
    "${GIT}" \
    /usr/bin/ldd \
    /usr/bin/true; do
    [[ -x "${tool}" ]] || skip "required isolation capability is unavailable: ${tool}"
done

if ! unshare_reason=$("${UNSHARE}" --user --map-root-user --mount -- /usr/bin/true 2>&1); then
    skip "the kernel/container blocked mapped-root user+mount namespaces: ${unshare_reason}"
fi

if [[ "$("${GIT}" -C "${REPO_ROOT}" rev-parse --verify \
        "${OLD_STABLE_COMMIT}^{commit}")" != "${OLD_STABLE_COMMIT}" ]]; then
    fail "immutable old stable commit is unavailable: ${OLD_STABLE_COMMIT}"
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
    local depend="${5:-}"
    local provides="${6:-}"

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
        if [[ -n "${depend}" ]]; then
            printf 'depend = %s\n' "${depend}"
        fi
        if [[ -n "${provides}" ]]; then
            printf 'provides = %s\n' "${provides}"
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
    local depend="${4:-}"
    local provides="${5:-}"
    local tree="${WORK}/tree-${name}-${version}"
    local archive="${PACKAGES}/${name}-${version}-x86_64.pkg.tar"

    /usr/bin/mkdir -p "${tree}/usr/share/howy-v2-alpm"
    write_pkginfo \
        "${tree}/.PKGINFO" \
        "${name}" \
        "${version}" \
        "${conflict}" \
        "${depend}" \
        "${provides}"
    printf '%s %s\n' "${name}" "${version}" \
        > "${tree}/usr/share/howy-v2-alpm/${name}"
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
    local version="$2"
    local payload="$3"
    local package_dir="${PACKAGES}/${label}"
    local tree="${WORK}/tree-stable-${label}"
    local archive="${package_dir}/howy-cpu-${version}-x86_64.pkg.tar"

    /usr/bin/mkdir -p \
        "${package_dir}" \
        "${tree}/usr/lib/howy" \
        "${tree}/usr/share/howy-v2-alpm" \
        "${tree}/usr/share/libalpm/hooks"
    write_pkginfo "${tree}/.PKGINFO" howy-cpu "${version}"
    if [[ "${version}" == 2.0.0-1 ]]; then
        "${GIT}" -C "${REPO_ROOT}" show \
            "${OLD_STABLE_COMMIT}:scripts/howy-v2-update-admission" \
            > "${tree}/usr/lib/howy/howy-v2-update-admission"
        "${GIT}" -C "${REPO_ROOT}" show \
            "${OLD_STABLE_COMMIT}:packaging/00-howy-update-admission.hook" \
            > "${tree}/usr/share/libalpm/hooks/00-howy-update-admission.hook"
        /usr/bin/chmod 0755 "${tree}/usr/lib/howy/howy-v2-update-admission"
        /usr/bin/chmod 0644 \
            "${tree}/usr/share/libalpm/hooks/00-howy-update-admission.hook"
    else
        /usr/bin/install -m 0755 "${REPO_ROOT}/scripts/howy-v2-update-admission" \
            "${tree}/usr/lib/howy/howy-v2-update-admission"
        /usr/bin/install -m 0644 "${REPO_ROOT}/packaging/00-howy-update-admission.hook" \
            "${tree}/usr/share/libalpm/hooks/00-howy-update-admission.hook"
    fi
    /usr/bin/install -m 0644 "${REPO_ROOT}/packaging/05-howy-config-stash.hook" \
        "${tree}/usr/share/libalpm/hooks/05-howy-config-stash.hook"
    {
        printf '#!/bin/bash\n'
        printf 'printf "%%s\\n" "$*" >> /config-stash.calls\n'
        printf 'exit 0\n'
    } > "${tree}/usr/lib/howy/howy-config-bridge"
    /usr/bin/chmod 0755 "${tree}/usr/lib/howy/howy-config-bridge"
    {
        printf '[Trigger]\n'
        printf 'Operation = Upgrade\n'
        printf 'Type = Package\n'
        printf 'Target = howy-cpu\n\n'
        printf '[Action]\n'
        printf 'Description = Running benign Howy ALPM fixture hook\n'
        printf 'When = PreTransaction\n'
        printf 'Exec = /usr/lib/howy/howy-benign-update-hook\n'
    } > "${tree}/usr/share/libalpm/hooks/50-howy-benign-update.hook"
    {
        printf '#!/bin/bash\n'
        printf 'printf "benign-hook-ran\\n" >> /benign-hook.calls\n'
    } > "${tree}/usr/lib/howy/howy-benign-update-hook"
    /usr/bin/chmod 0755 "${tree}/usr/lib/howy/howy-benign-update-hook"
    printf '%s\n' "${payload}" > "${tree}/usr/share/howy-v2-alpm/stable-update-payload"
    archive_package "${tree}" "${archive}"
    printf '%s\n' "${archive}"
}

build_removal_fixture() {
    local tree="${WORK}/tree-removal"
    local package_dir="${PACKAGES}/removal"
    local archive="${package_dir}/howy-cpu-2.0.1-1-x86_64.pkg.tar"

    /usr/bin/mkdir -p \
        "${package_dir}" \
        "${tree}/usr/lib/howy" \
        "${tree}/usr/share/howy-v2-alpm" \
        "${tree}/usr/share/libalpm/hooks"
    write_pkginfo "${tree}/.PKGINFO" howy-cpu 2.0.1-1
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

pacman_install_with_hook_override() {
    local case_dir="$1"
    local archive="$2"
    local override_dir="$3"
    local root="${case_dir}/root"

    "${UNSHARE}" --user --map-root-user --mount -- \
        "${PACMAN}" \
        --config "${case_dir}/pacman.conf" \
        --root "${root}" \
        --dbpath "${root}/var/lib/pacman" \
        --cachedir "${root}/var/cache/pacman/pkg" \
        --hookdir "${case_dir}/hooks" \
        --hookdir "${override_dir}" \
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
stable_cpu_archive=$(build_provider howy-cpu 2.0.1-1 howy-cpu-git)
candidate_archive=$(build_provider howy-rocm-mode0 0.1.0.r27.g0b76fa2-6)
stable_rocm_archive=$(build_provider howy-rocm 2.0.1-1 howy-rocm-mode0)
removal_archive=$(build_removal_fixture)
stable_old_archive=$(build_stable_update_fixture old 2.0.0-1 'old stable bytes')
stable_new_archive=$(build_stable_update_fixture new 2.0.1-1 'new stable bytes')
runtime_old_archive=$(build_provider \
    onnxruntime-opt-rocm 1.24.4-9 '' '' 'onnxruntime=1.24.4')
runtime_new_archive=$(build_provider \
    onnxruntime-opt-rocm 1.28.0-1 '' '' 'onnxruntime=1.28.0')
runtime_dependent_archive=$(build_provider \
    howy-runtime-probe 2.0.1-1 '' 'onnxruntime=1.28.0')

assert_conflict_without_replaces "${stable_cpu_archive}" howy-cpu-git
assert_conflict_without_replaces "${stable_rocm_archive}" howy-rocm-mode0

case_dir=$(new_root runtime-exact-provider)
pacman_install "${case_dir}" "${runtime_new_archive}" >/dev/null
pacman_install "${case_dir}" "${runtime_dependent_archive}" >/dev/null \
    || fail 'provider capability onnxruntime=1.28.0 did not satisfy the exact dependency'

case_dir=$(new_root runtime-old-provider)
pacman_install "${case_dir}" "${runtime_old_archive}" >/dev/null
if pacman_install "${case_dir}" "${runtime_dependent_archive}" >/dev/null 2>&1; then
    fail 'provider capability onnxruntime=1.24.4 satisfied the 1.28.0 dependency'
fi

case_dir=$(new_root runtime-provider-downgrade)
pacman_install "${case_dir}" "${runtime_new_archive}" >/dev/null
pacman_install "${case_dir}" "${runtime_dependent_archive}" >/dev/null
if pacman_install "${case_dir}" "${runtime_old_archive}" >/dev/null 2>&1; then
    fail 'ALPM allowed the installed provider to break the exact ONNX Runtime dependency'
fi
[[ "$(pacman_query "${case_dir}" onnxruntime-opt-rocm)" \
    == 'onnxruntime-opt-rocm 1.28.0-1' ]] \
    || fail 'refused provider downgrade changed the installed provider'

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
    'target_version=2.0.1-1' > "${root}/run/howy-v2-update-v1.prepared"
/usr/bin/chmod 0600 "${root}/run/howy-v2-update-v1.prepared"
candidate_replace_output=$( \
    HOWY_V2_UPDATE_FORMAT=howy-v2-update-v1 \
    HOWY_V2_UPDATE_ARCHIVE="${stable_rocm_archive}" \
    HOWY_V2_UPDATE_ARCHIVE_SHA256="${stable_rocm_sha}" \
    HOWY_V2_UPDATE_SOURCE_PACKAGE=howy-rocm-mode0 \
    HOWY_V2_UPDATE_SOURCE_VERSION=0.1.0.r27.g0b76fa2-6 \
    HOWY_V2_UPDATE_TARGET_PACKAGE=howy-rocm \
    HOWY_V2_UPDATE_TARGET_VERSION=2.0.1-1 \
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
    'target_version=2.0.1-1' \
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
old_helper_expected_sha=$( \
    "${GIT}" -C "${REPO_ROOT}" show \
        "${OLD_STABLE_COMMIT}:scripts/howy-v2-update-admission" \
        | /usr/bin/sha256sum
)
old_helper_expected_sha=${old_helper_expected_sha%% *}
current_helper_sha=$(/usr/bin/sha256sum -- \
    "${REPO_ROOT}/scripts/howy-v2-update-admission")
current_helper_sha=${current_helper_sha%% *}
[[ "${old_helper_expected_sha}" != "${current_helper_sha}" ]] \
    || fail 'old stable fixture helper unexpectedly matches the current helper bytes'
pacman_install "${case_dir}" "${stable_old_archive}" >/dev/null
/usr/bin/cp -- "${root}/usr/share/libalpm/hooks/00-howy-update-admission.hook" \
    "${case_dir}/hooks/00-howy-update-admission.hook"
/usr/bin/cp -- "${root}/usr/share/libalpm/hooks/05-howy-config-stash.hook" \
    "${case_dir}/hooks/05-howy-config-stash.hook"
/usr/bin/cp -- "${root}/usr/share/libalpm/hooks/50-howy-benign-update.hook" \
    "${case_dir}/hooks/50-howy-benign-update.hook"
old_helper_installed_sha=$(/usr/bin/sha256sum -- \
    "${root}/usr/lib/howy/howy-v2-update-admission")
old_helper_installed_sha=${old_helper_installed_sha%% *}
[[ "${old_helper_installed_sha}" == "${old_helper_expected_sha}" ]] \
    || fail 'installed old stable admission helper differs from the immutable v2.0.0 bytes'
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
        'target_version=2.0.1-1'
} > "${root}/run/howy-v2-update-v1.prepared"
/usr/bin/chmod 0600 "${root}/run/howy-v2-update-v1.prepared"

set +e
prepared_direct_output=$(pacman_install "${case_dir}" "${stable_new_archive}" 2>&1)
prepared_direct_status=$?
set -e
[[ "${prepared_direct_status}" -ne 0 ]] \
    || fail 'direct prepared v2.0.0 to v2.0.1 update bypassed the old admission helper'
[[ "${prepared_direct_output}" \
    == *'prepared source and target versions must both be 2.0.0-1'* ]] \
    || fail "old helper version refusal was not reported: ${prepared_direct_output}"
[[ "$(<"${root}/usr/share/howy-v2-alpm/stable-update-payload")" == 'old stable bytes' ]] \
    || fail 'old helper refusal changed installed payload bytes'
[[ ! -e "${root}/config-stash.calls" && ! -e "${root}/benign-hook.calls" ]] \
    || fail 'old helper refusal continued to later fixture hooks'

override_dir="${root}/run/howy-v2-update-hook-override"
override_path="${override_dir}/00-howy-update-admission.hook"
/usr/bin/mkdir -m 0700 -- "${override_dir}"
/usr/bin/ln -s -- /dev/null "${override_path}"
override_dir_metadata=$( \
    "${UNSHARE}" --user --map-root-user --mount -- \
        /usr/bin/stat -c '%u:%g:%a' -- "${override_dir}"
)
override_link_metadata=$( \
    "${UNSHARE}" --user --map-root-user --mount -- \
        /usr/bin/stat -c '%u:%g' -- "${override_path}"
)
[[ "${override_dir_metadata}" == '0:0:700' ]] \
    || fail "isolated override directory metadata is not root:root 0700: ${override_dir_metadata}"
[[ "${override_link_metadata}" == '0:0' \
    && "$(/usr/bin/readlink -- "${override_path}")" == /dev/null ]] \
    || fail 'isolated override is not the exact root-owned admission-hook symlink to /dev/null'

pacman_install_with_hook_override \
    "${case_dir}" "${stable_new_archive}" "${override_dir}" >/dev/null \
    || fail 'same-name stable update with the higher-priority symlink override failed'
[[ "$(pacman_query "${case_dir}" howy-cpu)" == 'howy-cpu 2.0.1-1' ]] \
    || fail 'admitted v2.0.0 to v2.0.1 stable update has the wrong package database entry'
[[ "$(<"${root}/usr/share/howy-v2-alpm/stable-update-payload")" == 'new stable bytes' ]] \
    || fail 'admitted same-name stable update did not install new payload bytes'
[[ "$(<"${root}/config-stash.calls")" == stash-release-n ]] \
    || fail 'admitted same-name stable update did not continue to the 05 config stash hook'
[[ "$(<"${root}/benign-hook.calls")" == benign-hook-ran ]] \
    || fail 'higher-priority admission override disabled or skipped the benign fixture hook'
/usr/bin/rm -- "${override_path}"
/usr/bin/rmdir -- "${override_dir}"
[[ ! -e "${override_dir}" && ! -L "${override_dir}" ]] \
    || fail 'isolated exact override cleanup retained state'

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

printf 'v2 isolated ALPM compatibility evidence: old_commit=%s old_helper_sha256=%s direct_prepared_status=%s override_dir=%s override_link=/dev/null benign_hook=ran target=howy-cpu-2.0.1-1\n' \
    "${OLD_STABLE_COMMIT}" \
    "${old_helper_installed_sha}" \
    "${prepared_direct_status}" \
    "${override_dir_metadata}"
printf '%s\n' 'v2 isolated ALPM: exact runtime capability, conflict-only predecessor replacement, PAM alias, stable update admission override, and removal abort passed'
