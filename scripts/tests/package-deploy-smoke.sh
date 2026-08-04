#!/bin/bash

set -euo pipefail

TEST_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(dirname "$(dirname "${TEST_DIR}")")
DEPLOY_DIR="${REPO_ROOT}/packaging/deploy"
TARGET_ROOT="${REPO_ROOT}/target/package-deploy"
PACKAGE_DIR="${TARGET_ROOT}/packages"
EXPECTED_VERSION='0.1.0.r27.g0b76fa2-7'

fail() {
    printf 'package deploy smoke: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

archive_manifest() {
    local archive="$1"
    local output="$2"
    local mode links uid gid size month day clock path remainder
    local type link_target

    : > "${output}"
    while read -r mode links uid gid size month day clock path remainder; do
        [ -n "${path:-}" ] || fail "could not parse archive listing for ${archive}"
        case "${mode:0:1}" in
            -) type=file ;;
            d) type=directory ;;
            l) type=symlink ;;
            *) fail "unsupported archive entry type '${mode:0:1}' at ${path}" ;;
        esac
        link_target=-
        if [ "${type}" = symlink ]; then
            [[ "${remainder:-}" == '-> '* ]] \
                || fail "missing symlink target for ${path}"
            link_target=${remainder#-> }
        elif [ -n "${remainder:-}" ]; then
            fail "unexpected archive listing suffix for ${path}: ${remainder}"
        fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "${type}" "${mode:1}" "${uid}" "${gid}" "${path}" "${link_target}" \
            >> "${output}"
    done < <(bsdtar -tvf "${archive}" --numeric-owner)
    LC_ALL=C sort -o "${output}" "${output}"
}

expected_manifest() {
    local output="$1"

    printf '%s\n' \
        $'file\trw-r--r--\t0\t0\t.BUILDINFO\t-' \
        $'file\trw-r--r--\t0\t0\t.MTREE\t-' \
        $'file\trw-r--r--\t0\t0\t.PKGINFO\t-' \
        $'directory\trwxr-xr-x\t0\t0\tetc/\t-' \
        $'directory\trwx------\t0\t0\tetc/howy/\t-' \
        $'file\trw-------\t0\t0\tetc/howy/config.toml\t-' \
        $'directory\trwxr-xr-x\t0\t0\tusr/\t-' \
        $'directory\trwxr-xr-x\t0\t0\tusr/bin/\t-' \
        $'file\trwxr-xr-x\t0\t0\tusr/bin/howy\t-' \
        $'file\trwxr-xr-x\t0\t0\tusr/bin/howyd\t-' \
        $'directory\trwxr-xr-x\t0\t0\tusr/lib/\t-' \
        $'directory\trwxr-xr-x\t0\t0\tusr/lib/security/\t-' \
        $'symlink\trwxrwxrwx\t0\t0\tusr/lib/security/pam_howdy.so\tpam_howy.so' \
        $'file\trw-r--r--\t0\t0\tusr/lib/security/pam_howy.so\t-' \
        $'directory\trwxr-xr-x\t0\t0\tusr/lib/systemd/\t-' \
        $'directory\trwxr-xr-x\t0\t0\tusr/lib/systemd/system/\t-' \
        $'file\trw-r--r--\t0\t0\tusr/lib/systemd/system/howy.service\t-' \
        $'file\trw-r--r--\t0\t0\tusr/lib/systemd/system/howy.socket\t-' \
        $'directory\trwxr-xr-x\t0\t0\tusr/share/\t-' \
        $'directory\trwxr-xr-x\t0\t0\tusr/share/doc/\t-' \
        $'directory\trwxr-xr-x\t0\t0\tusr/share/doc/howy-rocm-mode0/\t-' \
        $'file\trw-r--r--\t0\t0\tusr/share/doc/howy-rocm-mode0/README.md\t-' \
        $'directory\trwxr-xr-x\t0\t0\tusr/share/licenses/\t-' \
        $'directory\trwxr-xr-x\t0\t0\tusr/share/licenses/howy-rocm-mode0/\t-' \
        $'file\trw-r--r--\t0\t0\tusr/share/licenses/howy-rocm-mode0/LICENSE\t-' \
        $'directory\trwxr-xr-x\t0\t0\tvar/\t-' \
        $'directory\trwxr-xr-x\t0\t0\tvar/lib/\t-' \
        $'file\trw-------\t0\t0\tvar/lib/howy-package-bootstrap.complete\t-' \
        | LC_ALL=C sort > "${output}"
}

pkginfo_values() {
    local pkginfo="$1"
    local key="$2"
    local line

    while IFS= read -r line; do
        if [[ "${line}" == "${key} = "* ]]; then
            printf '%s\n' "${line#*= }"
        fi
    done < "${pkginfo}"
}

assert_pkginfo_values() {
    local pkginfo="$1"
    local key="$2"
    shift 2
    local -a expected=("$@")
    local -a actual
    local index

    mapfile -t actual < <(pkginfo_values "${pkginfo}" "${key}")
    [ "${#actual[@]}" -eq "${#expected[@]}" ] \
        || fail ".PKGINFO ${key} count differs: expected ${#expected[@]}, got ${#actual[@]}"
    for index in "${!expected[@]}"; do
        [ "${actual[index]}" = "${expected[index]}" ] \
            || fail ".PKGINFO ${key} differs at index ${index}: expected '${expected[index]}', got '${actual[index]}'"
    done
}

validate_elf() {
    local extracted="$1"
    local relative="$2"
    local kind="$3"
    local file="${extracted}/${relative}"
    local dynamic interpreter ldd_output onnx_resolution

    [ -f "${file}" ] || fail "missing ELF file ${relative}"
    readelf -h "${file}" >/dev/null \
        || fail "${relative} is not a readable ELF file"

    interpreter=$(readelf -l "${file}" | grep -F 'Requesting program interpreter:' || true)
    if [ "${kind}" = executable ]; then
        [[ "${interpreter}" == *'/lib64/ld-linux-x86-64.so.2]'* ]] \
            || fail "${relative} has an unexpected ELF interpreter"
    elif [ -n "${interpreter}" ]; then
        fail "shared library ${relative} unexpectedly has an ELF interpreter"
    fi

    dynamic=$(readelf -d "${file}")
    [[ "${dynamic}" == *'(NEEDED)'* ]] \
        || fail "${relative} has no DT_NEEDED entries"
    if [[ "${dynamic}" == *'(RPATH)'* || "${dynamic}" == *'(RUNPATH)'* ]]; then
        fail "${relative} contains RPATH/RUNPATH"
    fi
    if printf '%s\n' "${dynamic}" \
        | grep -E '\(NEEDED\).*\[[^]]*/[^]]*\]' >/dev/null; then
        fail "${relative} has a path-bearing DT_NEEDED entry"
    fi
    [[ "${dynamic}" != *'target/package-deploy'* ]] \
        || fail "${relative} dynamic section contains a package build path"

    ldd_output=$(ldd "${file}" 2>&1) \
        || fail "ldd failed for ${relative}: ${ldd_output}"
    [[ "${ldd_output}" != *'not found'* ]] \
        || fail "${relative} has an unresolved runtime dependency"

    if [ "${relative}" = usr/bin/howyd ]; then
        [[ "${dynamic}" == *'Shared library: [libonnxruntime.so.1]'* ]] \
            || fail "${relative} does not need libonnxruntime.so.1"
        onnx_resolution=$(printf '%s\n' "${ldd_output}" \
            | grep -E '^[[:space:]]*libonnxruntime\.so\.1[[:space:]]+=>' || true)
        [[ "${onnx_resolution}" == *'=> /usr/lib/'* ]] \
            || fail "${relative} does not resolve libonnxruntime.so.1 under /usr/lib"
    fi
}

for command in bsdtar cmp grep ldd mktemp nm readelf readlink sort systemd-analyze; do
    require_command "${command}"
done

[ -d "${PACKAGE_DIR}" ] || fail "package output directory not found: ${PACKAGE_DIR}"
shopt -s nullglob
archives=("${PACKAGE_DIR}"/howy-rocm-mode0-*.pkg.tar*)
shopt -u nullglob
[ "${#archives[@]}" -eq 1 ] \
    || fail "expected exactly one package archive, found ${#archives[@]}"
[ -f "${archives[0]}" ] && [ ! -L "${archives[0]}" ] \
    || fail "package archive is not a regular file: ${archives[0]}"
archive=${archives[0]}

work=$(mktemp -d "${TARGET_ROOT}/smoke.XXXXXX")
cleanup() {
    rm -rf -- "${work}"
}
trap cleanup EXIT INT TERM

manifest="${work}/archive.manifest"
expected="${work}/expected.manifest"
archive_manifest "${archive}" "${manifest}"
expected_manifest "${expected}"
cmp -s "${expected}" "${manifest}" \
    || fail 'archive path/type/mode/UID/GID manifest differs from the exact allowlist'

extracted="${work}/extracted"
mkdir -p "${extracted}"
bsdtar -xf "${archive}" -C "${extracted}"

pkginfo="${extracted}/.PKGINFO"
assert_pkginfo_values "${pkginfo}" pkgname howy-rocm-mode0
assert_pkginfo_values "${pkginfo}" pkgbase howy-rocm-mode0
assert_pkginfo_values "${pkginfo}" pkgver "${EXPECTED_VERSION}"
assert_pkginfo_values "${pkginfo}" arch x86_64
assert_pkginfo_values "${pkginfo}" license GPL-2.0-only
assert_pkginfo_values "${pkginfo}" depend \
    glibc \
    gcc-libs \
    onnxruntime-opt-rocm \
    pam \
    'systemd>=261'
assert_pkginfo_values "${pkginfo}" provides \
    'howy=0.1.0.r27.g0b76fa2' \
    howdy
assert_pkginfo_values "${pkginfo}" conflict \
    howy \
    howdy \
    howdy-git \
    howy-ab-rocm \
    howy-cpu-git \
    howy-rocm-git \
    howy-cuda-git
assert_pkginfo_values "${pkginfo}" backup etc/howy/config.toml
assert_pkginfo_values "${pkginfo}" makedepend \
    cargo \
    clang \
    git \
    patch \
    protobuf \
    onnxruntime-opt-rocm
assert_pkginfo_values "${pkginfo}" optdepend
assert_pkginfo_values "${pkginfo}" replaces howdy-git
assert_pkginfo_values "${pkginfo}" install

cmp -s "${DEPLOY_DIR}/config.toml" "${extracted}/etc/howy/config.toml" \
    || fail 'packaged config differs from the local deploy config'
"${extracted}/usr/bin/howy" config --stdout > "${work}/generated-config.toml"
cmp -s "${extracted}/etc/howy/config.toml" "${work}/generated-config.toml" \
    || fail 'packaged config differs from extracted pinned howy config --stdout'
cmp -s "${REPO_ROOT}/systemd/howy.service" \
    "${extracted}/usr/lib/systemd/system/howy.service" \
    || fail 'packaged service differs from the pinned repository source unit'
cmp -s "${REPO_ROOT}/systemd/howy.socket" \
    "${extracted}/usr/lib/systemd/system/howy.socket" \
    || fail 'packaged socket differs from the pinned repository source unit'
[[ -L "${extracted}/usr/lib/security/pam_howdy.so" \
    && "$(readlink "${extracted}/usr/lib/security/pam_howdy.so")" = pam_howy.so ]] \
    || fail 'packaged PAM compatibility alias is not the exact relative symlink'
cmp -s "${DEPLOY_DIR}/README.md" \
    "${extracted}/usr/share/doc/howy-rocm-mode0/README.md" \
    || fail 'packaged README differs from the pinned repository README'
cmp -s "${REPO_ROOT}/LICENSE" \
    "${extracted}/usr/share/licenses/howy-rocm-mode0/LICENSE" \
    || fail 'packaged LICENSE differs from the pinned repository LICENSE'

marker="${extracted}/var/lib/howy-package-bootstrap.complete"
cmp -s "${DEPLOY_DIR}/package-capability.marker" "${marker}" \
    || fail 'packaged capability marker differs from the pinned package source'
expected_marker=$(printf '%s\n' \
    'schema=howy-package-capability-v1' \
    'package=howy-rocm-mode0' \
    'source_commit=0b76fa23ad3883ccfa8edd38210766f97cdbb71a' \
    'supported_modes=0,1')
[ "$(<"${marker}")" = "${expected_marker}" ] \
    || fail 'packaged capability marker content differs from the exact schema'

validate_elf "${extracted}" usr/bin/howyd executable
validate_elf "${extracted}" usr/bin/howy executable
validate_elf "${extracted}" usr/lib/security/pam_howy.so library

pam_exports=$(
    nm -D --defined-only --format=posix \
        "${extracted}/usr/lib/security/pam_howy.so" \
        | while read -r symbol type value size; do
            case "${symbol}" in
                pam_sm_*) printf '%s\n' "${symbol}" ;;
            esac
        done \
        | LC_ALL=C sort
)
expected_pam_exports=$(printf '%s\n' \
    pam_sm_authenticate \
    pam_sm_setcred \
    pam_sm_acct_mgmt \
    pam_sm_open_session \
    pam_sm_close_session \
    pam_sm_chauthtok \
    | LC_ALL=C sort)
[ "${pam_exports}" = "${expected_pam_exports}" ] \
    || fail 'PAM export set differs from the exact six project entry points'

recursive_errors=()
if systemd-analyze verify --help 2>&1 | grep -F -- '--recursive-errors=MODE' >/dev/null; then
    recursive_errors=(--recursive-errors=yes)
else
    printf 'package deploy smoke: warning: systemd-analyze lacks --recursive-errors; using direct verification only\n' >&2
fi
unit_dir="${extracted}/usr/lib/systemd/system"
SYSTEMD_UNIT_PATH="${unit_dir}:/usr/lib/systemd/system" \
    systemd-analyze "${recursive_errors[@]}" --man=no --generators=no verify \
        "${unit_dir}/howy.service" \
        "${unit_dir}/howy.socket"

"${extracted}/usr/bin/howyd" --help >/dev/null
"${extracted}/usr/bin/howy" --version >/dev/null
provision_help=$("${extracted}/usr/bin/howy" security provision --help)
[[ "${provision_help}" == *'--presence <PRESENCE>'* ]] \
    || fail 'security provision help lacks --presence <PRESENCE>'
[[ "${provision_help}" == *'[possible values: off, confirm]'* ]] \
    || fail 'security provision presence values differ from off, confirm'

printf 'package deploy structural smoke passed: %s\n' "${archive}"
