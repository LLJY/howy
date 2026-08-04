#!/bin/bash

set -euo pipefail

TEST_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(dirname "$(dirname "${TEST_DIR}")")
TARGET_ROOT="${REPO_ROOT}/target/package-ab"
EXPECTED_PATHS=$(printf '%s\n' \
    .BUILDINFO \
    .MTREE \
    .PKGINFO \
    usr/ \
    usr/bin/ \
    usr/bin/howy \
    usr/bin/howyd \
    usr/lib/ \
    usr/lib/howy-ab/ \
    usr/lib/howy-ab/bench/ \
    usr/lib/howy-ab/bench/capture_bench \
    usr/lib/howy-ab/bench/smoke_test \
    usr/lib/security/ \
    usr/lib/security/pam_howy.so \
    usr/lib/systemd/ \
    usr/lib/systemd/system/ \
    usr/lib/systemd/system/howy.service \
    usr/lib/systemd/system/howy.socket | LC_ALL=C sort)

fail() {
    printf 'package A/B smoke: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

package_for_variant() {
    local variant="$1"
    local package_dir="${TARGET_ROOT}/${variant}/packages"
    local -a archives

    shopt -s nullglob
    archives=("${package_dir}"/howy-ab-rocm-*.pkg.tar*)
    shopt -u nullglob
    [ "${#archives[@]}" -eq 1 ] \
        || fail "expected exactly one ${variant} package, found ${#archives[@]}"
    [ -f "${archives[0]}" ] || fail "package is not a regular file: ${archives[0]}"
    printf '%s\n' "${archives[0]}"
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

validate_archive() {
    local variant="$1"
    local archive="$2"
    local root="$3"
    local manifest="$4"
    local paths_file="${root}/archive-paths"
    local expected_file="${root}/expected-paths"
    local type mode uid gid path link_target

    archive_manifest "${archive}" "${manifest}"
    cut -f5 "${manifest}" | LC_ALL=C sort > "${paths_file}"
    printf '%s\n' "${EXPECTED_PATHS}" > "${expected_file}"
    cmp -s "${expected_file}" "${paths_file}" \
        || fail "${variant} archive paths differ from the exact allowlist"

    if cut -f5 "${manifest}" | grep -Eiq \
        '(^|/)(\.INSTALL|\.CHANGELOG|etc|var|hooks?|sysusers|[^/]*(config|model|data|credential)[^/]*)(/|$)'; then
        fail "${variant} archive contains a forbidden control/config/data path"
    fi

    while IFS=$'\t' read -r type mode uid gid path link_target; do
        [ "${uid}:${gid}" = '0:0' ] \
            || fail "${variant} ${path} is not owned by UID/GID 0:0"
        case "${path}" in
            */)
                [ "${type}:${mode}:${link_target}" = 'directory:rwxr-xr-x:-' ] \
                    || fail "${variant} directory metadata differs at ${path}"
                ;;
            usr/bin/howy|usr/bin/howyd|usr/lib/howy-ab/bench/*)
                [ "${type}:${mode}:${link_target}" = 'file:rwxr-xr-x:-' ] \
                    || fail "${variant} executable metadata differs at ${path}"
                ;;
            *)
                [ "${type}:${mode}:${link_target}" = 'file:rw-r--r--:-' ] \
                    || fail "${variant} file metadata differs at ${path}"
                ;;
        esac
    done < "${manifest}"

    mkdir -p "${root}/extracted"
    bsdtar -xf "${archive}" -C "${root}/extracted"
}

validate_elf() {
    local variant="$1"
    local root="$2"
    local relative="$3"
    local kind="$4"
    local file="${root}/extracted/${relative}"
    local dynamic interpreter ldd_output resolved

    [ -f "${file}" ] || fail "${variant} missing ELF file ${relative}"
    readelf -h "${file}" >/dev/null \
        || fail "${variant} ${relative} is not a readable ELF file"

    interpreter=$(readelf -l "${file}" | grep -F 'Requesting program interpreter:' || true)
    if [ "${kind}" = executable ]; then
        [[ "${interpreter}" == *'/lib64/ld-linux-x86-64.so.2]'* ]] \
            || fail "${variant} ${relative} has an unexpected ELF interpreter"
    elif [ -n "${interpreter}" ]; then
        fail "${variant} shared library ${relative} unexpectedly has an ELF interpreter"
    fi

    dynamic=$(readelf -d "${file}")
    [[ "${dynamic}" == *'(NEEDED)'* ]] \
        || fail "${variant} ${relative} has no DT_NEEDED entries"
    if [[ "${dynamic}" == *'(RPATH)'* || "${dynamic}" == *'(RUNPATH)'* ]]; then
        fail "${variant} ${relative} contains RPATH/RUNPATH"
    fi
    if printf '%s\n' "${dynamic}" | grep -E '\(NEEDED\).*\[[^]]*/[^]]*\]' >/dev/null; then
        fail "${variant} ${relative} has an absolute/path DT_NEEDED entry"
    fi

    ldd_output=$(ldd "${file}" 2>&1) \
        || fail "${variant} ldd failed for ${relative}: ${ldd_output}"
    [[ "${ldd_output}" != *'not found'* ]] \
        || fail "${variant} ${relative} has an unresolved runtime dependency"

    case "${relative}" in
        usr/bin/howyd|usr/lib/howy-ab/bench/smoke_test|usr/lib/howy-ab/bench/capture_bench)
            [[ "${dynamic}" == *'Shared library: [libonnxruntime.so.1]'* ]] \
                || fail "${variant} ${relative} does not need libonnxruntime.so.1"
            resolved=$(printf '%s\n' "${ldd_output}" \
                | grep -E '^[[:space:]]*libonnxruntime\.so\.1[[:space:]]+=>' || true)
            [[ "${resolved}" == *'=> /usr/lib/'* ]] \
                || fail "${variant} ${relative} does not resolve libonnxruntime.so.1 under /usr/lib"
            ;;
    esac
}

for command in bsdtar cmp cut grep ldd mktemp readelf sort; do
    require_command "${command}"
done

work=$(mktemp -d "${TARGET_ROOT}/smoke.XXXXXX")
cleanup() {
    rm -rf -- "${work}"
}
trap cleanup EXIT INT TERM

master_package=$(package_for_variant master)
hardened_package=$(package_for_variant hardened)
mkdir -p "${work}/master" "${work}/hardened"

validate_archive master "${master_package}" "${work}/master" "${work}/master.manifest"
validate_archive hardened "${hardened_package}" "${work}/hardened" "${work}/hardened.manifest"
cmp -s "${work}/master.manifest" "${work}/hardened.manifest" \
    || fail 'master and hardened path/type/mode/ownership manifests differ'

for variant in master hardened; do
    root="${work}/${variant}"
    validate_elf "${variant}" "${root}" usr/bin/howyd executable
    validate_elf "${variant}" "${root}" usr/bin/howy executable
    validate_elf "${variant}" "${root}" usr/lib/security/pam_howy.so library
    validate_elf "${variant}" "${root}" usr/lib/howy-ab/bench/smoke_test executable
    validate_elf "${variant}" "${root}" usr/lib/howy-ab/bench/capture_bench executable

    "${root}/extracted/usr/bin/howyd" --help >/dev/null
    "${root}/extracted/usr/bin/howy" --version >/dev/null
done

printf 'package A/B structural smoke passed: master=%s hardened=%s\n' \
    "${master_package}" "${hardened_package}"
