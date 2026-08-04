#!/bin/bash

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(dirname "${SCRIPT_DIR}")
AB_DIR="${REPO_ROOT}/packaging/ab"
TARGET_ROOT="${REPO_ROOT}/target/package-ab"

fail() {
    printf 'package A/B build: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

if [ "$(id -u)" -eq 0 ]; then
    fail 'refusing to run as root'
fi

for command in cargo clang git makepkg protoc sha256sum stat tee; do
    require_command "${command}"
done

mkdir -p "${TARGET_ROOT}"

for variant in master hardened; do
    variant_root="${TARGET_ROOT}/${variant}"
    build_dir="${variant_root}/build"
    source_dir="${variant_root}/sources"
    package_dir="${variant_root}/packages"
    log_dir="${variant_root}/logs"
    source_package_dir="${variant_root}/source-packages"

    mkdir -p \
        "${build_dir}" \
        "${source_dir}" \
        "${package_dir}" \
        "${log_dir}" \
        "${source_package_dir}"

    shopt -s nullglob
    stale_archives=("${package_dir}"/howy-ab-rocm-*.pkg.tar*)
    shopt -u nullglob
    for stale_archive in "${stale_archives[@]}"; do
        [ -f "${stale_archive}" ] \
            || fail "refusing to clean non-file package output: ${stale_archive}"
        rm -f -- "${stale_archive}"
    done
    rm -f -- "${log_dir}/build.log"

    printf 'Building %s in %s\n' "${variant}" "${variant_root}"
    (
        export BUILDDIR="${build_dir}"
        export SRCDEST="${source_dir}"
        export PKGDEST="${package_dir}"
        export LOGDEST="${log_dir}"
        export SRCPKGDEST="${source_package_dir}"
        export LC_ALL=C
        makepkg -D "${AB_DIR}" -p "PKGBUILD.${variant}" \
            --cleanbuild --clean --nosign --noconfirm --noprogressbar
    ) 2>&1 | tee "${log_dir}/build.log"

    shopt -s nullglob
    archives=("${package_dir}"/howy-ab-rocm-*.pkg.tar*)
    shopt -u nullglob
    [ "${#archives[@]}" -eq 1 ] \
        || fail "expected one ${variant} package, found ${#archives[@]}"

    archive=${archives[0]}
    archive_hash=$(sha256sum "${archive}" | cut -d' ' -f1)
    archive_size=$(stat -c '%s' "${archive}")
    printf '%s package: %s\n' "${variant}" "${archive}"
    printf '%s sha256: %s\n' "${variant}" "${archive_hash}"
    printf '%s bytes: %s\n' "${variant}" "${archive_size}"
done
