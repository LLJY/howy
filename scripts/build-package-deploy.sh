#!/bin/bash

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(dirname "${SCRIPT_DIR}")
TARGET_ROOT="${REPO_ROOT}/target/package-deploy"
BUILD_DIR="${TARGET_ROOT}/build"
SOURCE_DIR="${TARGET_ROOT}/sources"
PACKAGE_DIR="${TARGET_ROOT}/packages"
LOG_DIR="${TARGET_ROOT}/logs"
SOURCE_PACKAGE_DIR="${TARGET_ROOT}/source-packages"

fail() {
    printf 'package deploy build: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

if (( EUID == 0 )); then
    fail 'refusing to run as root'
fi

for command in cargo clang git makepkg protoc sha256sum stat tee; do
    require_command "${command}"
done

mkdir -p \
    "${BUILD_DIR}" \
    "${SOURCE_DIR}" \
    "${PACKAGE_DIR}" \
    "${LOG_DIR}" \
    "${SOURCE_PACKAGE_DIR}"

shopt -s nullglob
stale_archives=("${PACKAGE_DIR}"/howy-rocm-mode0-*.pkg.tar*)
shopt -u nullglob
[ "${#stale_archives[@]}" -le 1 ] \
    || fail "refusing to replace ${#stale_archives[@]} prior package archives"
for stale_archive in "${stale_archives[@]}"; do
    [ -f "${stale_archive}" ] && [ ! -L "${stale_archive}" ] \
        || fail "refusing to replace non-regular package output: ${stale_archive}"
    rm -- "${stale_archive}"
done

build_log="${LOG_DIR}/build.log"
if [ -e "${build_log}" ] || [ -L "${build_log}" ]; then
    [ -f "${build_log}" ] && [ ! -L "${build_log}" ] \
        || fail "refusing to replace non-regular build log: ${build_log}"
    rm -- "${build_log}"
fi

printf 'Building deploy candidate in %s\n' "${TARGET_ROOT}"
(
    cd "${REPO_ROOT}"
    export BUILDDIR="${BUILD_DIR}"
    export SRCDEST="${SOURCE_DIR}"
    export PKGDEST="${PACKAGE_DIR}"
    export LOGDEST="${LOG_DIR}"
    export SRCPKGDEST="${SOURCE_PACKAGE_DIR}"
    export LC_ALL=C
    makepkg -D packaging/deploy -p PKGBUILD \
        --cleanbuild --clean --nosign --noconfirm --noprogressbar
) 2>&1 | tee "${build_log}"

shopt -s nullglob
archives=("${PACKAGE_DIR}"/howy-rocm-mode0-*.pkg.tar*)
shopt -u nullglob
[ "${#archives[@]}" -eq 1 ] \
    || fail "expected exactly one package archive, found ${#archives[@]}"
[ -f "${archives[0]}" ] && [ ! -L "${archives[0]}" ] \
    || fail "package output is not a regular file: ${archives[0]}"

archive=${archives[0]}
read -r archive_hash _ < <(sha256sum "${archive}")
archive_size=$(stat -c '%s' "${archive}")
[ -n "${archive_hash}" ] || fail 'empty package SHA-256'
[[ "${archive_size}" =~ ^[1-9][0-9]*$ ]] || fail 'empty package archive'

printf 'package archive: %s\n' "${archive}"
printf 'package sha256: %s\n' "${archive_hash}"
printf 'package bytes: %s\n' "${archive_size}"
