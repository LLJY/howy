#!/bin/bash

set -euo pipefail

TEST_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(dirname "$(dirname "${TEST_DIR}")")
EXPECTED_LEGACY_HASH=c6ce9bfdf7e79dfa9ec85f3529a4a4400de8855da0d9488809ecbdf9966b1e01
EXPECTED_BOOTSTRAP_HASH=45d544fb9261da2dc1f6ce1ec546f0889c4934ca19eb39921074513081421ca4

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

assert_mode() {
    local path="$1"
    local expected="$2"
    [ "$(stat -c '%a' "${path}")" = "${expected}" ] \
        || fail "${path} mode is not ${expected}"
}

assert_file() {
    [ -f "$1" ] || fail "missing package file: $1"
}

cd "${REPO_ROOT}"

cmp -s packaging/config-release-n-legacy.toml <(git show 'a7d187d:config.toml') \
    || fail "release-N legacy fixture differs from a7d187d:config.toml"
[ "$(sha256sum packaging/config-release-n-legacy.toml | cut -d' ' -f1)" = "${EXPECTED_LEGACY_HASH}" ] \
    || fail "legacy fixture hash changed"
[ "$(sha256sum packaging/config.bootstrap.toml | cut -d' ' -f1)" = "${EXPECTED_BOOTSTRAP_HASH}" ] \
    || fail "bootstrap fixture hash changed"

hook=$(<packaging/05-howy-config-stash.hook)
[[ "${hook}" == *"Operation = Upgrade"* ]] || fail "hook lacks Upgrade coverage"
[[ "${hook}" == *"Operation = Remove"* ]] || fail "hook lacks Remove coverage"
[[ "${hook}" == *"Type = Package"* ]] || fail "hook is not a package trigger"
[[ "${hook}" == *"When = PreTransaction"* ]] || fail "hook is not PreTransaction"
[[ "${hook}" == *"Exec = /usr/lib/howy/howy-config-bridge stash-release-n"* ]] \
    || fail "hook does not use the absolute stash helper"
[[ "${hook}" == *"AbortOnFail"* ]] || fail "hook lacks AbortOnFail"
for variant in howy-cpu-git howy-rocm-git howy-cuda-git; do
    [[ "${hook}" == *"Target = ${variant}"* ]] || fail "hook misses ${variant}"
done

install_script=$(<howy.install)
[[ "${install_script}" == *'/usr/lib/howy/howy-config-bridge bootstrap-release-n'* ]] \
    || fail "post_install does not invoke bootstrap-release-n"
[[ "${install_script}" == *'sudo howy security provision --mode 1'* ]] \
    || fail "post_install omits the exact provision command"
[[ "${install_script}" == *'sudo howy security enable'* ]] \
    || fail "post_install omits the exact enable command"
[[ "${install_script}" == *'/usr/lib/howy/howy-config-bridge stash-release-n'* ]] \
    || fail "pre_remove does not preserve exact config state for removal/variant switch"
[[ "${install_script}" == *'cannot protect an upgrade path that skipped release N'* ]] \
    || fail "install script does not reject the skipped-N assurance claim"
[[ "${install_script}" != *'systemctl enable'* ]] || fail "install script enables a service"
[[ "${install_script}" != *'systemd-creds'* ]] || fail "install script performs credential operations"
[ "$(grep -c 'bootstrap-release-n' howy.install)" -eq 1 ] \
    || fail "bootstrap-release-n must occur only in true-fresh post_install"
# shellcheck source=../../howy.install
source "${REPO_ROOT}/howy.install"
[[ "$(declare -f post_upgrade)" != *'bootstrap-release-n'* ]] \
    || fail "post_upgrade invokes bootstrap replacement"

temporary=$(mktemp -d)
trap 'rm -rf "${temporary}"' EXIT
mkdir -p "${temporary}/target/release"
printf 'howyd\n' > "${temporary}/target/release/howyd"
printf 'howy\n' > "${temporary}/target/release/howy"
printf 'bridge\n' > "${temporary}/target/release/howy-config-bridge"
printf 'pam\n' > "${temporary}/target/release/libpam_howy.so"
chmod 0755 \
    "${temporary}/target/release/howyd" \
    "${temporary}/target/release/howy" \
    "${temporary}/target/release/howy-config-bridge"
ln -s "${REPO_ROOT}" "${temporary}/howy-git"

# shellcheck source=../../PKGBUILD
source "${REPO_ROOT}/PKGBUILD"

# Direct package-function tests run without fakeroot, so ignore only the
# requested root ownership flags. Modes and complete package content remain
# the real install(1) behavior.
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

for variant in howy-cpu-git howy-rocm-git howy-cuda-git; do
    pkgname="${variant}"
    srcdir="${temporary}"
    pkgdir="${temporary}/pkg-${variant}"
    mkdir -p "${pkgdir}"
    "package_${variant}"

    [ "${backup[*]}" = "etc/howy/config.toml" ] || fail "${variant} lost config backup ownership"
    [ "${install}" = "howy.install" ] || fail "${variant} lost install script"
    [[ " ${depends[*]} " == *" systemd>=261 "* ]] || fail "${variant} lacks systemd>=261"
    [[ " ${optdepends[*]} " == *" tpm2-tss: TPM-backed systemd credential provisioning "* ]] \
        || fail "${variant} lacks reviewed TPM optional dependency"
    [[ " ${conflicts[*]} " != *" ${variant} "* ]] || fail "${variant} conflicts with itself"
    for other in howy-cpu-git howy-rocm-git howy-cuda-git; do
        if [ "${other}" != "${variant}" ]; then
            [[ " ${conflicts[*]} " == *" ${other} "* ]] \
                || fail "${variant} does not conflict with ${other}"
        fi
    done

    for file in \
        usr/bin/howyd \
        usr/bin/howy \
        usr/lib/howy/howy-config-bridge \
        usr/lib/security/pam_howy.so \
        usr/lib/systemd/system/howy.service \
        usr/lib/systemd/system/howy.socket \
        usr/lib/sysusers.d/howy.conf \
        usr/share/howy/config.bootstrap.toml \
        usr/share/libalpm/hooks/05-howy-config-stash.hook \
        etc/howy/config.toml; do
        assert_file "${pkgdir}/${file}"
    done
    cmp -s packaging/config-release-n-legacy.toml "${pkgdir}/etc/howy/config.toml" \
        || fail "${variant} packages a nonlegacy /etc payload"
    cmp -s packaging/config.bootstrap.toml "${pkgdir}/usr/share/howy/config.bootstrap.toml" \
        || fail "${variant} bootstrap payload differs"
    assert_mode "${pkgdir}/etc/howy/config.toml" 644
    assert_mode "${pkgdir}/usr/share/howy/config.bootstrap.toml" 644
    assert_mode "${pkgdir}/usr/lib/howy/howy-config-bridge" 755

    for directory in \
        etc/howy \
        etc/howy/models \
        etc/howy/models/mode1 \
        etc/credstore.encrypted \
        var/lib/howy \
        var/lib/howy/security-state \
        var/lib/howy/security-state/unadopted \
        var/lib/howy/config-bridge \
        var/cache/howy \
        var/log/howy; do
        assert_mode "${pkgdir}/${directory}" 700
    done
    assert_mode "${pkgdir}/etc/systemd/system/howy.service.d" 755
done

printf 'release-N package matrix: 3 variants passed\n'

"${TEST_DIR}/package-alpm-matrix.sh"
