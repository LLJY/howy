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
for variant in howy-cpu howy-rocm howy-cuda; do
    [[ "${hook}" == *"Target = ${variant}"* ]] || fail "hook misses ${variant}"
done
[ "$(grep -c '^Target = ' packaging/05-howy-config-stash.hook)" -eq 3 ] \
    || fail "stable hook target set is not exact"
[[ "${hook}" != *'-git'* ]] || fail "stable hook retains release-N targets"

admission_hook=$(<packaging/00-howy-update-admission.hook)
[[ "${admission_hook}" == *"Operation = Upgrade"* ]] \
    || fail "update-admission hook lacks Upgrade coverage"
[[ "${admission_hook}" != *"Operation = Install"* ]] \
    || fail "update-admission hook runs during Install"
[[ "${admission_hook}" != *"Operation = Remove"* ]] \
    || fail "update-admission hook runs during Remove"
[[ "${admission_hook}" == *"Type = Package"* ]] \
    || fail "update-admission hook is not a package trigger"
[[ "${admission_hook}" == *"When = PreTransaction"* ]] \
    || fail "update-admission hook is not PreTransaction"
[[ "${admission_hook}" == *"Exec = /usr/lib/howy/howy-v2-update-admission"* ]] \
    || fail "update-admission hook does not use the absolute helper"
[[ "${admission_hook}" == *"AbortOnFail"* ]] \
    || fail "update-admission hook lacks AbortOnFail"
[[ "${admission_hook}" == *"NeedsTargets"* ]] \
    || fail "update-admission hook does not receive triggering targets"
for variant in howy-cpu howy-rocm howy-cuda; do
    [[ "${admission_hook}" == *"Target = ${variant}"* ]] \
        || fail "update-admission hook misses ${variant}"
done
[ "$(grep -c '^Target = ' packaging/00-howy-update-admission.hook)" -eq 3 ] \
    || fail "update-admission hook target set is not exact"
[[ "${admission_hook}" != *'-git'* ]] || fail "update-admission hook retains predecessor targets"
[[ 00-howy-update-admission.hook < 05-howy-config-stash.hook ]] \
    || fail "update-admission hook does not sort before config stash"

remove_hook=$(<packaging/10-howy-remove-prepare.hook)
[[ "${remove_hook}" == *"Operation = Remove"* ]] || fail "removal hook lacks Remove coverage"
[[ "${remove_hook}" != *"Operation = Upgrade"* ]] || fail "removal hook runs during Upgrade"
[[ "${remove_hook}" == *"Type = Package"* ]] || fail "removal hook is not a package trigger"
[[ "${remove_hook}" == *"When = PreTransaction"* ]] || fail "removal hook is not PreTransaction"
[[ "${remove_hook}" == *"Exec = /usr/lib/howy/howy-v2-remove-prepare"* ]] \
    || fail "removal hook does not use the absolute helper"
[[ "${remove_hook}" == *"AbortOnFail"* ]] || fail "removal hook lacks AbortOnFail"
for variant in howy-cpu howy-rocm howy-cuda; do
    [[ "${remove_hook}" == *"Target = ${variant}"* ]] \
        || fail "removal hook misses ${variant}"
done
[ "$(grep -c '^Target = ' packaging/10-howy-remove-prepare.hook)" -eq 3 ] \
    || fail "removal hook target set is not exact"
[[ "${remove_hook}" != *'-git'* ]] || fail "removal hook retains release-N targets"

[ -x scripts/howy-v2-remove-prepare ] || fail "removal helper is not executable"
remove_helper=$(<scripts/howy-v2-remove-prepare)
[[ "${remove_helper}" == *'/usr/bin/systemctl stop howy.socket'* ]] \
    || fail "removal helper does not stop the socket"
[[ "${remove_helper}" == *'/usr/bin/systemctl stop howy.service'* ]] \
    || fail "removal helper does not stop the service"
[[ "${remove_helper}" == *'/usr/bin/systemctl disable howy.socket howy.service'* ]] \
    || fail "removal helper does not disable both units"
[[ "${remove_helper}" == *'require_unit_property howy.socket ActiveState inactive'* ]] \
    || fail "removal helper does not verify inactive state"
[[ "${remove_helper}" == *'require_unit_property howy.service UnitFileState disabled'* ]] \
    || fail "removal helper does not verify disabled state"

[ -x scripts/howy-v2-update-admission ] || fail "update-admission helper is not executable"
admission_helper=$(<scripts/howy-v2-update-admission)
[[ "${admission_helper}" == *"set -euo pipefail"* ]] \
    || fail "update-admission helper is not strict Bash"
[[ "${admission_helper}" == *'if [[ "${source_package}" != "${target_package}" ]]'* ]] \
    || fail "update-admission helper lacks source-target equality"
[[ "${admission_helper}" == *'if [[ "${target_package}" != "${triggering_package}" ]]'* ]] \
    || fail "update-admission helper lacks trigger-target equality"
[[ "${admission_helper}" == *'/usr/bin/sha256sum -- "${SENTINEL_PATH}"'* ]] \
    || fail "update-admission helper lacks exact sentinel-byte validation"

install_script=$(<howy.install)
[[ "${install_script}" == *'/usr/lib/howy/howy-config-bridge bootstrap-release-n'* ]] \
    || fail "post_install does not invoke bootstrap-release-n"
[[ "${install_script}" == *'sudo howy security provision --mode 1'* ]] \
    || fail "post_install omits the exact provision command"
[[ "${install_script}" == *'sudo howy security enable'* ]] \
    || fail "post_install omits the exact enable command"
[[ "${install_script}" == *'/usr/lib/howy/howy-config-bridge stash-release-n'* ]] \
    || fail "pre_remove does not preserve exact config state for removal/variant switch"
[[ "${install_script}" == *'/usr/lib/howy/howy-v2-remove-prepare'* ]] \
    || fail "pre_remove does not invoke the defensive removal helper"
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
ln -s "${REPO_ROOT}" "${temporary}/howy"

# shellcheck source=../../PKGBUILD
pkgbuild_text=$(<"${REPO_ROOT}/PKGBUILD")
srcinfo_text=$(<"${REPO_ROOT}/.SRCINFO")
[[ "${pkgbuild_text}" != *'replaces='* ]] \
    || fail "stable PKGBUILD retains automatic predecessor replacement"
[[ "${srcinfo_text}" != *$'\treplaces = '* ]] \
    || fail "generated .SRCINFO retains automatic predecessor replacement"
source "${REPO_ROOT}/PKGBUILD"
[ "${pkgbase}" = howy ] || fail "root package base is not canonical howy"
[ "${pkgver}" = 2.0.0 ] || fail "root package version is not 2.0.0"
[ "${pkgname[*]}" = "howy-cpu howy-rocm howy-cuda" ] \
    || fail "root split package names are not canonical"
[[ " ${makedepends[*]} " == *" onnxruntime=1.28.0 "* ]] \
    || fail "root package lacks the ABI-pinned virtual ONNX Runtime build dependency"
for concrete_runtime in onnxruntime-cpu onnxruntime-rocm onnxruntime-cuda; do
    [[ " ${makedepends[*]} " != *" ${concrete_runtime} "* ]] \
        || fail "root package retains concrete build dependency ${concrete_runtime}"
done

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

for variant in howy-cpu howy-rocm howy-cuda; do
    unset -v replaces || true
    pkgname="${variant}"
    srcdir="${temporary}"
    pkgdir="${temporary}/pkg-${variant}"
    mkdir -p "${pkgdir}"
    "package_${variant}"

    [ "${backup[*]}" = "etc/howy/config.toml" ] || fail "${variant} lost config backup ownership"
    [ "${install}" = "howy.install" ] || fail "${variant} lost install script"
    [ "$(printf '%s\n' "${depends[@]}" | grep -cx 'diffutils')" -eq 1 ] \
        || fail "${variant} must depend on diffutils exactly once"
    [[ " ${depends[*]} " == *" systemd>=261 "* ]] || fail "${variant} lacks systemd>=261"
    [[ " ${optdepends[*]} " == *" tpm2-tss: TPM-backed systemd credential provisioning "* ]] \
        || fail "${variant} lacks reviewed TPM optional dependency"
    [[ " ${provides[*]} " == *" howy=2.0.0 "* ]] || fail "${variant} lacks stable howy provide"
    [[ " ${provides[*]} " == *" howdy=2.0.0 "* ]] || fail "${variant} lacks stable howdy provide"
    [[ ! -v replaces ]] || fail "${variant} declares automatic predecessor replacement"
    [[ " ${conflicts[*]} " != *" ${variant} "* ]] || fail "${variant} conflicts with itself"
    for legacy in howy howy-git howy-cpu-git howy-rocm-git howy-cuda-git \
        howy-rocm-mode0 howdy howdy-git; do
        [[ " ${conflicts[*]} " == *" ${legacy} "* ]] \
            || fail "${variant} does not conflict with ${legacy}"
    done
    for other in howy-cpu howy-rocm howy-cuda; do
        if [ "${other}" != "${variant}" ]; then
            [[ " ${conflicts[*]} " == *" ${other} "* ]] \
                || fail "${variant} does not conflict with ${other}"
        fi
    done
    [[ " ${depends[*]} " == *" onnxruntime=1.28.0 "* ]] \
        || fail "${variant} lacks the ABI-pinned virtual ONNX Runtime runtime dependency"
    for concrete_runtime in onnxruntime-cpu onnxruntime-rocm onnxruntime-cuda; do
        [[ " ${depends[*]} " != *" ${concrete_runtime} "* ]] \
            || fail "${variant} retains concrete runtime dependency ${concrete_runtime}"
    done

    for file in \
        usr/bin/howyd \
        usr/bin/howy \
        usr/bin/howy-download-models \
        usr/bin/howy-enroll \
        usr/bin/howy-v2-update \
        usr/lib/howy/howy-config-bridge \
        usr/lib/howy/howy-v2-update-admission \
        usr/lib/howy/howy-v2-remove-prepare \
        usr/lib/security/pam_howy.so \
        usr/lib/systemd/system/howy.service \
        usr/lib/systemd/system/howy.socket \
        usr/lib/sysusers.d/howy.conf \
        usr/share/howy/config.bootstrap.toml \
        usr/share/libalpm/hooks/00-howy-update-admission.hook \
        usr/share/libalpm/hooks/05-howy-config-stash.hook \
        usr/share/libalpm/hooks/10-howy-remove-prepare.hook \
        "usr/share/doc/${variant}/README.md" \
        "usr/share/licenses/${variant}/LICENSE" \
        etc/howy/config.toml; do
        assert_file "${pkgdir}/${file}"
    done
    [ -L "${pkgdir}/usr/lib/security/pam_howdy.so" ] \
        || fail "${variant} PAM compatibility alias is not a symlink"
    [ "$(readlink "${pkgdir}/usr/lib/security/pam_howdy.so")" = pam_howy.so ] \
        || fail "${variant} PAM compatibility alias is not relative to pam_howy.so"
    cmp -s packaging/config-release-n-legacy.toml "${pkgdir}/etc/howy/config.toml" \
        || fail "${variant} packages a nonlegacy /etc payload"
    cmp -s packaging/config.bootstrap.toml "${pkgdir}/usr/share/howy/config.bootstrap.toml" \
        || fail "${variant} bootstrap payload differs"
    cmp -s packaging/05-howy-config-stash.hook \
        "${pkgdir}/usr/share/libalpm/hooks/05-howy-config-stash.hook" \
        || fail "${variant} stable config hook differs"
    cmp -s packaging/00-howy-update-admission.hook \
        "${pkgdir}/usr/share/libalpm/hooks/00-howy-update-admission.hook" \
        || fail "${variant} update-admission hook differs"
    cmp -s packaging/10-howy-remove-prepare.hook \
        "${pkgdir}/usr/share/libalpm/hooks/10-howy-remove-prepare.hook" \
        || fail "${variant} removal hook differs"
    cmp -s scripts/howy-v2-update "${pkgdir}/usr/bin/howy-v2-update" \
        || fail "${variant} updater payload differs"
    cmp -s scripts/howy-v2-update-admission \
        "${pkgdir}/usr/lib/howy/howy-v2-update-admission" \
        || fail "${variant} update-admission helper payload differs"
    cmp -s scripts/howy-v2-remove-prepare \
        "${pkgdir}/usr/lib/howy/howy-v2-remove-prepare" \
        || fail "${variant} removal helper payload differs"
    assert_mode "${pkgdir}/etc/howy/config.toml" 644
    assert_mode "${pkgdir}/usr/share/howy/config.bootstrap.toml" 644
    assert_mode "${pkgdir}/usr/lib/howy/howy-config-bridge" 755
    assert_mode "${pkgdir}/usr/bin/howy-v2-update" 755
    assert_mode "${pkgdir}/usr/lib/howy/howy-v2-update-admission" 755
    assert_mode "${pkgdir}/usr/lib/howy/howy-v2-remove-prepare" 755
    assert_mode "${pkgdir}/usr/share/libalpm/hooks/00-howy-update-admission.hook" 644
    assert_mode "${pkgdir}/usr/share/libalpm/hooks/05-howy-config-stash.hook" 644
    assert_mode "${pkgdir}/usr/share/libalpm/hooks/10-howy-remove-prepare.hook" 644

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
    assert_mode "${pkgdir}/usr/share/howy/onnx-data" 755
done

printf 'v2 package matrix: 3 stable variants passed; release-N legacy/bootstrap fixtures remain hash-pinned\n'
printf 'historical release-N ALPM matrix is separate: run scripts/tests/package-alpm-matrix.sh directly\n'
