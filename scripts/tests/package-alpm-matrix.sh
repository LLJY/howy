#!/bin/bash

# Real libalpm qualification for the release-N bridge. Every pacman invocation
# uses a disposable root, database, cache, hook directory, and logfile under one
# mktemp tree. Package scriptlets/hooks execute in pacman's chroot, under a
# mapped-root user+mount namespace; no host package database or installed path is
# reachable through the chroot.

set -euo pipefail

TEST_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(dirname "$(dirname "${TEST_DIR}")")
PACMAN=/usr/bin/pacman
UNSHARE=/usr/bin/unshare
CHROOT=/usr/bin/chroot
BSDTAR=/usr/bin/bsdtar

fail() {
    printf 'ALPM FAIL: %s\n' "$*" >&2
    exit 1
}

for tool in "${PACMAN}" "${UNSHARE}" "${CHROOT}" "${BSDTAR}" /usr/bin/strace; do
    [ -x "${tool}" ] || fail "required real-ALPM tool is unavailable: ${tool}"
done

cd "${REPO_ROOT}"
cargo build --quiet -p howy-config-bridge
BRIDGE_BINARY="${REPO_ROOT}/target/debug/howy-config-bridge"
[ -x "${BRIDGE_BINARY}" ] || fail "bridge binary was not built"

WORK=$(mktemp -d)
cleanup() {
    if [ "${HOWY_KEEP_ALPM_WORK:-0}" = 1 ]; then
        printf 'retained ALPM worktree: %s\n' "${WORK}" >&2
    else
        rm -rf -- "${WORK}"
    fi
}
trap cleanup EXIT INT TERM
PACKAGES="${WORK}/packages"
mkdir -p "${PACKAGES}"

copy_runtime_file() {
    local source="$1"
    local root="$2"
    local destination="${root}${source}"
    mkdir -p "$(dirname "${destination}")"
    cp -L -- "${source}" "${destination}"
}

copy_runtime() {
    local binary="$1"
    local root="$2"
    local line
    local token
    copy_runtime_file "${binary}" "${root}"
    while IFS= read -r line; do
        for token in ${line}; do
            token=${token%%\(*}
            if [[ "${token}" == /* ]] && [ -f "${token}" ]; then
                copy_runtime_file "${token}" "${root}"
            fi
        done
    done < <(ldd "${binary}")
}

write_pkginfo() {
    local destination="$1"
    local name="$2"
    local version="$3"
    shift 3
    cat > "${destination}" <<EOF
pkgname = ${name}
pkgbase = ${name}
pkgver = ${version}
pkgdesc = isolated release-N ALPM fixture
url = https://example.invalid/howy-alpm-fixture
builddate = 1
packager = howy isolated ALPM test
size = 4096
arch = x86_64
backup = etc/howy/config.toml
EOF
    local conflict
    for conflict in "$@"; do
        printf 'conflict = %s\n' "${conflict}" >> "${destination}"
    done
}

package_tree() {
    local tree="$1"
    install -d -m 0755 "${tree}/etc/howy" "${tree}/usr/lib/systemd/system"
    install -d -m 0700 \
        "${tree}/etc/howy/models" \
        "${tree}/etc/howy/models/mode1" \
        "${tree}/etc/credstore.encrypted" \
        "${tree}/var/lib/howy" \
        "${tree}/var/lib/howy/security-state" \
        "${tree}/var/lib/howy/security-state/unadopted" \
        "${tree}/var/lib/howy/config-bridge" \
        "${tree}/var/cache/howy" \
        "${tree}/var/log/howy"
    install -d -m 0755 \
        "${tree}/etc/systemd/system/howy.service.d" \
        "${tree}/usr/lib/howy" \
        "${tree}/usr/share/howy" \
        "${tree}/usr/share/libalpm/hooks"
}

archive_package() {
    local tree="$1"
    local archive="$2"
    local -a entries=(.PKGINFO)
    [ ! -f "${tree}/.INSTALL" ] || entries+=(.INSTALL)
    [ ! -d "${tree}/etc" ] || entries+=(etc)
    [ ! -d "${tree}/usr" ] || entries+=(usr)
    [ ! -d "${tree}/var" ] || entries+=(var)
    "${BSDTAR}" --uid 0 --gid 0 -cf "${archive}" -C "${tree}" "${entries[@]}"
}

build_predecessor() {
    local name="$1"
    local tree="${WORK}/tree-${name}-nminus1"
    local archive="${PACKAGES}/${name}-0.0.9-1-x86_64.pkg.tar"
    mkdir -p "${tree}/etc/howy"
    write_pkginfo "${tree}/.PKGINFO" "${name}" "0.0.9-1"
    install -m 0644 packaging/config-release-n-legacy.toml "${tree}/etc/howy/config.toml"
    archive_package "${tree}" "${archive}"
}

build_release_n() {
    local name="$1"
    shift
    local tree="${WORK}/tree-${name}-n"
    local archive="${PACKAGES}/${name}-0.1.0-1-x86_64.pkg.tar"
    mkdir -p "${tree}"
    package_tree "${tree}"
    write_pkginfo "${tree}/.PKGINFO" "${name}" "0.1.0-1" "$@"
    install -m 0644 packaging/config-release-n-legacy.toml "${tree}/etc/howy/config.toml"
    install -m 0644 packaging/config.bootstrap.toml "${tree}/usr/share/howy/config.bootstrap.toml"
    install -m 0755 "${BRIDGE_BINARY}" "${tree}/usr/lib/howy/howy-config-bridge"
    install -m 0644 packaging/05-howy-config-stash.hook \
        "${tree}/usr/share/libalpm/hooks/05-howy-config-stash.hook"
    install -m 0644 systemd/howy.service "${tree}/usr/lib/systemd/system/howy.service"
    install -m 0644 systemd/howy.socket "${tree}/usr/lib/systemd/system/howy.socket"
    install -m 0644 howy.install "${tree}/.INSTALL"
    archive_package "${tree}" "${archive}"
}

build_nplus1() {
    local name="$1"
    local tree="${WORK}/tree-${name}-nplus1"
    local archive="${PACKAGES}/${name}-0.2.0-1-x86_64.pkg.tar"
    mkdir -p "${tree}"
    package_tree "${tree}"
    write_pkginfo "${tree}/.PKGINFO" "${name}" "0.2.0-1"
    install -m 0644 packaging/config-release-n-legacy.toml "${tree}/etc/howy/config.toml"
    install -m 0644 packaging/config.bootstrap.toml "${tree}/usr/share/howy/config.bootstrap.toml"
    install -m 0755 "${BRIDGE_BINARY}" "${tree}/usr/lib/howy/howy-config-bridge"
    install -m 0644 packaging/05-howy-config-stash.hook \
        "${tree}/usr/share/libalpm/hooks/05-howy-config-stash.hook"
    install -m 0644 systemd/howy.service "${tree}/usr/lib/systemd/system/howy.service"
    install -m 0644 systemd/howy.socket "${tree}/usr/lib/systemd/system/howy.socket"
    cat > "${tree}/.INSTALL" <<'EOF'
post_install() {
  printf '%s\n' 'simulated N+1 refuses fresh/skipped-N assurance without a release-N manifest' >&2
  return 1
}
post_upgrade() {
  if [ ! -f /var/lib/howy/config-bridge/manifest-v2.json ]; then
    printf '%s\n' 'simulated N+1 explicitly refuses skipped-N assurance: release-N manifest is absent' >&2
    return 1
  fi
  /usr/lib/howy/howy-config-bridge complete-release-n
}
pre_remove() {
  /usr/lib/howy/howy-config-bridge stash-release-n
}
EOF
    chmod 0644 "${tree}/.INSTALL"
    archive_package "${tree}" "${archive}"
}

for variant in howy-cpu-git howy-rocm-git howy-cuda-git; do
    build_predecessor "${variant}"
done
build_release_n howy-cpu-git howy-rocm-git howy-cuda-git
build_release_n howy-rocm-git howy-cpu-git howy-cuda-git
build_release_n howy-cuda-git howy-cpu-git howy-rocm-git
build_nplus1 howy-cpu-git

CPU_OLD="${PACKAGES}/howy-cpu-git-0.0.9-1-x86_64.pkg.tar"
CPU_N="${PACKAGES}/howy-cpu-git-0.1.0-1-x86_64.pkg.tar"
ROCM_N="${PACKAGES}/howy-rocm-git-0.1.0-1-x86_64.pkg.tar"
CUDA_N="${PACKAGES}/howy-cuda-git-0.1.0-1-x86_64.pkg.tar"
CPU_N1="${PACKAGES}/howy-cpu-git-0.2.0-1-x86_64.pkg.tar"

new_root() {
    local label="$1"
    local case_dir="${WORK}/case-${label}"
    local root="${case_dir}/root"
    mkdir -p \
        "${root}/bin" "${root}/run/lock" "${root}/tmp" "${root}/var/lib/pacman/local" \
        "${root}/var/cache/pacman/pkg" "${root}/var/log" "${case_dir}/hooks" \
        "${case_dir}/snapshots"
    chmod 0755 "${root}" "${root}/run" "${root}/run/lock" "${root}/var" "${root}/var/lib"
    chmod 1777 "${root}/tmp"
    cat > "${case_dir}/pacman.conf" <<EOF
[options]
Architecture = auto
SigLevel = Never
LocalFileSigLevel = Never
DisableSandbox
EOF
    for binary in /bin/bash /usr/bin/bash /usr/bin/cp /usr/bin/rm /usr/bin/mkdir /usr/bin/cmp /usr/bin/strace; do
        copy_runtime "${binary}" "${root}"
    done
    # The bridge's dynamic dependencies are present, while the binary itself is
    # supplied only by the fixture package under its real absolute path.
    while IFS= read -r line; do
        local token
        for token in ${line}; do
            token=${token%%\(*}
            if [[ "${token}" == /* ]] && [ -f "${token}" ]; then
                copy_runtime_file "${token}" "${root}"
            fi
        done
    done < <(ldd "${BRIDGE_BINARY}")
    ln -s bash "${root}/bin/sh"
    printf '%s\n' "${case_dir}"
}

sync_hookdir() {
    local case_dir="$1"
    local root="${case_dir}/root"
    rm -f -- "${case_dir}/hooks/05-howy-config-stash.hook"
    if [ -f "${root}/usr/share/libalpm/hooks/05-howy-config-stash.hook" ]; then
        cp -- "${root}/usr/share/libalpm/hooks/05-howy-config-stash.hook" \
            "${case_dir}/hooks/05-howy-config-stash.hook"
        cmp -s packaging/05-howy-config-stash.hook \
            "${case_dir}/hooks/05-howy-config-stash.hook" \
            || fail "${case_dir}: hookdir copy is not the exact installed release-N hook"
    fi
}

pacman_isolated() {
    local case_dir="$1"
    shift
    local root="${case_dir}/root"
    "${UNSHARE}" --user --map-root-user --mount -- \
        "${PACMAN}" \
        --config "${case_dir}/pacman.conf" \
        --root "${root}" \
        --dbpath "${root}/var/lib/pacman" \
        --cachedir "${root}/var/cache/pacman/pkg" \
        --hookdir "${case_dir}/hooks" \
        --logfile "${root}/var/log/pacman.log" \
        --noconfirm "$@"
}

snapshot_state() {
    local case_dir="$1"
    local label="$2"
    local root="${case_dir}/root"
    local destination="${case_dir}/snapshots/${label}.state"
    {
        printf 'packages:\n'
        pacman_isolated "${case_dir}" -Q 2>&1 || true
        printf 'local-db-files:\n'
        while IFS= read -r -d '' path; do
            printf '%s sha256=%s\n' \
                "${path#"${root}"}" \
                "$(sha256sum "${path}" | cut -d' ' -f1)"
        done < <(find "${root}/var/lib/pacman/local" -type f -print0 | sort -z)
        local path
        for path in \
            /etc/howy/config.toml \
            /etc/howy/config.toml.pacsave \
            /var/lib/howy-package-bootstrap.complete \
            /var/lib/howy/config-bridge/journal-v2.json \
            /var/lib/howy/config-bridge/manifest-v2.json \
            /var/lib/howy/config-bridge/config-release-n.stash.g1 \
            /var/lib/howy/config-bridge/config-release-n.stash.g2; do
            if [ -f "${root}${path}" ]; then
                printf '%s mode=%s sha256=%s\n' \
                    "${path}" \
                    "$(stat -c '%a' "${root}${path}")" \
                    "$(sha256sum "${root}${path}" | cut -d' ' -f1)"
            elif [ -e "${root}${path}" ] || [ -L "${root}${path}" ]; then
                printf '%s occupied-nonregular\n' "${path}"
            else
                printf '%s absent\n' "${path}"
            fi
        done
    } > "${destination}"
}

LAST_STATUS=0
LAST_OUTPUT=""
transaction() {
    local case_dir="$1"
    local label="$2"
    shift 2
    sync_hookdir "${case_dir}"
    set +e
    LAST_OUTPUT=$(pacman_isolated "${case_dir}" --nodeps "$@" 2>&1)
    LAST_STATUS=$?
    set -e
    printf '%s\n' "${LAST_OUTPUT}" > "${case_dir}/${label}.log"
    snapshot_state "${case_dir}" "${label}"
}

assert_success() {
    local label="$1"
    [ "${LAST_STATUS}" -eq 0 ] || fail "${label} failed (${LAST_STATUS}): ${LAST_OUTPUT}"
}

assert_failure() {
    local label="$1"
    [ "${LAST_STATUS}" -ne 0 ] || fail "${label} unexpectedly succeeded: ${LAST_OUTPUT}"
}

assert_config() {
    local case_dir="$1"
    local expected="$2"
    local expected_mode="$3"
    cmp -s "${expected}" "${case_dir}/root/etc/howy/config.toml" \
        || fail "${case_dir}: config bytes differ"
    [ "$(stat -c '%a' "${case_dir}/root/etc/howy/config.toml")" = "${expected_mode}" ] \
        || fail "${case_dir}: config mode differs"
}

assert_marker() {
    local case_dir="$1"
    [ -f "${case_dir}/root/var/lib/howy-package-bootstrap.complete" ] \
        || fail "${case_dir}: bootstrap marker is absent"
    [ "$(stat -c '%a' "${case_dir}/root/var/lib/howy-package-bootstrap.complete")" = 600 ] \
        || fail "${case_dir}: bootstrap marker mode differs"
}

package_version() {
    pacman_isolated "$1" -Q "$2" | cut -d' ' -f2
}

assert_backup_registered() {
    local case_dir="$1"
    local package="$2"
    local files
    files=$(printf '%s\n' "${case_dir}/root/var/lib/pacman/local/${package}-"*/files)
    [ -f "${files}" ] || fail "${case_dir}: package DB files record is absent"
    grep -q '^%BACKUP%$' "${files}" || fail "${case_dir}: package DB lacks BACKUP section"
    grep -q '^etc/howy/config.toml' "${files}" \
        || fail "${case_dir}: package DB lost config backup ownership"
}

# 1. Fresh release N: exact legacy package payload is exchanged for the exact
# disabled bootstrap, then the positive marker is committed.
case_dir=$(new_root fresh)
transaction "${case_dir}" fresh-n -U "${CPU_N}"
assert_success fresh-n
assert_config "${case_dir}" packaging/config.bootstrap.toml 600
assert_marker "${case_dir}"
grep -q 'ConditionPathExists=!/var/lib/howy-security-transaction.guard' \
    "${case_dir}/root/usr/lib/systemd/system/howy.service" || fail "fresh service lost guard"
grep -q 'ConditionPathExists=/var/lib/howy-package-bootstrap.complete' \
    "${case_dir}/root/usr/lib/systemd/system/howy.socket" || fail "fresh socket lost marker"

# 2. A malformed durable bridge control forces the actual post_install helper
# to fail. Pacman may still commit extraction, but no positive marker exists, so
# both units remain condition-guarded.
case_dir=$(new_root fresh-failure)
mkdir -p "${case_dir}/root/var/lib/howy/config-bridge"
chmod 0700 "${case_dir}/root/var/lib/howy" "${case_dir}/root/var/lib/howy/config-bridge"
printf '{malformed-journal}\n' > "${case_dir}/root/var/lib/howy/config-bridge/journal-v2.json"
chmod 0600 "${case_dir}/root/var/lib/howy/config-bridge/journal-v2.json"
transaction "${case_dir}" fresh-n-failed -U "${CPU_N}"
[ ! -e "${case_dir}/root/var/lib/howy-package-bootstrap.complete" ] \
    || fail "forced bootstrap failure created marker"
grep -q 'positive service start marker remains absent\|refused to replace' \
    "${case_dir}/fresh-n-failed.log" || fail "forced bridge failure was not reported"

# 3. Predecessor upgrades preserve both unmodified and modified config bytes;
# package backup metadata remains registered and no .pacnew is produced when N
# carries the byte-identical predecessor payload.
for state in unmodified modified; do
    case_dir=$(new_root "predecessor-${state}")
    transaction "${case_dir}" predecessor -U "${CPU_OLD}"
    assert_success "predecessor-${state} install"
    expected=packaging/config-release-n-legacy.toml
    mode=644
    if [ "${state}" = modified ]; then
        printf 'administrator=modified\n' > "${case_dir}/expected-config"
        cp "${case_dir}/expected-config" "${case_dir}/root/etc/howy/config.toml"
        chmod 0640 "${case_dir}/root/etc/howy/config.toml"
        expected="${case_dir}/expected-config"
        mode=640
    fi
    transaction "${case_dir}" upgrade-n -U "${CPU_N}"
    assert_success "predecessor-${state} to N"
    assert_config "${case_dir}" "${expected}" "${mode}"
    assert_marker "${case_dir}"
    assert_backup_registered "${case_dir}" howy-cpu-git
    [ ! -e "${case_dir}/root/etc/howy/config.toml.pacnew" ] \
        || fail "predecessor-${state}: unexpected pacnew"
done

# 4. Reinstall N refreshes/restores the administrator's current config.
case_dir=$(new_root reinstall)
transaction "${case_dir}" install-n -U "${CPU_N}"
assert_success reinstall-install
printf 'administrator=reinstall\n' > "${case_dir}/expected-config"
cp "${case_dir}/expected-config" "${case_dir}/root/etc/howy/config.toml"
chmod 0640 "${case_dir}/root/etc/howy/config.toml"
transaction "${case_dir}" reinstall-n -U "${CPU_N}"
assert_success reinstall-n
assert_config "${case_dir}" "${case_dir}/expected-config" 640
assert_marker "${case_dir}"

# 5. Conflict-driven CPU→ROCm→CUDA removal/install transactions use the exact
# installed release-N hook and restore the exact variant-independent config.
case_dir=$(new_root variants)
transaction "${case_dir}" cpu -U "${CPU_N}"
assert_success variants-cpu
printf 'administrator=variant\n' > "${case_dir}/expected-config"
cp "${case_dir}/expected-config" "${case_dir}/root/etc/howy/config.toml"
chmod 0600 "${case_dir}/root/etc/howy/config.toml"
transaction "${case_dir}" rocm --ask=4 -U "${ROCM_N}"
assert_success variants-rocm
[ "$(package_version "${case_dir}" howy-rocm-git)" = 0.1.0-1 ] || fail "ROCm not installed"
assert_config "${case_dir}" "${case_dir}/expected-config" 600
assert_marker "${case_dir}"
transaction "${case_dir}" cuda --ask=4 -U "${CUDA_N}"
assert_success variants-cuda
[ "$(package_version "${case_dir}" howy-cuda-git)" = 0.1.0-1 ] || fail "CUDA not installed"
assert_config "${case_dir}" "${case_dir}/expected-config" 600
assert_marker "${case_dir}"

# 6. Unknown orphan controls force AbortOnFail for both Upgrade and Remove.
case_dir=$(new_root hook-abort)
transaction "${case_dir}" install-n -U "${CPU_N}"
assert_success hook-abort-install
printf 'administrator=abort\n' > "${case_dir}/expected-config"
cp "${case_dir}/expected-config" "${case_dir}/root/etc/howy/config.toml"
chmod 0600 "${case_dir}/root/etc/howy/config.toml"
printf 'orphan\n' > "${case_dir}/root/var/lib/howy/config-bridge/.howy-control-v2-orphan"
transaction "${case_dir}" abort-upgrade -U "${CPU_N1}"
assert_failure abort-upgrade
[ "$(package_version "${case_dir}" howy-cpu-git)" = 0.1.0-1 ] \
    || fail "aborted Upgrade changed package DB"
assert_config "${case_dir}" "${case_dir}/expected-config" 600
transaction "${case_dir}" abort-remove -R howy-cpu-git
assert_failure abort-remove
[ "$(package_version "${case_dir}" howy-cpu-git)" = 0.1.0-1 ] \
    || fail "aborted Remove changed package DB"
assert_config "${case_dir}" "${case_dir}/expected-config" 600

# 7. Modified removal creates .pacsave after the hook captured exact bytes;
# absent config remains absent and produces no pacsave.
case_dir=$(new_root pacsave)
transaction "${case_dir}" install-n -U "${CPU_N}"
assert_success pacsave-install
printf 'administrator=pacsave\n' > "${case_dir}/expected-config"
cp "${case_dir}/expected-config" "${case_dir}/root/etc/howy/config.toml"
chmod 0600 "${case_dir}/root/etc/howy/config.toml"
transaction "${case_dir}" remove-n -R howy-cpu-git
assert_success pacsave-remove
cmp -s "${case_dir}/expected-config" "${case_dir}/root/etc/howy/config.toml.pacsave" \
    || fail "modified removal lost pacsave bytes"
[ ! -e "${case_dir}/root/var/lib/howy-package-bootstrap.complete" ] \
    || fail "removal retained bootstrap marker"

case_dir=$(new_root absent-remove)
transaction "${case_dir}" install-n -U "${CPU_N}"
assert_success absent-remove-install
rm -f "${case_dir}/root/etc/howy/config.toml"
transaction "${case_dir}" remove-n -R howy-cpu-git
assert_success absent-remove
[ ! -e "${case_dir}/root/etc/howy/config.toml" ] || fail "absent config reappeared"
[ ! -e "${case_dir}/root/etc/howy/config.toml.pacsave" ] || fail "absent config made pacsave"

# 8. Kill the actual bridge at the second linkat (journal durable; stash publish
# not yet complete), recover it in the chroot, then qualify a real reinstall.
case_dir=$(new_root interrupted)
transaction "${case_dir}" install-n -U "${CPU_N}"
assert_success interrupted-install
printf 'administrator=interrupted\n' > "${case_dir}/expected-config"
cp "${case_dir}/expected-config" "${case_dir}/root/etc/howy/config.toml"
chmod 0600 "${case_dir}/root/etc/howy/config.toml"
set +e
"${UNSHARE}" --user --map-root-user --mount -- \
    "${CHROOT}" "${case_dir}/root" \
    /usr/bin/strace -qq -e inject=linkat:signal=SIGKILL:when=2 \
    /usr/lib/howy/howy-config-bridge stash-release-n \
    > "${case_dir}/interrupted-bridge.log" 2>&1
interrupted_status=$?
set -e
[ "${interrupted_status}" -ne 0 ] || fail "bridge interruption injection did not fire"
[ -f "${case_dir}/root/var/lib/howy/config-bridge/journal-v2.json" ] \
    || fail "interrupted bridge did not leave its durable journal"
"${UNSHARE}" --user --map-root-user --mount -- \
    "${CHROOT}" "${case_dir}/root" /usr/lib/howy/howy-config-bridge recover >/dev/null
[ ! -e "${case_dir}/root/var/lib/howy/config-bridge/journal-v2.json" ] \
    || fail "actual bridge recovery retained journal"
transaction "${case_dir}" reinstall-after-recovery -U "${CPU_N}"
assert_success interrupted-reinstall
assert_config "${case_dir}" "${case_dir}/expected-config" 600
assert_marker "${case_dir}"

# 9. N→N+1 restores modified, unmodified-packaged, and absent generations.
for state in modified unmodified absent; do
    case_dir=$(new_root "nplus1-${state}")
    transaction "${case_dir}" install-n -U "${CPU_N}"
    assert_success "nplus1-${state} install"
    expected=""
    mode=644
    case "${state}" in
        modified)
            printf 'administrator=nplus1\n' > "${case_dir}/expected-config"
            cp "${case_dir}/expected-config" "${case_dir}/root/etc/howy/config.toml"
            chmod 0640 "${case_dir}/root/etc/howy/config.toml"
            expected="${case_dir}/expected-config"
            mode=640
            ;;
        unmodified)
            cp packaging/config-release-n-legacy.toml "${case_dir}/root/etc/howy/config.toml"
            chmod 0644 "${case_dir}/root/etc/howy/config.toml"
            expected=packaging/config-release-n-legacy.toml
            ;;
        absent)
            rm -f "${case_dir}/root/etc/howy/config.toml"
            ;;
    esac
    transaction "${case_dir}" upgrade-nplus1 -U "${CPU_N1}"
    assert_success "N to N+1 ${state}"
    [ "$(package_version "${case_dir}" howy-cpu-git)" = 0.2.0-1 ] \
        || fail "N+1 package DB version missing for ${state}"
    if [ "${state}" = absent ]; then
        [ ! -e "${case_dir}/root/etc/howy/config.toml" ] \
            || fail "N+1 absent generation was not restored"
    else
        assert_config "${case_dir}" "${expected}" "${mode}"
    fi
    assert_marker "${case_dir}"
done

# 10. N-1→N+1 has no release-N hook/manifest. The simulated N+1 scriptlet
# explicitly refuses assurance and cannot consume a nonexistent generation.
case_dir=$(new_root skipped-n)
transaction "${case_dir}" predecessor -U "${CPU_OLD}"
assert_success skipped-predecessor
printf 'administrator=skipped\n' > "${case_dir}/expected-config"
cp "${case_dir}/expected-config" "${case_dir}/root/etc/howy/config.toml"
chmod 0640 "${case_dir}/root/etc/howy/config.toml"
transaction "${case_dir}" skipped-upgrade -U "${CPU_N1}"
[ "$(package_version "${case_dir}" howy-cpu-git)" = 0.2.0-1 ] \
    || fail "skipped-N simulated package was not extracted"
grep -q 'explicitly refuses skipped-N assurance' "${case_dir}/skipped-upgrade.log" \
    || fail "skipped-N refusal was not explicit"
[ ! -e "${case_dir}/root/var/lib/howy/config-bridge/manifest-v2.json" ] \
    || fail "skipped-N consumed/created a nonexistent release-N manifest"
[ ! -e "${case_dir}/root/var/lib/howy-package-bootstrap.complete" ] \
    || fail "skipped-N incorrectly created bootstrap marker"
assert_config "${case_dir}" "${case_dir}/expected-config" 640

printf 'real isolated ALPM matrix: 10 scenario groups passed; snapshots=%s\n' \
    "$(find "${WORK}" -path '*/snapshots/*.state' -type f | wc -l)"
