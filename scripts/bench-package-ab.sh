#!/bin/bash

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(dirname "${SCRIPT_DIR}")
TARGET_ROOT="${REPO_ROOT}/target/package-ab"
BENCHMARK_ROOT="${TARGET_ROOT}/benchmark"
OPTED_IN=0
DETECTOR_MODEL=
RECOGNIZER_MODEL=
ITERATIONS=
CACHE_POLICY=

usage() {
    cat <<'EOF'
Usage: scripts/bench-package-ab.sh --i-understand-this-runs-inference \
  --detector-model FILE --recognizer-model FILE --iterations N \
  --cache-policy cold|warm

Runs extracted smoke_test binaries on synthetic images only. It never installs
packages or invokes a camera, PAM, systemd, or the Howy daemon server.
EOF
}

fail() {
    printf 'package A/B benchmark: %s\n' "$*" >&2
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

canonical_model() {
    local label="$1"
    local supplied="$2"
    local canonical

    [ -n "${supplied}" ] || fail "missing --${label}-model"
    canonical=$(realpath -e -- "${supplied}") \
        || fail "could not resolve ${label} model: ${supplied}"
    [ -f "${canonical}" ] || fail "${label} model is not a regular file: ${canonical}"
    [ -r "${canonical}" ] || fail "${label} model is not readable: ${canonical}"
    [ -s "${canonical}" ] || fail "${label} model is empty: ${canonical}"
    case "${canonical}" in
        /etc/howy|/etc/howy/*)
            fail "refusing ${label} model beneath /etc/howy: ${canonical}"
            ;;
    esac
    printf '%s\n' "${canonical}"
}

source_commit() {
    case "$1" in
        master) printf '%s\n' a7d187d723185742fb7cb9ef24e8af50d1e3890e ;;
        hardened) printf '%s\n' 0b76fa23ad3883ccfa8edd38210766f97cdbb71a ;;
        *) fail "unknown variant: $1" ;;
    esac
}

reset_cache() {
    local variant_root="$1"
    local cache_root="${variant_root}/cache"

    case "${cache_root}" in
        "${BENCHMARK_ROOT}"/*/master/cache|"${BENCHMARK_ROOT}"/*/hardened/cache) ;;
        *) fail "refusing to clear cache outside the variant benchmark root: ${cache_root}" ;;
    esac
    rm -rf -- "${cache_root}"
    mkdir -p \
        "${cache_root}/home" \
        "${cache_root}/xdg-cache" \
        "${cache_root}/xdg-config" \
        "${cache_root}/xdg-data" \
        "${cache_root}/xdg-state" \
        "${cache_root}/tmp" \
        "${cache_root}/migraphx"
}

run_synthetic() {
    local variant="$1"
    local log="$2"
    local variant_root="${POLICY_ROOT}/${variant}"
    local cache_root="${variant_root}/cache"
    local cwd="${variant_root}/cwd"
    local binary="${variant_root}/extracted/usr/lib/howy-ab/bench/smoke_test"

    (
        cd "${cwd}"
        env -i \
            PATH=/usr/bin:/bin \
            HOME="${cache_root}/home" \
            XDG_CACHE_HOME="${cache_root}/xdg-cache" \
            XDG_CONFIG_HOME="${cache_root}/xdg-config" \
            XDG_DATA_HOME="${cache_root}/xdg-data" \
            XDG_STATE_HOME="${cache_root}/xdg-state" \
            TMPDIR="${cache_root}/tmp" \
            ORT_MIGRAPHX_MODEL_CACHE_PATH="${cache_root}/migraphx" \
            ORT_MIGRAPHX_CACHE_PATH="${cache_root}/migraphx" \
            HOWY_PROVIDER=migraphx \
            RUST_LOG=warn \
            "${binary}"
    ) > "${log}" 2>&1
}

reported_provider() {
    local log="$1"
    local count provider

    count=$(grep -Ec '^[[:space:]]*Provider: migraphx[[:space:]]*$' "${log}" || true)
    [ "${count}" -eq 1 ] || return 1
    [ "$(grep -Ec '^[[:space:]]*Provider:' "${log}" || true)" -eq 1 ] || return 1
    if grep -Eiq \
        'Provider:[[:space:]]*(cpu|mixed)|falling back to CPU|fallback(_to_cpu)?[=:][[:space:]]*true' \
        "${log}"; then
        return 1
    fi
    provider=$(grep -E '^[[:space:]]*Provider:' "${log}")
    provider=${provider#*Provider: }
    provider=${provider//[[:space:]]/}
    [ "${provider}" = migraphx ] || return 1
    printf '%s\n' "${provider}"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --i-understand-this-runs-inference)
            OPTED_IN=1
            shift
            ;;
        --detector-model|--recognizer-model|--iterations|--cache-policy)
            [ "$#" -ge 2 ] || fail "missing value for $1"
            case "$1" in
                --detector-model) DETECTOR_MODEL=$2 ;;
                --recognizer-model) RECOGNIZER_MODEL=$2 ;;
                --iterations) ITERATIONS=$2 ;;
                --cache-policy) CACHE_POLICY=$2 ;;
            esac
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "unknown argument: $1"
            ;;
    esac
done

[ "${OPTED_IN}" -eq 1 ] \
    || fail 'explicit opt-in flag --i-understand-this-runs-inference is required'
[[ "${ITERATIONS}" =~ ^[1-9][0-9]*$ ]] || fail '--iterations must be a positive integer'
case "${CACHE_POLICY}" in
    cold|warm) ;;
    *) fail '--cache-policy must be cold or warm' ;;
esac

for command in bsdtar cut date env grep id ln mkdir realpath sha256sum; do
    require_command "${command}"
done

[ "$(id -u)" -ne 0 ] || fail 'refusing to run as root'

DETECTOR_MODEL=$(canonical_model detector "${DETECTOR_MODEL}")
RECOGNIZER_MODEL=$(canonical_model recognizer "${RECOGNIZER_MODEL}")
DETECTOR_HASH=$(sha256sum "${DETECTOR_MODEL}" | cut -d' ' -f1)
RECOGNIZER_HASH=$(sha256sum "${RECOGNIZER_MODEL}" | cut -d' ' -f1)
POLICY_ROOT="${BENCHMARK_ROOT}/${CACHE_POLICY}"
mkdir -p "${POLICY_ROOT}"

# env -i below is the enforcement boundary. Explicitly drop inherited values in
# this process too, so no helper accidentally observes credential, Howy, ORT,
# or host cache variables while setting up target-local state.
while IFS='=' read -r name _value; do
    case "${name}" in
        CREDENTIALS_DIRECTORY|HOWY_*|ORT_*|MIGRAPHX_*|HIP_*|MIOPEN_*|XDG_*|HOME|TMPDIR)
            unset "${name}"
            ;;
    esac
done < <(env)

for variant in master hardened; do
    variant_root="${POLICY_ROOT}/${variant}"
    extracted="${variant_root}/extracted"
    cwd="${variant_root}/cwd"
    model_dir="${cwd}/dist/howdy_onnx/_internal/onnx-data"
    logs="${variant_root}/logs"
    package=$(package_for_variant "${variant}")

    rm -rf -- "${extracted}" "${cwd}" "${logs}"
    mkdir -p "${extracted}" "${model_dir}" "${logs}"
    bsdtar -xf "${package}" -C "${extracted}"
    [ -x "${extracted}/usr/lib/howy-ab/bench/smoke_test" ] \
        || fail "${variant} package lacks executable smoke_test"
    ln -s -- "${DETECTOR_MODEL}" "${model_dir}/det_10g.onnx"
    ln -s -- "${RECOGNIZER_MODEL}" "${model_dir}/w600k_r50.onnx"
    reset_cache "${variant_root}"
done

RESULTS="${POLICY_ROOT}/results.csv"
printf '%s\n' \
    'variant,iteration,order_position,cache_policy,wall_ms,exit,package_sha256,source_commit,detector_sha256,recognizer_sha256,reported_provider' \
    > "${RESULTS}"

if [ "${CACHE_POLICY}" = warm ]; then
    for variant in master hardened; do
        warmup_log="${POLICY_ROOT}/${variant}/logs/warmup.log"
        if ! run_synthetic "${variant}" "${warmup_log}"; then
            fail "${variant} non-recorded warmup failed; see ${warmup_log}"
        fi
        reported_provider "${warmup_log}" >/dev/null \
            || fail "${variant} warmup did not report exactly Provider: migraphx"
    done
fi

order=(master hardened hardened master)
for ((iteration = 1; iteration <= ITERATIONS; iteration++)); do
    for index in "${!order[@]}"; do
        variant=${order[${index}]}
        position=$((index + 1))
        variant_root="${POLICY_ROOT}/${variant}"
        log="${variant_root}/logs/run-${iteration}-${position}.log"
        package=$(package_for_variant "${variant}")
        package_hash=$(sha256sum "${package}" | cut -d' ' -f1)
        commit=$(source_commit "${variant}")

        if [ "${CACHE_POLICY}" = cold ]; then
            reset_cache "${variant_root}"
        fi

        started=$(date +%s%N)
        set +e
        run_synthetic "${variant}" "${log}"
        exit_status=$?
        set -e
        finished=$(date +%s%N)
        wall_ms=$(((finished - started) / 1000000))
        provider=
        if [ "${exit_status}" -eq 0 ]; then
            provider=$(reported_provider "${log}" || true)
        fi

        printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
            "${variant}" "${iteration}" "${position}" "${CACHE_POLICY}" \
            "${wall_ms}" "${exit_status}" "${package_hash}" "${commit}" \
            "${DETECTOR_HASH}" "${RECOGNIZER_HASH}" "${provider}" >> "${RESULTS}"

        [ "${exit_status}" -eq 0 ] \
            || fail "${variant} run ${iteration}/${position} failed; see ${log}"
        [ "${provider}" = migraphx ] \
            || fail "${variant} run ${iteration}/${position} did not report exactly Provider: migraphx"
    done
done

printf 'package A/B synthetic inference results: %s\n' "${RESULTS}"
