#!/bin/bash
# Download ONNX models for howy face authentication
# SCRFD (face detection) + ArcFace w600k_r50 (face recognition)
#
# Models are from InsightFace: https://github.com/deepinsight/insightface

set -euo pipefail

MODEL_DIR="${1:-/usr/share/howy/onnx-data}"
BASE_URL="https://github.com/deepinsight/insightface/releases/download/v0.7"
ARCHIVE_URL="${BASE_URL}/buffalo_l.zip"
DET_FILE="${MODEL_DIR}/det_10g.onnx"
REC_FILE="${MODEL_DIR}/w600k_r50.onnx"
TMP_DIR=""

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    if [ -n "${TMP_DIR}" ] && [ -d "${TMP_DIR}" ]; then
        rm -rf "${TMP_DIR}"
    fi
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

download_archive() {
    TMP_DIR=$(mktemp -d)
    local archive_path="${TMP_DIR}/buffalo_l.zip"

    echo "Downloading buffalo_l model pack..."
    curl -fL -o "${archive_path}" "${ARCHIVE_URL}" \
        || die "Failed to download ${ARCHIVE_URL}"

    echo "Extracting required models..."
    unzip -j -o "${archive_path}" "det_10g.onnx" "w600k_r50.onnx" -d "${MODEL_DIR}" >/dev/null \
        || die "Failed to extract required ONNX models from buffalo_l.zip"

    [ -f "${DET_FILE}" ] || die "Missing extracted model: ${DET_FILE}"
    [ -f "${REC_FILE}" ] || die "Missing extracted model: ${REC_FILE}"
}

trap cleanup EXIT

echo "Preparing howy ONNX models in: ${MODEL_DIR}"
require_command curl
require_command unzip
mkdir -p "${MODEL_DIR}" || die "Failed to create model directory: ${MODEL_DIR}"

if [ -f "${DET_FILE}" ] && [ -f "${REC_FILE}" ]; then
    echo "Required models already present."
else
    download_archive
fi

echo ""
echo "Models ready:"
for model in "${DET_FILE}" "${REC_FILE}"; do
    [ -f "${model}" ] || die "Expected model not found: ${model}"
    printf '  %s (%s)\n' "$(basename "${model}")" "$(du -h "${model}" | cut -f1)"
done
echo ""
echo "Done. You can now start the daemon:"
echo "  sudo systemctl enable --now howy.socket"
