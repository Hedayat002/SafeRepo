#!/usr/bin/env bash
# ==============================================================================
# SafeRepo Phase 09 — Scanner Image Pre-Caching Script (Linux/POSIX)
#
# Preloads and verifies the pinned container images required by SafeRepo's
# multi-scanner analysis pipeline:
#   1. semgrep/semgrep:1.100.0 (SAST)
#   2. aquasec/trivy:0.59.1    (SCA / Vulnerabilities)
#   3. zricethezav/gitleaks:v8.24.0 (Secret Detection)
#
# Safety Invariants:
# - Read-only metadata inspection (NO scanner containers executed)
# - Exact pinned semantic version tags ONLY (no :latest, :edge, etc.)
# - Zero host filesystem or socket mounts
# - Zero repository scans or code execution
# ==============================================================================

set -euo pipefail

# Pinned scanner image registry references
SCANNER_IMAGES=(
  "semgrep/semgrep:1.100.0"
  "aquasec/trivy:0.59.1"
  "zricethezav/gitleaks:v8.24.0"
)

echo "================================================================"
echo " SafeRepo Phase 09 Scanner Image Pre-Caching"
echo "================================================================"

# 1. Verify Docker CLI availability
if ! command -v docker >/dev/null 2>&1; then
  echo "[FAIL] Docker CLI is not installed or not in PATH." >&2
  exit 1
fi
echo "[OK] Docker CLI detected: $(docker --version)"

# 2. Verify Docker daemon responsiveness
if ! docker info >/dev/null 2>&1; then
  echo "[FAIL] Docker daemon is not running or unreachable." >&2
  exit 1
fi
echo "[OK] Docker daemon is reachable."
echo ""

TOTAL_IMAGES=${#SCANNER_IMAGES[@]}
PASSED_COUNT=0
FAILED_COUNT=0

for IMAGE in "${SCANNER_IMAGES[@]}"; do
  echo "────────────────────────────────────────────────────────────────"
  echo "Target Scanner: ${IMAGE}"

  # Check if image already cached locally
  if docker image inspect "${IMAGE}" >/dev/null 2>&1; then
    echo "  [INFO] Image already present in local Docker cache."
  else
    echo "  [PULL] Image not found locally. Pulling exact pinned tag..."
    if ! docker pull "${IMAGE}"; then
      echo "  [FAIL] Failed to pull ${IMAGE}" >&2
      FAILED_COUNT=$((FAILED_COUNT + 1))
      continue
    fi
  fi

  # Read-only metadata inspection (safe dry-run without container execution)
  INSPECT_OUTPUT=$(docker image inspect "${IMAGE}" --format '{{.Id}}|{{.Architecture}}|{{.Os}}|{{.Size}}' 2>/dev/null || true)

  if [ -z "${INSPECT_OUTPUT}" ]; then
    echo "  [FAIL] Metadata inspection failed for ${IMAGE}" >&2
    FAILED_COUNT=$((FAILED_COUNT + 1))
    continue
  fi

  # Parse inspection fields
  IMAGE_ID=$(echo "${INSPECT_OUTPUT}" | cut -d'|' -f1)
  IMAGE_ARCH=$(echo "${INSPECT_OUTPUT}" | cut -d'|' -f2)
  IMAGE_OS=$(echo "${INSPECT_OUTPUT}" | cut -d'|' -f3)
  IMAGE_SIZE=$(echo "${INSPECT_OUTPUT}" | cut -d'|' -f4)
  IMAGE_SIZE_MB=$((IMAGE_SIZE / 1024 / 1024))

  # Verify image tag matching
  TAG_MATCH=$(docker image inspect "${IMAGE}" --format '{{range .RepoTags}}{{println .}}{{end}}' | grep -F "${IMAGE}" || true)

  if [ -z "${TAG_MATCH}" ]; then
    echo "  [FAIL] RepoTags metadata does not contain exact reference: ${IMAGE}" >&2
    FAILED_COUNT=$((FAILED_COUNT + 1))
    continue
  fi

  echo "  [PASS] Verified: ${IMAGE}"
  echo "         Digest:       ${IMAGE_ID}"
  echo "         Architecture: ${IMAGE_OS}/${IMAGE_ARCH}"
  echo "         Size:         ${IMAGE_SIZE_MB} MB"
  PASSED_COUNT=$((PASSED_COUNT + 1))
done

echo ""
echo "================================================================"
echo " SUMMARY: ${PASSED_COUNT}/${TOTAL_IMAGES} PASSED | ${FAILED_COUNT} FAILED"
echo "================================================================"

if [ "${FAILED_COUNT}" -gt 0 ]; then
  echo "[FAIL] One or more scanner images failed validation." >&2
  exit 1
fi

echo "[SUCCESS] All scanner images preloaded and verified successfully."
exit 0
