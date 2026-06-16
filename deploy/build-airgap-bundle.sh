#!/usr/bin/env bash
# ============================================================================
# build-airgap-bundle.sh
# Run on a machine WITH internet + Docker. Produces a single self-contained
# tar.gz you copy to any air-gapped host and deploy with deploy-airgap.sh —
# no internet, no registry, no build needed on the target.
#
# Usage:   sudo ./deploy/build-airgap-bundle.sh
#          sudo APP_VERSION=1.1 ./deploy/build-airgap-bundle.sh   # bump version
# ============================================================================
set -euo pipefail

VERSION="${APP_VERSION:-1.0}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="${REPO_ROOT}/deploy"
WORK="$(mktemp -d)"
BUNDLE_NAME="socdb-airgap-${VERSION}"
STAGE="${WORK}/${BUNDLE_NAME}"
OUT="${REPO_ROOT}/${BUNDLE_NAME}.tar.gz"

POSTGRES_IMAGE="postgres:15-alpine"
BACKEND_IMAGE="soc-ops-db/backend:${VERSION}"
FRONTEND_IMAGE="soc-ops-db/frontend:${VERSION}"

cleanup() { rm -rf "${WORK}"; }
trap cleanup EXIT

echo "==> [1/5] Building application images (v${VERSION})"
cd "${REPO_ROOT}"
APP_VERSION="${VERSION}" docker compose build

echo "==> [2/5] Pulling base runtime image: ${POSTGRES_IMAGE}"
docker pull "${POSTGRES_IMAGE}"

echo "==> [3/5] Saving images to a single archive"
mkdir -p "${STAGE}/images"
docker save "${POSTGRES_IMAGE}" "${BACKEND_IMAGE}" "${FRONTEND_IMAGE}" \
  > "${STAGE}/images/socdb-images-${VERSION}.tar"

echo "==> [4/5] Assembling bundle"
cp "${DEPLOY_DIR}/docker-compose.airgap.yml" "${STAGE}/docker-compose.yml"
cp "${DEPLOY_DIR}/deploy-airgap.sh"          "${STAGE}/deploy-airgap.sh"
cp "${REPO_ROOT}/.env.example"               "${STAGE}/.env.example"
chmod +x "${STAGE}/deploy-airgap.sh"
# Carry the version so compose interpolation resolves the right image tags.
grep -q '^APP_VERSION=' "${STAGE}/.env.example" || \
  printf '\n# Image version (must match the loaded images)\nAPP_VERSION=%s\n' "${VERSION}" >> "${STAGE}/.env.example"
cat > "${STAGE}/README.md" <<EOF
# SOC-OPS-DB — air-gapped bundle v${VERSION}

On the target host (Docker Engine + Compose v2 must already be installed):

    tar -xzf ${BUNDLE_NAME}.tar.gz
    cd ${BUNDLE_NAME}
    cp .env.example .env      # then EDIT .env — set every secret
    sudo ./deploy-airgap.sh

Then open  http://<host>/   (API at  http://<host>:8000 ).
EOF

echo "==> [5/5] Packing -> ${OUT}"
tar -C "${WORK}" -czf "${OUT}" "${BUNDLE_NAME}"

echo
echo "==> Done. Copy this single file to the air-gapped host:"
ls -lh "${OUT}"
sha256sum "${OUT}"
