#!/usr/bin/env bash
# ============================================================================
# deploy-airgap.sh
# Run INSIDE the extracted bundle directory on the air-gapped host.
# Loads the bundled images (offline) and starts the full stack. No internet.
#
# Usage:   sudo ./deploy-airgap.sh
# ============================================================================
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

red()   { printf '\033[0;31m%s\033[0m\n' "$1"; }
green() { printf '\033[0;32m%s\033[0m\n' "$1"; }

# --- 1. Prerequisites -------------------------------------------------------
command -v docker >/dev/null 2>&1 || { red "Docker Engine is not installed on this host."; exit 1; }
docker compose version >/dev/null 2>&1 || { red "Docker Compose v2 plugin is missing."; exit 1; }

# --- 2. Secrets -------------------------------------------------------------
if [ ! -f .env ]; then
  cp .env.example .env
  red "No .env found — created one from the template."
  red "Edit .env and set every secret, then re-run: sudo ./deploy-airgap.sh"
  exit 1
fi
if grep -qE '=(change_me|change_me_)' .env; then
  red "Refusing to deploy: .env still contains placeholder 'change_me' values."
  red "Fill in real secrets in .env first."
  exit 1
fi

# --- 3. Load images (offline) ----------------------------------------------
green "==> Loading images from bundle (no network)"
for tar in images/socdb-images-*.tar; do
  echo "    loading ${tar}"
  docker load -i "${tar}"
done

# --- 4. Start the stack -----------------------------------------------------
green "==> Starting stack"
docker compose up -d

echo
green "==> Status"
docker compose ps
echo
green "Frontend:  http://localhost/"
green "API:       http://localhost:8000/   (health: /health)"
echo "Logs:      sudo docker compose logs -f"
