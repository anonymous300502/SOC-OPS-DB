#!/bin/bash
#
# Cybersecurity Intelligence Dashboard - production launcher
# Validates prerequisites and brings up the full stack via Docker Compose.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo "🛡️  Cybersecurity Intelligence Dashboard"
echo "========================================"
echo ""

# --- Prerequisites ---------------------------------------------------------
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker is not installed.${NC} See https://docs.docker.com/get-docker/"
    exit 1
fi
if ! docker compose version &> /dev/null; then
    echo -e "${RED}❌ Docker Compose v2 is not available.${NC} Install/upgrade Docker."
    exit 1
fi
echo -e "${GREEN}✓ Docker and Docker Compose present${NC}"

# --- Configuration ---------------------------------------------------------
if [ ! -f .env ]; then
    echo -e "${RED}❌ No .env file found.${NC}"
    echo "   Copy the template and fill in real secrets:"
    echo -e "   ${YELLOW}cp .env.example .env${NC}  then edit .env"
    exit 1
fi

# Warn if any required secret is unset or still a placeholder.
required=(POSTGRES_PASSWORD SECRET_KEY SUPER_ADMIN_USERNAME SUPER_ADMIN_PASSWORD SUPER_ADMIN_EMAIL)
missing=0
set -a; . ./.env; set +a
for var in "${required[@]}"; do
    val="${!var:-}"
    if [ -z "$val" ] || [[ "$val" == change_me* ]]; then
        echo -e "${RED}❌ $var is not set (or still a placeholder) in .env${NC}"
        missing=1
    fi
done
[ "$missing" -eq 0 ] || { echo "Fix the values above and re-run."; exit 1; }
echo -e "${GREEN}✓ Required secrets present${NC}"

# --- Launch ----------------------------------------------------------------
echo ""
echo "🚀 Building and starting services (first run may take a few minutes)..."
docker compose up -d --build

echo ""
echo "⏳ Waiting for the API to become healthy..."
for _ in $(seq 1 60); do
    if curl -fs http://localhost:8000/health > /dev/null 2>&1; then
        echo -e "${GREEN}✓ API is ready${NC}"
        break
    fi
    echo -n "."
    sleep 2
done

echo ""
echo "========================================"
echo -e "${GREEN}✅ Application is up${NC}"
echo "========================================"
echo -e "${BLUE}Frontend:${NC} http://localhost"
echo -e "${BLUE}API docs:${NC} http://localhost:8000/docs"
echo ""
echo "Log in with the super-admin credentials from your .env (SUPER_ADMIN_*),"
echo "then create admin/analyst users from the Users screen."
echo ""
echo "Logs:  docker compose logs -f"
echo "Stop:  docker compose down        (data is preserved)"
