#!/bin/bash

# Cybersecurity Intelligence Dashboard - Production Quick Start
# This script sets up and launches the complete application

set -e

echo "🛡️  Cybersecurity Intelligence Dashboard - Production Setup"
echo "=========================================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check prerequisites
check_requirements() {
    echo "📋 Checking prerequisites..."
    
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}❌ Docker is not installed${NC}"
        echo "   Install from: https://www.docker.com/products/docker-desktop"
        exit 1
    fi
    echo -e "${GREEN}✓ Docker${NC}"
    
    if ! command -v docker compose &> /dev/null; then
        echo -e "${RED}❌ Docker Compose is not installed${NC}"
        echo "   Install from: https://docs.docker.com/compose/install"
        exit 1
    fi
    echo -e "${GREEN}✓ Docker Compose${NC}"
    
    echo ""
}

# Create necessary directories
setup_directories() {
    echo "📁 Setting up directories..."
    mkdir -p backend frontend
    echo -e "${GREEN}✓ Directories created${NC}"
    echo ""
}

# Check if files exist
check_files() {
    echo "📂 Checking application files..."
    
    files=(
        "docker-compose.yml"
        "backend.Dockerfile"
        "frontend.Dockerfile"
        "nginx.conf"
        "requirements.txt"
        "database_models.py"
        "fastapi_backend.py"
        "react_frontend.jsx"
        "init_prod_db.py"
    )
    
    missing=0
    for file in "${files[@]}"; do
        if [ ! -f "$file" ]; then
            echo -e "${RED}❌ Missing: $file${NC}"
            missing=$((missing + 1))
        fi
    done
    
    if [ $missing -gt 0 ]; then
        echo -e "${RED}Error: $missing required files are missing${NC}"
        echo "Please ensure all files are in the project directory"
        exit 1
    fi
    
    echo -e "${GREEN}✓ All files present${NC}"
    echo ""
}

# Organize files
organize_files() {
    echo "📦 Organizing files..."
    
    # Backend files
    cp -v database_models.py backend/ 2>/dev/null || true
    cp -v fastapi_backend.py backend/ 2>/dev/null || true
    cp -v init_prod_db.py backend/ 2>/dev/null || true
    cp -v requirements.txt backend/ 2>/dev/null || true
    cp -v backend.Dockerfile backend/Dockerfile 2>/dev/null || true
    
    # Frontend files
    cp -v react_frontend.jsx frontend/App.jsx 2>/dev/null || true
    cp -v package.json frontend/ 2>/dev/null || true
    cp -v frontend.Dockerfile frontend/Dockerfile 2>/dev/null || true
    cp -v nginx.conf frontend/ 2>/dev/null || true
    
    echo -e "${GREEN}✓ Files organized${NC}"
    echo ""
}

# Build and start containers
start_services() {
    echo "🚀 Building and starting services..."
    echo "   (This may take 2-5 minutes on first run)"
    echo ""
    
    docker compose down 2>/dev/null || true
    docker compose up -d --build
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Services started${NC}"
    else
        echo -e "${RED}❌ Failed to start services${NC}"
        exit 1
    fi
    echo ""
}

# Wait for services to be ready
wait_for_services() {
    echo "⏳ Waiting for services to be ready..."
    
    max_attempts=60
    attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        if curl -s http://localhost:8000/health > /dev/null 2>&1; then
            echo -e "${GREEN}✓ API is ready${NC}"
            break
        fi
        attempt=$((attempt + 1))
        echo -n "."
        sleep 1
    done
    
    if [ $attempt -eq $max_attempts ]; then
        echo -e "${RED}❌ Timeout waiting for API${NC}"
        echo "   Try: docker-compose logs backend"
        exit 1
    fi
    echo ""
}

# Display access information
display_info() {
    echo ""
    echo "=========================================================="
    echo -e "${GREEN}✅ APPLICATION IS READY!${NC}"
    echo "=========================================================="
    echo ""
    echo -e "${BLUE}📊 Access the application:${NC}"
    echo ""
    echo -e "  ${GREEN}Frontend:${NC}        http://localhost"
    echo -e "  ${GREEN}API Docs:${NC}        http://localhost:8000/docs"
    echo -e "  ${GREEN}Database:${NC}        http://localhost:5050 (pgAdmin)"
    echo ""
    echo -e "${BLUE}🔐 Demo Credentials:${NC}"
    echo ""
    echo -e "  ${GREEN}Analyst (read-only):${NC}"
    echo "    Username: analyst"
    echo "    Password: demo"
    echo ""
    echo -e "  ${GREEN}Admin (manage artifacts):${NC}"
    echo "    Username: admin"
    echo "    Password: demo"
    echo ""
    echo -e "  ${GREEN}Super Admin (full control):${NC}"
    echo "    Username: superadmin"
    echo "    Password: demo"
    echo ""
    echo -e "${BLUE}📚 Quick Start:${NC}"
    echo ""
    echo "  1. Open http://localhost in your browser"
    echo "  2. Login with any demo credentials above"
    echo "  3. Select a framework (MITRE or NIST)"
    echo "  4. Explore security sources and mappings"
    echo "  5. View correlation rules and detection artifacts"
    echo ""
    echo -e "${BLUE}🛠️  Useful Commands:${NC}"
    echo ""
    echo "  View logs:        docker-compose logs -f"
    echo "  Stop services:    docker-compose down"
    echo "  Restart:          docker-compose restart"
    echo "  Database shell:   docker-compose exec postgres psql -U cybersec -d cybersec_dashboard"
    echo "  API shell:        docker-compose exec backend bash"
    echo ""
    echo "=========================================================="
    echo ""
}

# Main execution
main() {
    check_requirements
    check_files
    setup_directories
    organize_files
    start_services
    wait_for_services
    display_info
}

main
