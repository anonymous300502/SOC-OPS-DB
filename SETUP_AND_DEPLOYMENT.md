# Cybersecurity Intelligence Dashboard - Setup & Deployment Guide

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- Node.js 16+ (for React frontend)
- PostgreSQL 12+ (for production) or SQLite (for development)
- Docker & Docker Compose (optional, for containerized deployment)

---

## 📋 Backend Setup (FastAPI)

### 1. Create Virtual Environment

```bash
# Create Python virtual environment
python -m venv venv

# Activate (Linux/Mac)
source venv/bin/activate

# Activate (Windows)
venv\Scripts\activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Database Configuration

#### For SQLite (Development)

```python
# In your main.py or initialization script:
from database_models import init_db

db_url = "sqlite:///cybersec_dashboard.db"
engine = init_db(db_url)
```

#### For PostgreSQL (Production)

```python
# Set environment variable:
export DATABASE_URL="postgresql://user:password@localhost:5432/cybersec_dashboard"

# Or in .env file:
# DATABASE_URL=postgresql://user:password@localhost:5432/cybersec_dashboard

from database_models import init_db
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

db_url = os.getenv("DATABASE_URL")
engine = init_db(db_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
```

### 4. Environment Configuration

Create `.env` file in backend directory:

```env
# Security
SECRET_KEY=your-super-secret-key-change-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=480

# Database
DATABASE_URL=sqlite:///cybersec_dashboard.db
# Or for PostgreSQL:
# DATABASE_URL=postgresql://user:password@localhost:5432/cybersec_dashboard

# CORS
ALLOWED_ORIGINS=http://localhost:3000,http://localhost,https://yourdomain.com

# Server
API_PORT=8000
API_HOST=0.0.0.0
```

### 5. Initialize Database with Sample Data

Create `init_db.py`:

```python
from database_models import (
    init_db, Framework, FrameworkVector, SourceType, Brand, SourceModel,
    User, RoleEnum
)
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import bcrypt

# Initialize database
engine = init_db("sqlite:///cybersec_dashboard.db")
Session = sessionmaker(bind=engine)
db = Session()

# Create frameworks
mitre = Framework(name="mitre", description="MITRE ATT&CK Framework")
nist = Framework(name="nist", description="NIST Cybersecurity Framework")
db.add_all([mitre, nist])
db.flush()

# Create MITRE tactics (sample)
tactics = [
    FrameworkVector(
        framework_id=mitre.id,
        external_id="TA0001",
        name="Initial Access",
        description="Tactics used to gain initial access to a system"
    ),
    FrameworkVector(
        framework_id=mitre.id,
        external_id="TA0002",
        name="Execution",
        description="Tactics for executing code"
    ),
    FrameworkVector(
        framework_id=mitre.id,
        external_id="TA0003",
        name="Persistence",
        description="Maintaining access to systems"
    ),
]
db.add_all(tactics)
db.flush()

# Create NIST functions (sample)
functions = [
    FrameworkVector(
        framework_id=nist.id,
        external_id="ID.AM",
        name="Asset Management",
        description="Manage IT and data assets"
    ),
    FrameworkVector(
        framework_id=nist.id,
        external_id="PR.AC",
        name="Access Control",
        description="Access and authorization controls"
    ),
]
db.add_all(functions)
db.flush()

# Create source types
server = SourceType(name="Server", description="Server systems")
firewall = SourceType(name="Firewall", description="Firewall appliances")
endpoint = SourceType(name="Endpoint", description="Endpoint devices")
db.add_all([server, firewall, endpoint])
db.flush()

# Create brands
microsoft = Brand(name="Microsoft", description="Microsoft Corporation")
paloalto = Brand(name="Palo Alto", description="Palo Alto Networks")
crowdstrike = Brand(name="CrowdStrike", description="CrowdStrike")
cisco = Brand(name="Cisco", description="Cisco Systems")
db.add_all([microsoft, paloalto, crowdstrike, cisco])
db.flush()

# Create source models (CORE IDENTITY)
models = [
    SourceModel(
        source_type_id=server.id,
        brand_id=microsoft.id,
        name="Windows Server 2022",
        description="Microsoft Windows Server 2022"
    ),
    SourceModel(
        source_type_id=firewall.id,
        brand_id=paloalto.id,
        name="PA-5220",
        description="Palo Alto Networks PA-5220 Firewall"
    ),
    SourceModel(
        source_type_id=endpoint.id,
        brand_id=crowdstrike.id,
        name="Falcon",
        description="CrowdStrike Falcon Endpoint Protection"
    ),
    SourceModel(
        source_type_id=firewall.id,
        brand_id=cisco.id,
        name="ASA 5520",
        description="Cisco ASA 5520 Firewall"
    ),
]
db.add_all(models)
db.flush()

# Map models to framework vectors (sample)
from database_models import ModelFrameworkMap
for model in models:
    # Map each model to multiple tactics/functions
    for tactic in tactics[:2]:  # Map to first 2 tactics
        mapping = ModelFrameworkMap(
            source_model_id=model.id,
            framework_vector_id=tactic.id
        )
        db.add(mapping)

db.commit()

# Create demo users
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

users = [
    User(
        username="analyst",
        email="analyst@example.com",
        password_hash=hash_password("demo"),
        role=RoleEnum.ANALYST
    ),
    User(
        username="admin",
        email="admin@example.com",
        password_hash=hash_password("demo"),
        role=RoleEnum.ADMIN
    ),
    User(
        username="superadmin",
        email="superadmin@example.com",
        password_hash=hash_password("demo"),
        role=RoleEnum.SUPER_ADMIN
    ),
]
db.add_all(users)
db.commit()

print("✅ Database initialized successfully!")
print("\nDemo Users:")
print("  analyst / demo (read-only access)")
print("  admin / demo (manage artifacts)")
print("  superadmin / demo (full control)")
```

Run initialization:

```bash
python init_db.py
```

### 6. Run Backend Server

```bash
# Using uvicorn directly
uvicorn fastapi_backend:app --reload --host 0.0.0.0 --port 8000

# Or with environment file
python -m uvicorn fastapi_backend:app --reload
```

Backend will be available at: `http://localhost:8000`
API docs at: `http://localhost:8000/docs`

---

## 🎨 Frontend Setup (React)

### 1. Create React App

```bash
# Option A: Using create-react-app
npx create-react-app cybersec-dashboard
cd cybersec-dashboard

# Option B: Using Vite (faster)
npm create vite@latest cybersec-dashboard -- --template react
cd cybersec-dashboard
npm install
```

### 2. Install Dependencies

```bash
npm install lucide-react axios
```

### 3. Configure Environment

Create `.env` file in frontend directory:

```env
REACT_APP_API_URL=http://localhost:8000
REACT_APP_ENV=development
```

### 4. Replace App.jsx

Replace the default `src/App.jsx` with the provided `react_frontend.jsx`

### 5. Configure Tailwind CSS (Optional but Recommended)

```bash
npm install -D tailwindcss postcss autoprefixer
npx tailwindcss init -p
```

Update `tailwind.config.js`:

```javascript
module.exports = {
  content: [
    "./index.html",
    "./src/**/*.{js,jsx}",
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}
```

Add to `src/index.css`:

```css
@tailwind base;
@tailwind components;
@tailwind utilities;
```

### 6. Run Development Server

```bash
npm start
# or with Vite:
npm run dev
```

Frontend will be available at: `http://localhost:3000`

---

## 🐳 Docker Deployment

### Backend Dockerfile

Create `Dockerfile` in backend directory:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "fastapi_backend:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Frontend Dockerfile

Create `Dockerfile` in frontend directory:

```dockerfile
FROM node:18-alpine as builder

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
```

### Docker Compose

Create `docker-compose.yml` in root directory:

```yaml
version: '3.8'

services:
  # PostgreSQL Database
  postgres:
    image: postgres:15-alpine
    container_name: cybersec-db
    environment:
      POSTGRES_USER: cybersec
      POSTGRES_PASSWORD: secure_password_change_me
      POSTGRES_DB: cybersec_dashboard
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U cybersec"]
      interval: 10s
      timeout: 5s
      retries: 5

  # FastAPI Backend
  backend:
    build:
      context: ./backend
    container_name: cybersec-api
    environment:
      DATABASE_URL: postgresql://cybersec:secure_password_change_me@postgres:5432/cybersec_dashboard
      SECRET_KEY: ${SECRET_KEY:-your-secret-key-here}
      ALGORITHM: HS256
      ACCESS_TOKEN_EXPIRE_MINUTES: 480
    ports:
      - "8000:8000"
    depends_on:
      postgres:
        condition: service_healthy
    volumes:
      - ./backend:/app

  # React Frontend
  frontend:
    build:
      context: ./frontend
    container_name: cybersec-ui
    environment:
      REACT_APP_API_URL: http://localhost:8000
    ports:
      - "3000:80"
    depends_on:
      - backend

volumes:
  postgres_data:
```

### Deploy with Docker Compose

```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

---

## 📊 Database Schema Overview

### Core Identity
```
source_models (id, source_type_id, brand_id, name)
  ↓
  UNIQUE(source_type_id, brand_id, name)
```

### Framework Mapping
```
frameworks
  ├─ framework_vectors
  │   └─ model_framework_map → source_models
```

### Detection Engineering
```
source_models
  ├─ parsers
  ├─ soar_flows
  └─ model_correlation_map ↔ correlation_rules
```

### Access Control
```
users (role: analyst, admin, super_admin)
  ↓ JWT token validation
  ↓ RBAC enforcement on each endpoint
```

---

## 🔐 Security Checklist

- [ ] Change `SECRET_KEY` in production
- [ ] Use strong, unique database password
- [ ] Enable HTTPS (use reverse proxy like nginx)
- [ ] Set secure CORS origins (not `*`)
- [ ] Enable password hashing (bcrypt/argon2)
- [ ] Implement rate limiting on auth endpoints
- [ ] Use environment variables for sensitive data
- [ ] Enable database encryption at rest
- [ ] Set up regular database backups
- [ ] Implement API request logging
- [ ] Use strong JWT expiration times
- [ ] Enable SQL injection prevention (SQLAlchemy ORM)

---

## 📈 Performance Optimization

### Database Indexes

The schema includes critical indexes on:
- `users.username`
- `frameworks.name`
- `framework_vectors.framework_id`
- `source_models.source_type_id, brand_id`
- `model_framework_map.source_model_id, framework_vector_id`
- `parser.source_model_id`
- `model_correlation_map.source_model_id, correlation_rule_id`

### Query Optimization Tips

1. Use `.select()` with specific columns instead of loading all
2. Implement pagination for large result sets
3. Cache framework vectors (rarely change)
4. Use connection pooling (SQLAlchemy default)
5. Monitor slow queries with database logs

### Frontend Optimization

- Code splitting with React.lazy()
- Memoization for components with expensive re-renders
- Implement client-side pagination/filtering
- Use IndexedDB for large datasets
- Lazy load tabs/sections

---

## 🧪 Testing

### Backend Tests

Create `test_api.py`:

```python
import pytest
from fastapi.testclient import TestClient
from fastapi_backend import app

client = TestClient(app)

def test_login():
    response = client.post("/auth/login", json={
        "username": "analyst",
        "password": "demo"
    })
    assert response.status_code == 200
    assert "access_token" in response.json()

def test_get_frameworks():
    # Get token first
    login_response = client.post("/auth/login", json={
        "username": "analyst",
        "password": "demo"
    })
    token = login_response.json()["access_token"]
    
    # Get frameworks
    response = client.get(
        "/frameworks",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert len(response.json()) > 0

def test_unauthorized_parser_creation():
    """Analyst shouldn't be able to create parsers"""
    login_response = client.post("/auth/login", json={
        "username": "analyst",
        "password": "demo"
    })
    token = login_response.json()["access_token"]
    
    response = client.post(
        "/parsers?model_id=1",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "test",
            "format": "json",
            "parser_config": {}
        }
    )
    assert response.status_code == 403
```

Run tests:

```bash
pytest test_api.py -v
```

---

## 📝 API Documentation

After starting the backend, full interactive API docs available at:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

---

## 🚨 Troubleshooting

### Backend Issues

**ModuleNotFoundError: No module named 'fastapi'**
```bash
pip install -r requirements.txt
```

**Database connection error**
```bash
# Check database URL
echo $DATABASE_URL

# Test PostgreSQL connection
psql postgresql://user:password@localhost:5432/cybersec_dashboard
```

**CORS errors in frontend**
Update `ALLOWED_ORIGINS` in backend `.env`

### Frontend Issues

**API_URL not working**
- Check `.env` file has `REACT_APP_API_URL`
- Restart dev server after changing env
- Verify backend is running on correct port

**Port 3000 already in use**
```bash
# Kill process on port 3000 (Linux/Mac)
lsof -ti:3000 | xargs kill -9

# Or use different port
PORT=3001 npm start
```

---

## 🔄 Data Ingestion

### MITRE ATT&CK

```python
import requests
import json

# Download MITRE ATT&CK framework
response = requests.get(
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack.json"
)

attack_data = response.json()

# Extract tactics
for obj in attack_data['objects']:
    if obj['type'] == 'x-mitre-tactic':
        # Insert into framework_vectors table
        pass
```

### NIST Cybersecurity Framework

```python
# NIST functions mapping (manual)
nist_functions = {
    "ID.AM": "Asset Management",
    "ID.BE": "Business Environment",
    "ID.GV": "Governance",
    # ... add all 23 NIST functions
}
```

---

## 📞 Support & Maintenance

### Regular Maintenance Tasks

- **Daily**: Monitor logs for errors
- **Weekly**: Check database disk usage
- **Monthly**: Review access logs, update dependencies
- **Quarterly**: Full backup verification, security audit
- **Annually**: Infrastructure review, capacity planning

### Monitoring & Alerting

Recommend integrating with:
- Prometheus + Grafana (metrics)
- ELK Stack (logging)
- Sentry (error tracking)
- PagerDuty (alerting)

---

## 📚 Additional Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [SQLAlchemy ORM](https://docs.sqlalchemy.org/)
- [React Documentation](https://react.dev/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)

---

**Last Updated**: 2024
**Version**: 1.0.0
