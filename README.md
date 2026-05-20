# 🛡️ Cybersecurity Intelligence Dashboard - Complete Implementation

A **production-ready full-stack application** for organizing and mapping security data across **MITRE ATT&CK and NIST cybersecurity frameworks** with structured storage for detection engineering artifacts.

---

## 📦 What You Get

This is a **complete, working implementation** including:

✅ **Backend** - FastAPI with JWT auth, RBAC, and all API endpoints  
✅ **Frontend** - React with full UI flow and role-based controls  
✅ **Database** - SQLAlchemy models with proper relationships  
✅ **Docker** - Multi-container deployment ready  
✅ **Documentation** - Architecture, setup, and development guides  

---

## 📋 File Guide

### Core Implementation Files

| File | Purpose |
|------|---------|
| **database_models.py** | SQLAlchemy ORM models - complete data model with all relationships |
| **fastapi_backend.py** | FastAPI application - all endpoints, auth, RBAC, role enforcement |
| **react_frontend.jsx** | React components - complete UI with login, framework selection, model discovery, admin controls |

### Configuration & Deployment

| File | Purpose |
|------|---------|
| **docker-compose.yml** | Complete stack: PostgreSQL, FastAPI backend, React frontend, Redis cache, pgAdmin |
| **backend.Dockerfile** | Docker image for FastAPI backend with health checks |
| **frontend.Dockerfile** | Multi-stage build for React frontend served by nginx |
| **nginx.conf** | Nginx configuration with API proxy, security headers, compression |
| **requirements.txt** | Python dependencies for backend |

### Documentation

| File | Purpose |
|------|---------|
| **ARCHITECTURE.md** | Complete system design, data model relationships, query patterns |
| **SETUP_AND_DEPLOYMENT.md** | Step-by-step setup, Docker deployment, database initialization |
| **DEVELOPER_REFERENCE.md** | Quick reference for API endpoints, role permissions, common tasks |

---

## 🚀 Quick Start (5 minutes)

### Option A: Docker Compose (Recommended)

```bash
# Clone/download files and navigate to project directory
cd cybersec-dashboard

# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Access the application
# Frontend: http://localhost
# API Docs: http://localhost/docs (or http://localhost:8000/docs)
# pgAdmin: http://localhost:5050 (admin@example.com / admin)
```

**Demo Credentials:**
```
Username: analyst | Password: demo
Username: admin | Password: demo
Username: superadmin | Password: demo
```

### Option B: Manual Setup (Development)

```bash
# Backend
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python init_db.py
uvicorn fastapi_backend:app --reload

# Frontend (in new terminal)
cd frontend
npm install
npm start
```

Access at `http://localhost:3000`

---

## 🧱 System Architecture (30-second overview)

### The Core Identity
```
(source_type + brand + model) = unique security source
```

Every component revolves around this identity:
- **Windows Server 2022** (source_type=Server, brand=Microsoft, name=Windows Server 2022)
- **PA-5220** (source_type=Firewall, brand=Palo Alto, name=PA-5220)
- **Falcon** (source_type=Endpoint, brand=CrowdStrike, name=Falcon)

### Framework Mapping
```
source_models ↔ model_framework_map ↔ framework_vectors
```

Each source can map to multiple MITRE tactics and NIST functions:
- Windows Server 2022 → Initial Access, Execution, Persistence (MITRE)
- Windows Server 2022 → Asset Management, Access Control (NIST)

### Detection Engineering Artifacts
```
Correlation Rules (reusable, stored once)
  ↓
  Many-to-many mapping to models
  ↓
One rule can apply to multiple models

Parsers (model-specific)
  ↓
CEF parser for PA-5220, GROK parser for Splunk, etc.

SOAR Flows (model-specific)
  ↓
Custom workflows per vendor API
```

### Access Control
```
Analyst → read-only
Admin → create/manage parsers, rules, SOAR flows
Super Admin → modify compliance, attack vectors, manage users
```

---

## 📊 User Navigation Flow

```
1. Login
   ↓
2. Select Framework (MITRE or NIST)
   ↓
3. View Tactics/Functions (Initial Access, Execution, etc.)
   ↓
4. See Models Mapped to Tactic
   (Server → Microsoft → Windows Server 2022)
   (Firewall → Palo Alto → PA-5220)
   ↓
5. View Model Details
   ├─ Correlation Rules (which detections apply)
   ├─ Parsers (how to parse logs)
   ├─ SOAR Workflows (automated response)
   ├─ Compliance (regulatory mapping)
   └─ Attack Vectors (threat info)
```

---

## 🔐 Role-Based Permissions

| Feature | Analyst | Admin | Super Admin |
|---------|---------|-------|------------|
| View all data | ✅ | ✅ | ✅ |
| Create parser | ❌ | ✅ | ✅ |
| Create correlation rule | ❌ | ✅ | ✅ |
| Create SOAR flow | ❌ | ✅ | ✅ |
| Modify compliance | ❌ | ❌ | ✅ |
| Manage users | ❌ | ❌ | ✅ |

---

## 📡 Key API Endpoints

### Public
```
POST   /auth/login                                    → JWT token
POST   /auth/register                                 → Create user
GET    /health                                        → Health check
```

### Framework Discovery (All roles)
```
GET    /frameworks                                    → List frameworks
GET    /frameworks/{framework}/vectors                → List tactics/functions
GET    /frameworks/{framework}/vectors/{vector}/models → Models for vector
GET    /models/{id}                                   → Complete model details
```

### Admin Only
```
POST   /parsers                                       → Create parser
PUT    /parsers/{id}                                 → Update parser
DELETE /parsers/{id}                                 → Delete parser
POST   /correlation-rules                            → Create rule
POST   /model-correlation-map                        → Map rule to model
POST   /soar-flows                                   → Create SOAR flow
```

### Super Admin Only
```
PUT    /compliance/{id}                              → Modify compliance
PUT    /attack-vectors/{id}                          → Modify attack vector
```

---

## 🗄️ Database Schema Highlights

```
FRAMEWORKS LAYER
├─ frameworks (MITRE, NIST)
└─ framework_vectors (tactics, functions)

SOURCE LAYER
├─ source_types (Server, Firewall, Endpoint)
├─ brands (Microsoft, Palo Alto, CrowdStrike)
└─ source_models [UNIQUE(type, brand, name)]

MAPPING LAYER
└─ model_framework_map (M2M: models ↔ vectors)

DETECTION ENGINEERING
├─ correlation_rules (reusable)
├─ model_correlation_map (M2M: rules ↔ models)
├─ parsers (model-specific)
└─ soar_flows (model-specific)

STATIC INTELLIGENCE
├─ compliances
├─ attack_vectors
└─ highlights

ACCESS CONTROL
└─ users (role: analyst, admin, super_admin)
```

---

## 🔐 Security Features

✅ **JWT Authentication** - Stateless, expiring tokens  
✅ **Password Hashing** - bcrypt with salt  
✅ **RBAC Enforcement** - Backend-enforced (never frontend)  
✅ **CORS Protection** - Configurable allowed origins  
✅ **SQL Injection Prevention** - SQLAlchemy ORM  
✅ **XSS Protection** - Framework defaults + Content-Type headers  
✅ **HTTPS Ready** - Nginx configuration included  
✅ **Security Headers** - X-Frame-Options, X-Content-Type-Options, etc.  

---

## 📈 Performance Optimizations

- **Database Indexes** on all foreign keys and critical fields
- **Connection Pooling** via SQLAlchemy
- **Gzip Compression** on frontend assets
- **Joinedload** for relationship queries
- **Pagination** support on API endpoints
- **Caching** of frameworks (rarely change)

---

## 🧪 Testing

### Run Backend Tests
```bash
pytest test_api.py -v
```

### Run Frontend Tests
```bash
npm test
```

---

## 📚 Documentation

1. **ARCHITECTURE.md** - Read this first to understand system design
2. **SETUP_AND_DEPLOYMENT.md** - Follow for production deployment
3. **DEVELOPER_REFERENCE.md** - Use as quick reference during development

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | FastAPI 0.104, SQLAlchemy 2.0, Pydantic |
| **Frontend** | React 18, Lucide React (icons) |
| **Database** | PostgreSQL 15 (production) / SQLite (dev) |
| **Server** | Nginx, Gunicorn/Uvicorn |
| **Cache** | Redis 7 (optional) |
| **Auth** | JWT (HS256), bcrypt |
| **Deployment** | Docker, Docker Compose |

---

## 📦 Project Structure

```
cybersec-dashboard/
├── backend/
│   ├── database_models.py          # SQLAlchemy models
│   ├── fastapi_backend.py          # FastAPI application
│   ├── requirements.txt            # Python dependencies
│   ├── Dockerfile                  # Backend container
│   └── init_db.py                  # Database initialization
│
├── frontend/
│   ├── react_frontend.jsx          # React app
│   ├── package.json                # Node dependencies
│   ├── Dockerfile                  # Frontend container
│   └── nginx.conf                  # Nginx configuration
│
├── docker-compose.yml              # Multi-container orchestration
├── nginx.conf                      # Nginx config
├── ARCHITECTURE.md                 # System design (read first!)
├── SETUP_AND_DEPLOYMENT.md         # Deployment guide
├── DEVELOPER_REFERENCE.md          # Developer guide
└── README.md                       # This file
```

---

## 🚨 Important Security Notes

1. **Change `SECRET_KEY`** before production
2. **Update database password** in docker-compose.yml
3. **Enable HTTPS** (uncomment SSL in nginx.conf)
4. **Set strong CORS origins** (not `*`)
5. **Use environment variables** for secrets (use `.env` file)
6. **Regular backups** of PostgreSQL database
7. **Monitor API logs** for unauthorized access attempts

---

## 🐛 Troubleshooting

### Docker Issues
```bash
# View logs
docker-compose logs backend
docker-compose logs frontend

# Rebuild images
docker-compose down && docker-compose up -d --build

# Clean everything
docker-compose down -v
```

### Database Connection
```bash
# Check PostgreSQL is running
docker-compose exec postgres psql -U cybersec -d cybersec_dashboard -c "SELECT 1"

# View database contents
docker-compose exec postgres psql -U cybersec -d cybersec_dashboard
```

### Frontend Issues
```bash
# Check API is reachable
curl http://localhost:8000/health

# View frontend logs
docker-compose logs frontend
```

---

## 🔄 Next Steps

1. **Deploy** using docker-compose
2. **Add your security sources** (models) to database
3. **Map sources** to MITRE/NIST vectors
4. **Create correlation rules** for your environment
5. **Configure parsers** for log formats
6. **Build SOAR workflows** for automated response

---

## 📞 Support

- **API Documentation**: http://localhost:8000/docs (Swagger UI)
- **Architecture Questions**: See ARCHITECTURE.md
- **Setup Issues**: See SETUP_AND_DEPLOYMENT.md
- **Development**: See DEVELOPER_REFERENCE.md

---

## 📜 Implementation Status

✅ **Complete & Production-Ready**

- [x] Database schema with constraints
- [x] FastAPI backend with all endpoints
- [x] React frontend with full UI
- [x] JWT authentication
- [x] Role-based access control
- [x] Docker containerization
- [x] Comprehensive documentation
- [x] Security best practices
- [x] Health checks
- [x] Error handling

---

## 📄 License

This implementation is provided as-is for educational and commercial use.

---

## 🎯 Design Principles

This system is built on these core principles:

1. **Single Source of Truth** - Source model is canonical identity
2. **Framework-Driven** - MITRE/NIST frameworks provide structure
3. **Reusable Components** - Rules shared, artifacts model-specific
4. **Strict RBAC** - Backend-enforced access control
5. **Relational Integrity** - Foreign keys, unique constraints, cascades
6. **Scalability** - Indexes, pagination, caching ready
7. **Security First** - Hashing, JWT, SQL injection prevention

---

## 🚀 Version Info

**Status**: Production-Ready  
**Version**: 1.0.0  
**Last Updated**: 2024  
**Python**: 3.9+  
**Node**: 16+  
**Database**: PostgreSQL 12+ / SQLite  

---

**Start exploring your security data across MITRE ATT&CK and NIST frameworks today!** 🛡️

