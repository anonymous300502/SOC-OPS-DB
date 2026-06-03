# 🛡️ Cybersecurity Intelligence Dashboard

A production full-stack application for organizing and mapping security data across **MITRE ATT&CK** and **NIST** cybersecurity frameworks, with structured storage for detection-engineering artifacts (correlation rules, parsers, SOAR flows).

- **Backend** — FastAPI, JWT auth, strict role-based access control (RBAC)
- **Frontend** — React (Vite) served by nginx
- **Database** — PostgreSQL (SQLAlchemy ORM); data persists in a Docker volume
- **Deployment** — Docker Compose

---

## 🔐 Access model

| Capability                              | Analyst | Admin | Super Admin |
|-----------------------------------------|:-------:|:-----:|:-----------:|
| View all data                           |   ✅    |  ✅   |     ✅      |
| Create/update/delete parsers            |   ❌    |  ✅   |     ✅      |
| Create/delete correlation rules         |   ❌    |  ✅   |     ✅      |
| Create/delete SOAR flows                |   ❌    |  ✅   |     ✅      |
| Create/delete highlights & mappings     |   ❌    |  ✅   |     ✅      |
| Import / export artifacts               |   ❌    |  ✅   |     ✅      |
| Create / manage **users**               |   ❌    |  ✅¹  |     ✅      |
| Modify compliance & attack vectors      |   ❌    |  ❌   |     ✅      |

¹ Admins can manage analysts and other admins, but **cannot** create, modify, or delete super-admins.

- **Analyst** — read-only across the entire dashboard.
- **Admin** — full content management plus user management (except super-admins).
- **Super Admin** — everything, including compliance/attack-vector edits and managing super-admins.

A single **super admin** is bootstrapped from environment variables on first startup. That account logs in and creates all other users from the **Users** screen. RBAC is enforced on the backend (the UI gating is convenience only).

---

## 🚀 Quick start

### 1. Configure environment

Edit `.env` and set strong values. At minimum you must provide:

| Variable               | Notes                                            |
|------------------------|--------------------------------------------------|
| `POSTGRES_PASSWORD`    | Strong DB password (`openssl rand -base64 24`)   |
| `SECRET_KEY`           | JWT signing key (`openssl rand -hex 32`)         |
| `SUPER_ADMIN_USERNAME` | First super-admin login                          |
| `SUPER_ADMIN_PASSWORD` | Min 8 characters; change after first login       |
| `SUPER_ADMIN_EMAIL`    | First super-admin email                          |

Compose will refuse to start if any required secret is missing.

### 2. Launch

```bash
docker compose up -d --build
```

- Frontend: http://localhost
- API docs (Swagger): http://localhost:8000/docs
- Health check: http://localhost:8000/health

### 3. First login

Log in with the `SUPER_ADMIN_*` credentials, open **Users**, and create your admin/analyst accounts. Everything those users create or upload is stored in PostgreSQL and **persists until explicitly deleted** (the database lives in the `postgres_data` volume; seeding never wipes existing data unless you set `FORCE_SEED=true`).

---

## 🗂️ Data persistence & seeding

- Application data is stored in the `postgres_data` Docker volume and survives restarts, rebuilds, and `docker compose up/down` (it is removed only by `docker compose down -v`).
- On first init the reference catalog (frameworks, source models, etc.) is seeded. On later starts the seeder detects existing data and **skips** — user-created/uploaded content is never overwritten.
- The bootstrap super-admin is created once; if it already exists it is left untouched (passwords are managed via the API, never reset from env).
- To intentionally wipe and re-seed the catalog, run the backend with `FORCE_SEED=true`.

---

## 🧱 Architecture (overview)

```
(source_type + brand + model) = a unique security source
        │
        ├── model_framework_map ──→ framework_vectors (MITRE tactics / NIST functions)
        │
        ├── correlation_rules  (reusable, many-to-many with models)
        ├── parsers            (model-specific)
        ├── soar_flows         (model-specific)
        └── compliance / attack_vectors / highlights
```

See **ARCHITECTURE.md** for the full data model and query patterns.

---

## 📡 Key API endpoints

```
POST   /auth/login                         → JWT token
GET    /auth/me                            → current user profile

# User management (admin / super_admin)
GET    /auth/users                         → list users
POST   /auth/users                         → create user
PATCH  /auth/users/{id}                    → update role / status / email / password
DELETE /auth/users/{id}                    → delete user

# Discovery (all authenticated roles)
GET    /frameworks
GET    /frameworks/{framework}/vectors
GET    /frameworks/{framework}/vectors/{vector}/models
GET    /models/{id}

# Content management (admin / super_admin)
POST|PUT|DELETE /parsers ...
POST|DELETE     /correlation-rules ...
POST|DELETE     /soar-flows ...
POST|DELETE     /models/{id}/highlights ...
POST|DELETE     /model-correlation-map ...
POST            /import/...      GET /export/...

# Super-admin only
PUT    /compliance/{id}
PUT    /attack-vectors/{id}
```

Interactive reference: http://localhost:8000/docs

---

## 📦 Project structure

```
.
├── backend/
│   ├── database_models.py     # SQLAlchemy models
│   ├── fastapi_backend.py     # FastAPI app: auth, RBAC, endpoints
│   ├── init_prod_db.py        # Catalog seed + super-admin bootstrap
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── App.jsx                # React app (login, dashboard, user mgmt)
│   ├── src/                   # entry + components
│   ├── package.json
│   ├── nginx.conf
│   └── Dockerfile
├── samples/                   # example import files (CSV / text / JSON)
├── docker-compose.yml
├── .env.example
├── ARCHITECTURE.md
├── DEVELOPER_REFERENCE.md
└── README.md
```

---

## 🔒 Security notes

- Set a unique `SECRET_KEY`; in `ENVIRONMENT=production` the API refuses to start with a missing/insecure key.
- All secrets come from `.env` (git-ignored). Never commit real credentials.
- Passwords are bcrypt-hashed; minimum length is 8 characters.
- RBAC is enforced server-side on every mutating endpoint.
- Enable HTTPS via `frontend/nginx.conf` and mount certificates into `frontend/ssl`.
- Set `ALLOWED_ORIGINS` to your real frontend origin(s).

---

## 🛠️ Tech stack

| Layer    | Technology                              |
|----------|-----------------------------------------|
| Backend  | FastAPI, SQLAlchemy 2.0, Pydantic, JWT  |
| Frontend | React 18 + Vite, Tailwind, lucide-react |
| Database | PostgreSQL 15                           |
| Serving  | Nginx, Uvicorn                          |
| Deploy   | Docker, Docker Compose                  |

---

## 🐛 Troubleshooting

```bash
docker compose logs -f backend          # backend logs
docker compose logs -f frontend         # frontend logs
docker compose down && docker compose up -d --build   # rebuild
docker compose exec postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"   # db shell
```

> `docker compose down -v` deletes the `postgres_data` volume and **all data**. Use only when you intend to start fresh.
