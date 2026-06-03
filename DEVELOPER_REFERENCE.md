# Developer Quick Reference Guide

## 🚀 Quick Start

```bash
# Backend
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python init_db.py
uvicorn fastapi_backend:app --reload

# Frontend
cd frontend
npm install
npm start
```

---

## 📚 Core Concepts

### 1. Source Model (Core Identity)

```python
# Unique identity: (source_type_id, brand_id, model_name)
source_model = SourceModel(
    source_type_id=1,          # "Server"
    brand_id=1,                # "Microsoft"
    name="Windows Server 2022" # Model name
)
# Database enforces: UNIQUE(source_type_id, brand_id, name)
```

### 2. Framework Mapping

```python
# Many-to-many: source_model <-> framework_vector
mapping = ModelFrameworkMap(
    source_model_id=1,
    framework_vector_id=1  # e.g., MITRE TA0001
)
```

### 3. Correlation Rules (Reusable)

```python
# Create rule once
rule = CorrelationRule(
    name="Suspicious Outbound",
    rule_logic="...",
    severity="high"
)

# Map to multiple models
ModelCorrelationMap(source_model_id=1, correlation_rule_id=1)
ModelCorrelationMap(source_model_id=2, correlation_rule_id=1)  # Same rule
```

### 4. Model-Specific Artifacts

```python
# Parsers (one per model)
parser = Parser(
    source_model_id=1,
    format="cef",
    parser_config={...}
)

# SOAR Flows (one per model)
flow = SOARFlow(
    source_model_id=1,
    workflow_json={...}
)
```

---

## 🔐 Role Permissions

| Action | Analyst | Admin | Super Admin |
|--------|---------|-------|------------|
| View data | ✅ | ✅ | ✅ |
| Create parser | ❌ | ✅ | ✅ |
| Create correlation rule | ❌ | ✅ | ✅ |
| Create SOAR flow | ❌ | ✅ | ✅ |
| Modify compliance | ❌ | ❌ | ✅ |
| Modify attack vectors | ❌ | ❌ | ✅ |
| Manage users | ❌ | ❌ | ✅ |

---

## 📡 API Endpoints Summary

### Authentication

```python
# Login
POST /auth/login
{
    "username": "<username>",
    "password": "<your-password>"
}
# Returns: {access_token, token_type, expires_in}

# Register
POST /auth/register
{
    "username": "newuser",
    "email": "user@example.com",
    "password": "secure_password",
    "role": "analyst"
}
```

### Frameworks & Vectors

```python
# Get all frameworks
GET /frameworks
# Returns: [{id, name, description}]

# Get vectors for framework
GET /frameworks/{framework}/vectors
# Returns: [{id, external_id, name, description}]

# Get models for vector
GET /frameworks/{framework}/vectors/{vector}/models
# Returns: [{source_type, brand, model, model_id}]
```

### Model Details

```python
# Get complete model details
GET /models/{model_id}
# Returns: {
#   id, source_type, brand, model, description,
#   correlation_rules, parsers, soar_flows,
#   compliance, attack_vectors, highlights
# }
```

### Parsers (Admin+)

```python
# Create parser
POST /parsers?model_id={model_id}
{
    "name": "Parser Name",
    "format": "json",  # kv, json, grok, csv, cef, xml
    "description": "...",
    "parser_config": {...}
}

# Update parser
PUT /parsers/{parser_id}
{
    "name": "Updated Name",
    "is_active": true
    # Other fields optional
}

# Delete parser
DELETE /parsers/{parser_id}
```

### Correlation Rules (Admin+)

```python
# Create correlation rule
POST /correlation-rules
{
    "name": "Rule Name",
    "rule_logic": "...",
    "description": "...",
    "author": "Team Name",
    "severity": "high",  # critical, high, medium, low
    "tags": ["tag1", "tag2"]
}

# Map rule to model
POST /model-correlation-map
{
    "source_model_id": 1,
    "correlation_rule_id": 1
}
```

### SOAR Flows (Admin+)

```python
# Create SOAR flow
POST /soar-flows?model_id={model_id}
{
    "name": "Flow Name",
    "description": "...",
    "workflow_json": {
        "steps": [
            {"action": "block_ip", "params": {...}},
            {"action": "notify_soc", "params": {...}}
        ]
    }
}
```

### Static Data (Super Admin+)

```python
# Update compliance
PUT /compliance/{compliance_id}
{...}

# Update attack vector
PUT /attack-vectors/{vector_id}
{...}
```

---

## 🗄️ Database Query Examples

### Find all models mapped to a vector

```python
from sqlalchemy import and_

models = db.query(SourceModel).join(
    ModelFrameworkMap
).filter(
    ModelFrameworkMap.framework_vector_id == vector_id
).all()
```

### Find all rules for a model

```python
rules = db.query(CorrelationRule).join(
    ModelCorrelationMap
).filter(
    ModelCorrelationMap.source_model_id == model_id
).all()
```

### Get model with all relationships

```python
from sqlalchemy.orm import joinedload

model = db.query(SourceModel).options(
    joinedload(SourceModel.source_type),
    joinedload(SourceModel.brand),
    joinedload(SourceModel.parsers),
    joinedload(SourceModel.soar_flows),
    joinedload(SourceModel.correlation_mappings).joinedload(
        ModelCorrelationMap.correlation_rule
    )
).filter(SourceModel.id == model_id).first()
```

### Count artifacts per model

```python
from sqlalchemy import func

result = db.query(
    SourceModel.id,
    SourceModel.name,
    func.count(Parser.id).label('parser_count'),
    func.count(SOARFlow.id).label('flow_count'),
    func.count(ModelCorrelationMap.id).label('rule_count')
).outerjoin(Parser).outerjoin(SOARFlow).outerjoin(
    ModelCorrelationMap
).group_by(SourceModel.id).all()
```

---

## 🔐 Authentication & Authorization

### Login Flow

```javascript
// Frontend
const response = await fetch('/auth/login', {
    method: 'POST',
    body: JSON.stringify({username, password})
});
const {access_token} = await response.json();
localStorage.setItem('auth_token', access_token);

// All subsequent requests
fetch('/api/endpoint', {
    headers: {
        'Authorization': `Bearer ${access_token}`
    }
});
```

### Backend JWT Verification

```python
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer

security = HTTPBearer()

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail='Invalid token')

# In endpoint:
@app.get('/frameworks')
async def get_frameworks(
    credentials: HTTPAuthCredential = Depends(security)
):
    payload = verify_token(credentials.credentials)
    user_id = payload['user_id']
    role = payload['role']
```

### Role-Based Access

```python
def require_role(*allowed_roles):
    def role_checker(current_user: dict = Depends(get_current_user)):
        if current_user['role'] not in allowed_roles:
            raise HTTPException(status_code=403, detail='Insufficient permissions')
        return current_user
    return role_checker

@app.post('/parsers')
async def create_parser(
    current_user: dict = Depends(require_role('admin', 'super_admin'))
):
    # Only admin or super_admin can reach here
    pass
```

---

## 🎨 Frontend Components

### API Service

```javascript
class APIService {
    async login(username, password) {
        const response = await fetch(`${API_BASE}/auth/login`, {
            method: 'POST',
            body: JSON.stringify({username, password})
        });
        const data = await response.json();
        this.setToken(data.access_token);
        return data;
    }

    async getFrameworks() {
        return this.request('GET', '/frameworks');
    }

    async getFrameworkVectors(framework) {
        return this.request('GET', `/frameworks/${framework}/vectors`);
    }

    request(method, path, body = null) {
        return fetch(`${API_BASE}${path}`, {
            method,
            headers: this.getHeaders(),
            body: body ? JSON.stringify(body) : null
        }).then(r => r.json());
    }

    getHeaders() {
        return {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.token}`
        };
    }
}
```

### Component Structure

```javascript
<App>
  {isLoggedIn ? (
    <>
      <Header logout={logout} role={userRole} />
      {currentPage === 'frameworks' && <FrameworkSelector />}
      {currentPage === 'vectors' && <VectorList />}
      {currentPage === 'models' && <ModelListing />}
      {currentPage === 'detail' && <ModelDetail />}
    </>
  ) : (
    <LoginPage />
  )}
</App>
```

---

## 🧪 Testing Checklist

### Backend Tests

```python
def test_login_success():
    response = client.post('/auth/login', json={
        'username': '<username>',
        'password': '<your-password>'
    })
    assert response.status_code == 200
    assert 'access_token' in response.json()

def test_unauthorized_access():
    response = client.get('/frameworks')
    assert response.status_code == 401

def test_role_enforcement():
    # Login as analyst
    token = get_token('analyst')
    # Try to create parser (requires admin)
    response = client.post(
        '/parsers?model_id=1',
        headers={'Authorization': f'Bearer {token}'},
        json={'name': 'test', 'format': 'json', 'parser_config': {}}
    )
    assert response.status_code == 403
```

### Frontend Tests

```javascript
it('should login with valid credentials', async () => {
    await act(async () => {
        // Simulate login
        await api.login('<username>', '<your-password>');
    });
    expect(localStorage.getItem('auth_token')).toBeTruthy();
});

it('should show model details on selection', async () => {
    // Select framework
    // Select vector
    // Select model
    // Assert ModelDetail component renders
});
```

---

## 🐛 Common Issues & Solutions

### Issue: CORS Error

```
Access to XMLHttpRequest blocked by CORS policy
```

**Solution:**
```python
# In fastapi_backend.py
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=['http://localhost:3000'],
    allow_methods=['*'],
    allow_headers=['*']
)
```

### Issue: Database Connection Error

```
sqlalchemy.exc.OperationalError: (sqlite3.OperationalError)
```

**Solution:**
```bash
# Check database file exists
ls -la cybersec_dashboard.db

# Reinitialize if needed
rm cybersec_dashboard.db
python init_db.py
```

### Issue: JWT Token Expired

```
fastapi.exceptions.HTTPException: Invalid token
```

**Solution:**
```javascript
// Refresh token on expiration
if (error.status === 401) {
    localStorage.removeItem('auth_token');
    redirectToLogin();
}
```

### Issue: Module Not Found

```
ModuleNotFoundError: No module named 'fastapi'
```

**Solution:**
```bash
pip install -r requirements.txt
```

---

## 📋 Development Workflow

### 1. Add New Field to Source Model

```python
# In database_models.py
class SourceModel(Base):
    # ... existing fields ...
    new_field = Column(String(255), nullable=True)

# Migrate database (for SQLite, delete and recreate)
# For PostgreSQL: alembic upgrade head
```

### 2. Add New Role Permission

```python
# In RoleEnum
class RoleEnum(str, Enum):
    ANALYST = "analyst"
    NEW_ROLE = "new_role"

# Update require_role decorator
@require_role("new_role", "super_admin")
async def new_endpoint():
    pass
```

### 3. Add New API Endpoint

```python
# In fastapi_backend.py
@app.get("/new-endpoint/{id}")
async def new_endpoint(
    id: int,
    current_user: dict = Depends(get_current_user)
):
    # Implementation
    return result
```

### 4. Add New Frontend Component

```javascript
// Create component
function NewComponent({ data, onAction }) {
    return (
        <div className="...">
            {/* Component JSX */}
        </div>
    );
}

// Use in App
{currentPage === 'new' && <NewComponent />}
```

---

## 📊 Key Metrics to Monitor

- **Database Size**: Monitor `.db` file size
- **API Response Time**: Should be <500ms per request
- **Token Expiration**: Warn users 5min before expiry
- **Error Rates**: Monitor 4xx and 5xx responses
- **Concurrent Users**: Track active sessions
- **Rule Coverage**: % of models with correlation rules

---

## 🔗 Important Links

- API Docs: `http://localhost:8000/docs`
- Database: `sqlite:///cybersec_dashboard.db`
- Frontend: `http://localhost:3000`
- MITRE ATT&CK: `https://attack.mitre.org`
- NIST Framework: `https://www.nist.gov/cyberframework`

---

## 💡 Pro Tips

1. **Use joinedload for relationships** to avoid N+1 queries
2. **Cache frameworks** (rarely change, cached in frontend)
3. **Pagination on large result sets** (models, rules)
4. **Validate JWT tokens** on every request (backend)
5. **Use database transactions** for multi-step operations
6. **Test role enforcement** thoroughly before deployment
7. **Keep JSON parsers** flexible for vendor variations
8. **Document SOAR workflows** in workflow_json

---

**Last Updated**: 2024 | Version 1.0
