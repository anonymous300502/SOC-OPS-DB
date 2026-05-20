# Cybersecurity Intelligence Dashboard - Architecture & Design Document

## 📐 System Architecture Overview

This document explains the complete architecture of the Cybersecurity Intelligence Dashboard, a full-stack application for organizing security data across MITRE ATT&CK and NIST frameworks.

---

## 🧩 Core Data Model Architecture

### Central Identity: Source Models

The entire system revolves around a **canonical identity**:

```
(source_type + brand + model) = unique source model
```

This is the **single source of truth** for all security sources.

### Example Core Identities

| Source Type | Brand         | Model           | ID  |
|-------------|---------------|-----------------|-----|
| Server      | Microsoft     | Windows Server 2022 | 1   |
| Firewall    | Palo Alto     | PA-5220         | 2   |
| Endpoint    | CrowdStrike   | Falcon          | 3   |
| Firewall    | Cisco         | ASA 5520        | 4   |

### Database Relationships

```
┌──────────────────────────────────────────────────────────────┐
│                    FRAMEWORK LAYER                           │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  frameworks (id, name)                                       │
│  ├─ MITRE ATT&CK                                            │
│  └─ NIST Cybersecurity Framework                            │
│       │                                                       │
│       ↓                                                       │
│  framework_vectors (id, framework_id, external_id, name)    │
│  ├─ MITRE: TA0001 (Initial Access), TA0002 (Execution)...  │
│  └─ NIST: ID.AM (Asset Management), PR.AC (Access Control) │
└──────────────────────────────────────────────────────────────┘
              ↓
┌──────────────────────────────────────────────────────────────┐
│              MAPPING LAYER (CORE LOGIC)                      │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  model_framework_map                                         │
│  (source_model_id, framework_vector_id)                      │
│                                                               │
│  Many-to-Many Relationship:                                 │
│  ├─ One model → multiple vectors                            │
│  └─ One vector → multiple models                            │
│                                                               │
│  Example:                                                    │
│  - Windows Server 2022 → [TA0001, TA0002, TA0003]         │
│  - PA-5220 → [TA0001, TA0002]                              │
└──────────────────────────────────────────────────────────────┘
              ↓
┌──────────────────────────────────────────────────────────────┐
│               SOURCE LAYER (CORE IDENTITY)                   │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  source_types (id, name)          [Unique Constraint]       │
│  ├─ Server                                                   │
│  ├─ Firewall                                                │
│  └─ Endpoint                                                │
│       │                                                       │
│  brands (id, name)                [Unique Constraint]       │
│  ├─ Microsoft                                               │
│  ├─ Palo Alto                                               │
│  ├─ CrowdStrike                                             │
│  └─ Cisco                                                   │
│       │                                                       │
│  source_models (id, source_type_id, brand_id, name)        │
│  [UNIQUE(source_type_id, brand_id, name)]                  │
│  ├─ 1: (Server, Microsoft, Windows Server 2022)            │
│  ├─ 2: (Firewall, Palo Alto, PA-5220)                      │
│  ├─ 3: (Endpoint, CrowdStrike, Falcon)                     │
│  └─ 4: (Firewall, Cisco, ASA 5520)                         │
└──────────────────────────────────────────────────────────────┘
              ↓
┌──────────────────────────────────────────────────────────────┐
│          DETECTION ENGINEERING LAYER                         │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─ correlation_rules (reusable, stored once)              │
│  │  └─ model_correlation_map (many-to-many)                │
│  │      └─ source_models                                    │
│  │                                                           │
│  │  ✓ Enables: One rule → multiple models                  │
│  │            One model → multiple rules                    │
│  │                                                           │
│  │  Example:                                                │
│  │  - "Suspicious Outbound" rule used by:                  │
│  │    └─ Windows Server 2022                               │
│  │    └─ PA-5220                                           │
│  │    └─ Falcon                                            │
│  │                                                           │
│  ├─ parsers (model-specific)                               │
│  │  One parser per model, linked directly                  │
│  │  Formats: KV, JSON, GROK, CSV, CEF, XML               │
│  │                                                           │
│  └─ soar_flows (model-specific)                            │
│     One workflow per model, stored as JSON                 │
└──────────────────────────────────────────────────────────────┘
              ↓
┌──────────────────────────────────────────────────────────────┐
│           STATIC INTELLIGENCE LAYER                          │
├──────────────────────────────────────────────────────────────┤
│  (Read-heavy, restricted modification)                       │
│                                                               │
│  ├─ compliances (PCI-DSS, HIPAA, SOC2, etc.)              │
│  ├─ attack_vectors (threats, attack scenarios)             │
│  └─ highlights (security findings)                         │
│                                                               │
│  ⚠️  Modified only by super_admin                           │
└──────────────────────────────────────────────────────────────┘
```

---

## 🔄 User Navigation Flow

### Step 1: Authentication
```
Login Page
  ↓
  Username + Password → JWT Token
  ↓
  Token stored in localStorage
  ↓
  Role determination (analyst, admin, super_admin)
```

### Step 2: Framework Selection
```
User selects framework:
  ├─ MITRE ATT&CK
  └─ NIST Cybersecurity Framework
```

### Step 3: Vector Exploration
```
GET /frameworks/{framework}/vectors
  ↓
  Display all tactics/functions for framework
  ↓
  User clicks on specific vector (e.g., "Initial Access")
```

### Step 4: Model Discovery
```
GET /frameworks/{framework}/vectors/{vector}/models
  ↓
  Returns all source_models mapped to this vector
  ↓
  Grouped by: source_type → brand → model
  ↓
  Optional filtering by brand
```

### Step 5: Model Details
```
GET /models/{model_id}
  ↓
  Returns complete model information:
  ├─ Correlation rules (mapped via model_correlation_map)
  ├─ Parsers (linked directly)
  ├─ SOAR flows (linked directly)
  ├─ Compliance mappings
  ├─ Attack vectors
  └─ Highlights
  ↓
  Display in tabbed interface
```

### Step 6: Admin Modifications (if authorized)
```
Admin-only endpoints:
├─ POST /parsers (create)
├─ PUT /parsers/{id} (update)
├─ DELETE /parsers/{id} (delete)
├─ POST /correlation-rules (create)
├─ POST /model-correlation-map (link to models)
├─ POST /soar-flows (create)
├─ PUT /compliance/{id} (super_admin only)
└─ PUT /attack-vectors/{id} (super_admin only)
```

---

## 🔐 Role-Based Access Control (RBAC)

### Role Hierarchy

```
Analyst (read-only)
  ↓ can view all data
  ├─ View frameworks and vectors
  ├─ View source models and mappings
  ├─ View detection artifacts (rules, parsers, SOAR)
  ├─ View compliance and attack vectors
  └─ CANNOT modify anything

Admin (manage artifacts)
  ↓ everything analyst can do, plus:
  ├─ Create/update/delete parsers
  ├─ Create correlation rules
  ├─ Map rules to models
  ├─ Create/update SOAR flows
  └─ CANNOT modify static data or manage users

Super Admin (full control)
  ↓ everything admin can do, plus:
  ├─ Modify compliance data
  ├─ Modify attack vectors
  ├─ Modify highlights
  ├─ Manage users
  └─ Modify framework mappings
```

### RBAC Enforcement Points

**Authentication Layer**
```python
# JWT token contains: user_id, role, exp
payload = {
    "user_id": 1,
    "role": "admin",
    "exp": datetime.utcnow() + timedelta(minutes=480)
}
```

**Authorization Layer** (Backend enforced - never frontend)
```python
# On each endpoint:
@app.post("/parsers")
async def create_parser(
    parser: ParserCreate,
    current_user: dict = Depends(require_role("admin", "super_admin"))
):
    # Endpoint only accessible if user has admin or super_admin role
    pass
```

---

## 📡 API Endpoint Design

### Framework Discovery

```
GET /frameworks
Response:
[
  {"id": 1, "name": "mitre", "description": "MITRE ATT&CK"},
  {"id": 2, "name": "nist", "description": "NIST Cybersecurity Framework"}
]
```

### Vector Retrieval

```
GET /frameworks/{framework}/vectors
Example: GET /frameworks/mitre/vectors

Response:
[
  {
    "id": 1,
    "external_id": "TA0001",
    "name": "Initial Access",
    "description": "Tactics used to gain initial access..."
  },
  {
    "id": 2,
    "external_id": "TA0002",
    "name": "Execution",
    "description": "..."
  }
]
```

### Model Discovery (Framework-Vector-Specific)

```
GET /frameworks/{framework}/vectors/{vector}/models
Example: GET /frameworks/mitre/vectors/1/models

Response:
[
  {
    "source_type": "Server",
    "brand": "Microsoft",
    "model": "Windows Server 2022",
    "model_id": 1
  },
  {
    "source_type": "Firewall",
    "brand": "Palo Alto",
    "model": "PA-5220",
    "model_id": 2
  }
]

Filter by brand: GET /frameworks/mitre/vectors/1/models?brand=Microsoft
```

### Model Details (Complete Artifact Collection)

```
GET /models/{model_id}
Example: GET /models/2

Response:
{
  "id": 2,
  "source_type": "Firewall",
  "brand": "Palo Alto",
  "model": "PA-5220",
  "description": "...",
  
  "correlation_rules": [
    {
      "id": 1,
      "name": "Suspicious Outbound Connection",
      "severity": "high",
      "author": "Security Team",
      "tags": ["network", "exfiltration"],
      "created_at": "2024-01-15T10:30:00"
    }
  ],
  
  "parsers": [
    {
      "id": 1,
      "name": "PA System Log Parser",
      "format": "cef",
      "parser_config": {...}
    }
  ],
  
  "soar_flows": [
    {
      "id": 1,
      "name": "Block Malicious IP",
      "workflow_json": {...}
    }
  ],
  
  "compliance": [
    {"framework": "PCI-DSS", "requirement": "6.2"},
    {"framework": "HIPAA", "requirement": "164.308"}
  ],
  
  "attack_vectors": [
    {"vector": "Exfiltration", "severity": "critical"}
  ]
}
```

---

## 🔗 Key Design Decisions

### 1. Source Model as Central Identity

**Why?**
- Single source of truth for all security sources
- Prevents duplication and ensures consistency
- Unique constraint `(source_type_id, brand_id, name)` enforces integrity
- All relationships flow through source_models

**How it works:**
```
Windows Server 2022 (source_model_id=1)
  ├─ Maps to MITRE TA0001, TA0002, TA0003
  ├─ Maps to NIST ID.AM, PR.AC
  ├─ Uses 2 parsers
  ├─ Uses 3 correlation rules (via model_correlation_map)
  └─ Runs 2 SOAR flows
```

### 2. Framework-Driven Filtering

**Why?**
- User selects framework first, then sees only vectors for that framework
- Prevents confusion between MITRE and NIST
- Clear navigation path

**How it works:**
```
User selects "MITRE"
  ↓
Show only MITRE tactics (framework_vector where framework_id=1)
  ↓
User selects "Initial Access" (TA0001)
  ↓
Show only models mapped to TA0001 (via model_framework_map)
```

### 3. Reusable Correlation Rules

**Why?**
- Rules stored once, mapped to multiple models
- Reduces duplication
- Enables organization-wide rule sharing

**How it works:**
```
correlation_rules (stored once)
  ↓
  ├─ "Suspicious Outbound Connection"
  ├─ "Unauthorized Privilege Escalation"
  └─ "Process Injection Detected"
      ↓
model_correlation_map (bridges to models)
  ├─ Rule 1 → Windows Server 2022
  ├─ Rule 1 → PA-5220 (same rule, different model)
  ├─ Rule 2 → Falcon
  └─ Rule 3 → Windows Server 2022
```

### 4. Model-Specific Artifacts

**Parsers & SOAR Flows:**
- Linked directly to source_models
- Not shared between models (format variations differ)
- Each model can have multiple parsers (different formats)
- Each model can have multiple SOAR workflows

**Why separate from rules?**
- Parser format depends on vendor (CEF vs GROK vs JSON)
- SOAR workflow is model-specific (API differences)
- Rules are generic (applicable across models)

### 5. Static Intelligence Layer

**Compliances, Attack Vectors, Highlights:**
- Read-heavy
- Modified only by super_admin
- Not directly tied to source_models (organizational level)
- Cached in frontend (rarely change)

---

## 🎯 Query Patterns

### Pattern 1: What models support Initial Access?

```sql
SELECT DISTINCT sm.id, sm.name, st.name as type, b.name as brand
FROM source_models sm
JOIN model_framework_map mfm ON sm.id = mfm.source_model_id
JOIN framework_vectors fv ON mfm.framework_vector_id = fv.id
WHERE fv.external_id = 'TA0001'
ORDER BY st.name, b.name, sm.name;
```

**Result:**
- Windows Server 2022 (Server, Microsoft)
- PA-5220 (Firewall, Palo Alto)
- Windows Defender (Endpoint, Microsoft)

### Pattern 2: What correlation rules apply to PA-5220?

```sql
SELECT cr.id, cr.name, cr.severity
FROM correlation_rules cr
JOIN model_correlation_map mcm ON cr.id = mcm.correlation_rule_id
JOIN source_models sm ON mcm.source_model_id = sm.id
WHERE sm.id = 2
ORDER BY cr.severity DESC;
```

**Result:**
- "Suspicious Outbound Connection" (high)
- "Port Scanning Detected" (medium)

### Pattern 3: Complete model details

```sql
SELECT 
  sm.*, st.name as source_type, b.name as brand,
  (SELECT COUNT(*) FROM model_correlation_map WHERE source_model_id = sm.id) as rule_count,
  (SELECT COUNT(*) FROM parsers WHERE source_model_id = sm.id) as parser_count,
  (SELECT COUNT(*) FROM soar_flows WHERE source_model_id = sm.id) as flow_count
FROM source_models sm
JOIN source_types st ON sm.source_type_id = st.id
JOIN brands b ON sm.brand_id = b.id
WHERE sm.id = ?;
```

---

## 🎨 Frontend Component Architecture

```
App (main state management)
├─ LoginPage
│  └─ JWT token setup
│
├─ FrameworkSelector
│  └─ Select MITRE or NIST
│
├─ VectorList
│  └─ Display tactics/functions
│
├─ ModelListing
│  ├─ Group by source_type → brand
│  └─ Optional brand filter
│
└─ ModelDetail
   ├─ OverviewTab (model info + stats)
   ├─ CorrelationRulesTab (admin: add/delete)
   ├─ ParsersTab (admin: add/edit/delete)
   ├─ SOARFlowsTab (admin: add/delete)
   ├─ ComplianceTab (super_admin: edit)
   └─ AttackVectorsTab (super_admin: edit)
```

### State Management

```javascript
// Page navigation
const [currentPage, setCurrentPage] = useState('frameworks');

// Framework selection
const [selectedFramework, setSelectedFramework] = useState(null);

// Vector selection
const [selectedVector, setSelectedVector] = useState(null);
const [selectedVectorName, setSelectedVectorName] = useState(null);

// Model selection
const [selectedModel, setSelectedModel] = useState(null);
const [selectedModelName, setSelectedModelName] = useState(null);

// User info
const [userRole, setUserRole] = useState('analyst');
```

---

## 🔒 Security Architecture

### Password Hashing

```python
import bcrypt

# Registration
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

# Login verification
is_valid = bcrypt.checkpw(password.encode(), stored_hash.encode())
```

### JWT Token Flow

```
1. User logs in → POST /auth/login
2. Backend validates username/password
3. Backend creates JWT:
   {
     "user_id": 1,
     "role": "admin",
     "exp": 1704067200
   }
4. Frontend stores token in localStorage
5. Frontend sends token in Authorization header:
   Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc...
6. Backend verifies signature and expiration
7. Backend checks role for authorization
```

### RBAC Enforcement

```python
# Backend-side enforcement (never trust frontend)
@app.post("/parsers")
async def create_parser(
    current_user: dict = Depends(require_role("admin", "super_admin"))
):
    # Function only runs if user has admin or super_admin role
    if current_user["role"] not in ["admin", "super_admin"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
```

---

## 📊 Performance Considerations

### Indexing Strategy

```sql
-- Critical indexes
CREATE INDEX idx_user_username ON users(username);
CREATE INDEX idx_framework_name ON frameworks(name);
CREATE INDEX idx_framework_vector_framework ON framework_vectors(framework_id);
CREATE INDEX idx_source_type_name ON source_types(name);
CREATE INDEX idx_brand_name ON brands(name);
CREATE INDEX idx_source_model_source_type ON source_models(source_type_id);
CREATE INDEX idx_source_model_brand ON source_models(brand_id);
CREATE INDEX idx_model_framework_source ON model_framework_map(source_model_id);
CREATE INDEX idx_model_framework_vector ON model_framework_map(framework_vector_id);
CREATE INDEX idx_parser_source_model ON parsers(source_model_id);
CREATE INDEX idx_model_correlation_source ON model_correlation_map(source_model_id);
CREATE INDEX idx_model_correlation_rule ON model_correlation_map(correlation_rule_id);
```

### Query Optimization

1. **Eager Loading**
   ```python
   from sqlalchemy.orm import joinedload
   
   models = db.query(SourceModel).options(
       joinedload(SourceModel.source_type),
       joinedload(SourceModel.brand),
       joinedload(SourceModel.parsers)
   ).all()
   ```

2. **Pagination**
   ```python
   skip = (page - 1) * limit
   models = db.query(SourceModel).skip(skip).limit(limit).all()
   ```

3. **Caching**
   ```python
   from functools import lru_cache
   
   @lru_cache(maxsize=128)
   def get_frameworks():
       return db.query(Framework).all()
   ```

---

## 🔄 Data Ingestion Process

### MITRE ATT&CK

1. Download MITRE ATT&CK STIX data
2. Parse tactics from JSON/STIX
3. Insert into `framework_vectors` with `framework_id = MITRE.id`
4. Extract external_id (TA0001, TA0002, etc.)

### NIST Framework

1. Map NIST functions to internal format
2. Insert into `framework_vectors` with `framework_id = NIST.id`
3. Extract external_id (ID.AM, PR.AC, etc.)

### Manual Mapping

1. For each source_model, identify applicable vectors
2. Insert into `model_framework_map`
3. Example:
   - Windows Server 2022 → TA0001, TA0002, TA0003 (MITRE)
   - Windows Server 2022 → ID.AM, PR.AC (NIST)

---

## 🚀 Scalability Path

### Current (SQLite)
- 100-1000 source models
- 10-50 correlation rules
- Single-user or small team

### Medium Scale (PostgreSQL)
- 1000-10,000 source models
- 50-500 correlation rules
- 5-50 concurrent users
- Add connection pooling
- Add caching layer (Redis)

### Enterprise Scale
- 10,000+ source models
- 500+ correlation rules
- 50+ concurrent users
- Database replication
- API rate limiting
- Search indexing (Elasticsearch)
- Time-series metrics (Prometheus)

---

## 📝 Design Constraints (ENFORCED)

✅ **Do NOT duplicate correlation rules per model**
- Rules stored once, mapped via many-to-many

✅ **Do NOT split into multiple databases**
- Single unified database for all data

✅ **Do NOT tie brands to source types**
- Any brand can work with any source type

✅ **Do NOT trust frontend for authorization**
- All role checks enforced on backend

✅ **Do NOT hardcode framework mappings**
- Mappings stored in database, configurable

✅ **Maintain strict relational integrity**
- Foreign keys enforced
- Unique constraints enforced
- Cascade deletes where appropriate

---

**Architecture Version**: 1.0
**Last Updated**: 2024
**Status**: Production-Ready
