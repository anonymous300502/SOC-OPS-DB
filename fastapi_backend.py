"""
FastAPI Backend for Cybersecurity Intelligence Dashboard
Implements JWT authentication, RBAC, and all core endpoints
"""

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
import jwt
import bcrypt
from functools import wraps
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy import and_, create_engine
import os

# Import models
from database_models import (
    Base, User, Framework, FrameworkVector, SourceType, Brand, SourceModel,
    ModelFrameworkMap, CorrelationRule, ModelCorrelationMap, Parser, SOARFlow,
    Compliance, AttackVector, Highlight, RoleEnum, ParserFormatEnum,
    init_db
)

# ============================================================================
# CONFIGURATION
# ============================================================================

SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "480"))

# ============================================================================
# PYDANTIC MODELS (Request/Response)
# ============================================================================

class UserLogin(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: str = "analyst"

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    role: str
    username: str

class FrameworkVectorResponse(BaseModel):
    id: int
    external_id: str
    name: str
    description: Optional[str]
    
    class Config:
        from_attributes = True

class SourceTypeResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    
    class Config:
        from_attributes = True

class BrandResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    
    class Config:
        from_attributes = True

class SourceModelResponse(BaseModel):
    id: int
    source_type_id: int
    brand_id: int
    name: str
    description: Optional[str]
    source_type: SourceTypeResponse
    brand: BrandResponse
    
    class Config:
        from_attributes = True

class ModelDiscoveryResponse(BaseModel):
    """Response for GET /frameworks/{framework}/vectors/{vector}/models"""
    source_type: str
    brand: str
    model: str
    model_id: int
    
    class Config:
        from_attributes = True

class CorrelationRuleResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    author: Optional[str]
    severity: Optional[str]
    tags: Optional[List[str]]
    created_at: datetime
    
    class Config:
        from_attributes = True

class ParserResponse(BaseModel):
    id: int
    name: str
    format: str
    description: Optional[str]
    parser_config: dict
    is_active: bool
    created_at: datetime
    
    class Config:
        from_attributes = True

class SOARFlowResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    workflow_json: dict
    is_active: bool
    created_at: datetime
    
    class Config:
        from_attributes = True

class ModelDetailResponse(BaseModel):
    """Response for GET /models/{id} - complete model details"""
    id: int
    source_type: str
    brand: str
    model: str
    description: Optional[str]
    correlation_rules: List[CorrelationRuleResponse]
    parsers: List[ParserResponse]
    soar_flows: List[SOARFlowResponse]
    compliance: Optional[List[dict]]
    attack_vectors: Optional[List[dict]]
    highlights: Optional[List[dict]]

class ParserCreate(BaseModel):
    name: str
    format: str
    parser_config: dict
    description: Optional[str] = None

class ParserUpdate(BaseModel):
    name: Optional[str] = None
    format: Optional[str] = None
    parser_config: Optional[dict] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None

class CorrelationRuleCreate(BaseModel):
    name: str
    rule_logic: str
    description: Optional[str] = None
    author: Optional[str] = None
    severity: Optional[str] = None
    tags: Optional[List[str]] = None

class SOARFlowCreate(BaseModel):
    name: str
    workflow_json: dict
    description: Optional[str] = None

class ModelCorrelationMapCreate(BaseModel):
    source_model_id: int
    correlation_rule_id: int

class HighlightCreate(BaseModel):
    title: str
    content: Optional[str] = None
    priority: Optional[str] = "medium"

class ImportData(BaseModel):
    items: List[dict]

class ComplianceUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    requirements: Optional[List[str]] = None

class AttackVectorUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = None

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(password: str, hash: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode(), hash.encode())

def create_access_token(user_id: int, role: str, expires_delta: Optional[timedelta] = None):
    """Create JWT access token"""
    if expires_delta is None:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    expire = datetime.utcnow() + expires_delta
    payload = {
        "user_id": user_id,
        "role": role,
        "exp": expire
    }
    
    encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt, int(expires_delta.total_seconds())

def verify_token(token: str) -> dict:
    """Verify JWT token and return payload"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ============================================================================
# DEPENDENCY INJECTION
# ============================================================================

security = HTTPBearer()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///cybersec_dashboard.db")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> dict:
    """Extract and verify current user from JWT and check database status"""
    token = credentials.credentials
    payload = verify_token(token)
    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Token payload missing user ID")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if not user.is_active:
        raise HTTPException(status_code=400, detail="User account is deactivated")
        
    return {
        "user_id": user.id,
        "username": user.username,
        "role": user.role
    }

def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
    db: Session = Depends(get_db)
) -> Optional[dict]:
    """Optional version of get_current_user, returns None if not authenticated or invalid"""
    if not credentials:
        return None
    try:
        token = credentials.credentials
        payload = verify_token(token)
        user_id = payload.get("user_id")
        if not user_id:
            return None
        user = db.query(User).filter(User.id == user_id).first()
        if not user or not user.is_active:
            return None
        return {
            "user_id": user.id,
            "username": user.username,
            "role": user.role
        }
    except Exception:
        return None

def require_role(*allowed_roles):
    """Dependency to check if user has required role"""
    def role_checker(current_user: dict = Depends(get_current_user)):
        if current_user.get("role") not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient permissions. Required roles: {allowed_roles}"
            )
        return current_user
    return role_checker

# ============================================================================
# FASTAPI APPLICATION
# ============================================================================

app = FastAPI(
    title="Cybersecurity Intelligence Dashboard API",
    description="MITRE ATT&CK / NIST Framework Intelligence Platform",
    version="1.0.0"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# AUTH ENDPOINTS
# ============================================================================

@app.post("/auth/register", response_model=dict)
async def register(
    user: UserCreate,
    db: Session = Depends(get_db),
    current_user: Optional[dict] = Depends(get_current_user_optional)
):
    """Register new user (only admin can create non-analyst users)"""
    existing_user = db.query(User).filter(
        (User.username == user.username) | (User.email == user.email)
    ).first()
    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Username or email already registered"
        )
    
    role = RoleEnum.ANALYST
    if current_user and current_user.get("role") in [RoleEnum.ADMIN, RoleEnum.SUPER_ADMIN]:
        role = user.role
        
    hashed_pwd = hash_password(user.password)
    db_user = User(
        username=user.username,
        email=user.email,
        password_hash=hashed_pwd,
        role=role,
        is_active=True
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    return {
        "message": "User created successfully",
        "username": db_user.username,
        "role": db_user.role
    }

@app.post("/auth/login", response_model=TokenResponse)
async def login(
    credentials: UserLogin,
    db: Session = Depends(get_db)
):
    """
    Login endpoint - returns JWT token and user info
    """
    db_user = db.query(User).filter(User.username == credentials.username).first()
    if not db_user or not verify_password(credentials.password, db_user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    if not db_user.is_active:
        raise HTTPException(status_code=400, detail="User account is deactivated")
        
    token, expires_in = create_access_token(db_user.id, db_user.role)
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=expires_in,
        role=db_user.role,
        username=db_user.username
    )

# ============================================================================
# FRAMEWORK ENDPOINTS
# ============================================================================

@app.get("/frameworks")
async def get_frameworks(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    GET /frameworks
    Returns available frameworks (MITRE, NIST)
    """
    frameworks = db.query(Framework).all()
    return [{"id": f.id, "name": f.name, "description": f.description} for f in frameworks]

@app.get("/frameworks/{framework}/vectors")
async def get_framework_vectors(
    framework: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    GET /frameworks/{framework}/vectors
    Returns all tactics/functions for a framework
    """
    if framework not in ["mitre", "nist"]:
        raise HTTPException(status_code=400, detail="Invalid framework")
    
    fw = db.query(Framework).filter(Framework.name == framework).first()
    if not fw:
        raise HTTPException(status_code=404, detail="Framework not found")
    
    vectors = db.query(FrameworkVector).filter(FrameworkVector.framework_id == fw.id).all()
    return [
        {
            "id": v.id,
            "external_id": v.external_id,
            "name": v.name,
            "description": v.description
        }
        for v in vectors
    ]

@app.get("/frameworks/{framework}/vectors/{vector}/models")
async def get_models_for_vector(
    framework: str,
    vector: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    GET /frameworks/{framework}/vectors/{vector}/models
    Returns all source models mapped to this vector, grouped by source_type → brand → model
    """
    if framework not in ["mitre", "nist"]:
        raise HTTPException(status_code=400, detail="Invalid framework")
    
    fw = db.query(Framework).filter(Framework.name == framework).first()
    if not fw:
        raise HTTPException(status_code=404, detail="Framework not found")
        
    vec = db.query(FrameworkVector).filter(
        and_(FrameworkVector.framework_id == fw.id, FrameworkVector.id == vector)
    ).first()
    if not vec:
        raise HTTPException(status_code=404, detail="Vector not found")
        
    mappings = db.query(ModelFrameworkMap).filter(
        ModelFrameworkMap.framework_vector_id == vec.id
    ).all()
    
    result = []
    for m in mappings:
        model = m.source_model
        if model:
            result.append({
                "source_type": model.source_type.name if model.source_type else "Unknown",
                "brand": model.brand.name if model.brand else "Unknown",
                "model": model.name,
                "model_id": model.id
            })
    return result

# ============================================================================
# MODEL DETAIL ENDPOINTS
# ============================================================================

@app.get("/models/{model_id}")
async def get_model_details(
    model_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    GET /models/{model_id}
    Returns complete model details with all artifacts
    """
    model = db.query(SourceModel).filter(SourceModel.id == model_id).first()
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")
        
    return {
        "id": model.id,
        "source_type": model.source_type.name if model.source_type else "Unknown",
        "brand": model.brand.name if model.brand else "Unknown",
        "model": model.name,
        "description": model.description,
        "correlation_rules": [
            {
                "id": rm.correlation_rule.id,
                "name": rm.correlation_rule.name,
                "description": rm.correlation_rule.description,
                "author": rm.correlation_rule.author,
                "severity": rm.correlation_rule.severity,
                "tags": rm.correlation_rule.tags,
                "rule_logic": rm.correlation_rule.rule_logic,
                "created_at": rm.correlation_rule.created_at.isoformat()
            }
            for rm in model.correlation_mappings if rm.correlation_rule
        ],
        "parsers": [
            {
                "id": p.id,
                "name": p.name,
                "format": p.format,
                "description": p.description,
                "parser_config": p.parser_config,
                "is_active": p.is_active,
                "created_at": p.created_at.isoformat()
            }
            for p in model.parsers
        ],
        "soar_flows": [
            {
                "id": f.id,
                "name": f.name,
                "description": f.description,
                "workflow_json": f.workflow_json,
                "is_active": f.is_active,
                "created_at": f.created_at.isoformat()
            }
            for f in model.soar_flows
        ],
        "compliance": [
            {
                "framework": c.name,
                "requirement": req
            }
            for c in db.query(Compliance).all() for req in (c.requirements or [])
        ],
        "attack_vectors": [
            {
                "vector": a.name,
                "severity": a.severity,
                "description": a.description
            }
            for a in db.query(AttackVector).all()
        ],
        "highlights": [
            {
                "id": h.id,
                "title": h.title,
                "content": h.content,
                "priority": h.priority
            }
            for h in db.query(Highlight).filter(
                (Highlight.source_model_id == model_id) | (Highlight.source_model_id == None)
            ).all()
        ]
    }

# ============================================================================
# PARSER ENDPOINTS (Admin required)
# ============================================================================

@app.post("/parsers")
async def create_parser(
    parser: ParserCreate,
    model_id: int,
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db)
):
    """
    POST /parsers
    Create new parser (admin+ only)
    """
    model = db.query(SourceModel).filter(SourceModel.id == model_id).first()
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")
        
    new_parser = Parser(
        source_model_id=model_id,
        name=parser.name,
        format=parser.format,
        parser_config=parser.parser_config,
        description=parser.description
    )
    db.add(new_parser)
    db.commit()
    db.refresh(new_parser)
    
    return {
        "id": new_parser.id,
        "name": new_parser.name,
        "format": new_parser.format,
        "description": new_parser.description,
        "created_at": new_parser.created_at.isoformat(),
        "message": "Parser created successfully"
    }

@app.put("/parsers/{parser_id}")
async def update_parser(
    parser_id: int,
    update: ParserUpdate,
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db)
):
    """
    PUT /parsers/{parser_id}
    Update existing parser (admin+ only)
    """
    parser = db.query(Parser).filter(Parser.id == parser_id).first()
    if not parser:
        raise HTTPException(status_code=404, detail="Parser not found")
    
    update_data = update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(parser, field, value)
    
    db.commit()
    db.refresh(parser)
    
    return {
        "id": parser.id,
        "message": "Parser updated successfully",
        "updated_at": datetime.utcnow().isoformat()
    }

@app.delete("/parsers/{parser_id}")
async def delete_parser(
    parser_id: int,
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db)
):
    """
    DELETE /parsers/{parser_id}
    Delete parser (admin+ only)
    """
    parser = db.query(Parser).filter(Parser.id == parser_id).first()
    if not parser:
        raise HTTPException(status_code=404, detail="Parser not found")
    
    db.delete(parser)
    db.commit()
    
    return {"message": "Parser deleted successfully"}

# ============================================================================
# CORRELATION RULE ENDPOINTS (Admin required)
# ============================================================================

@app.post("/correlation-rules")
async def create_correlation_rule(
    rule: CorrelationRuleCreate,
    model_id: Optional[int] = None,
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db)
):
    """
    POST /correlation-rules
    Create reusable correlation rule (admin+ only)
    """
    new_rule = CorrelationRule(
        name=rule.name,
        description=rule.description,
        rule_logic=rule.rule_logic,
        author=rule.author or current_user.get("username", "Unknown"),
        severity=rule.severity,
        tags=rule.tags
    )
    db.add(new_rule)
    db.flush()
    
    if model_id is not None:
        model = db.query(SourceModel).filter(SourceModel.id == model_id).first()
        if not model:
            raise HTTPException(status_code=404, detail="Model not found")
        new_map = ModelCorrelationMap(
            source_model_id=model_id,
            correlation_rule_id=new_rule.id
        )
        db.add(new_map)
        
    db.commit()
    db.refresh(new_rule)
    
    return {
        "id": new_rule.id,
        "name": new_rule.name,
        "description": new_rule.description,
        "severity": new_rule.severity,
        "created_at": new_rule.created_at.isoformat(),
        "message": "Correlation rule created successfully"
    }

@app.post("/model-correlation-map")
async def map_correlation_to_model(
    mapping: ModelCorrelationMapCreate,
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db)
):
    """
    POST /model-correlation-map
    Map existing correlation rule to source model (admin+ only)
    Enables reuse: one rule → multiple models
    """
    model = db.query(SourceModel).filter(SourceModel.id == mapping.source_model_id).first()
    rule = db.query(CorrelationRule).filter(CorrelationRule.id == mapping.correlation_rule_id).first()
    if not model or not rule:
        raise HTTPException(status_code=404, detail="Model or rule not found")
        
    new_map = ModelCorrelationMap(
        source_model_id=mapping.source_model_id,
        correlation_rule_id=mapping.correlation_rule_id
    )
    db.add(new_map)
    db.commit()
    db.refresh(new_map)
    
    return {
        "id": new_map.id,
        "source_model_id": mapping.source_model_id,
        "correlation_rule_id": mapping.correlation_rule_id,
        "created_at": new_map.created_at.isoformat(),
        "message": "Correlation rule mapped to model successfully"
    }

# ============================================================================
# SOAR FLOW ENDPOINTS (Admin required)
# ============================================================================

@app.post("/soar-flows")
async def create_soar_flow(
    flow: SOARFlowCreate,
    model_id: int,
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db)
):
    """
    POST /soar-flows
    Create SOAR workflow for model (admin+ only)
    """
    model = db.query(SourceModel).filter(SourceModel.id == model_id).first()
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")
        
    new_flow = SOARFlow(
        source_model_id=model_id,
        name=flow.name,
        description=flow.description,
        workflow_json=flow.workflow_json
    )
    db.add(new_flow)
    db.commit()
    db.refresh(new_flow)
    
    return {
        "id": new_flow.id,
        "name": new_flow.name,
        "description": new_flow.description,
        "created_at": new_flow.created_at.isoformat(),
        "message": "SOAR flow created successfully"
    }

# ============================================================================
# NEW FEATURES ENDPOINTS
# ============================================================================

@app.post("/models/{model_id}/highlights")
async def create_highlight(
    model_id: int,
    highlight: HighlightCreate,
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db)
):
    model = db.query(SourceModel).filter(SourceModel.id == model_id).first()
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")
        
    new_highlight = Highlight(
        source_model_id=model_id,
        title=highlight.title,
        content=highlight.content,
        priority=highlight.priority
    )
    db.add(new_highlight)
    db.commit()
    return {"message": "Highlight created successfully"}

@app.post("/import/correlation-rules")
async def import_correlation_rules(
    data: ImportData,
    model_id: Optional[int] = None,
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db)
):
    count = 0
    for item in data.items:
        rule = CorrelationRule(
            name=item.get("name", "Imported Rule"),
            description=item.get("description", ""),
            rule_logic=item.get("rule_logic", ""),
            author=item.get("author", "Unknown"),
            severity=item.get("severity", "medium"),
            tags=item.get("tags", [])
        )
        db.add(rule)
        db.flush()
        
        if model_id is not None:
            mapping = ModelCorrelationMap(
                source_model_id=model_id,
                correlation_rule_id=rule.id
            )
            db.add(mapping)
        count += 1
    db.commit()
    return {"message": f"Successfully imported {count} correlation rules"}

@app.post("/import/parsers")
async def import_parsers(
    data: ImportData,
    model_id: int,
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db)
):
    model = db.query(SourceModel).filter(SourceModel.id == model_id).first()
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")
        
    count = 0
    for item in data.items:
        parser = Parser(
            source_model_id=model_id,
            name=item.get("name", "Imported Parser"),
            format=item.get("format", "unknown"),
            parser_config=item.get("parser_config", {}),
            description=item.get("description", "")
        )
        db.add(parser)
        count += 1
    db.commit()
    return {"message": f"Successfully imported {count} parsers"}

@app.post("/import/soar-flows")
async def import_soar_flows(
    data: ImportData,
    model_id: int,
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db)
):
    model = db.query(SourceModel).filter(SourceModel.id == model_id).first()
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")
        
    count = 0
    for item in data.items:
        flow = SOARFlow(
            source_model_id=model_id,
            name=item.get("name", "Imported Flow"),
            description=item.get("description", ""),
            workflow_json=item.get("workflow_json", {})
        )
        db.add(flow)
        count += 1
    db.commit()
    return {"message": f"Successfully imported {count} SOAR flows"}

# ============================================================================
# STATIC DATA ENDPOINTS (Super Admin only)
# ============================================================================

@app.put("/compliance/{compliance_id}")
async def update_compliance(
    compliance_id: int,
    update: ComplianceUpdate,
    current_user: dict = Depends(require_role("super_admin")),
    db: Session = Depends(get_db)
):
    """
    PUT /compliance/{compliance_id}
    Modify compliance data (super_admin only)
    """
    comp = db.query(Compliance).filter(Compliance.id == compliance_id).first()
    if not comp:
        raise HTTPException(status_code=404, detail="Compliance framework not found")
        
    update_data = update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(comp, field, value)
        
    db.commit()
    db.refresh(comp)
    
    return {
        "id": comp.id,
        "message": "Compliance data updated",
        "updated_at": datetime.utcnow().isoformat()
    }

@app.put("/attack-vectors/{vector_id}")
async def update_attack_vector(
    vector_id: int,
    update: AttackVectorUpdate,
    current_user: dict = Depends(require_role("super_admin")),
    db: Session = Depends(get_db)
):
    """
    PUT /attack-vectors/{vector_id}
    Modify attack vector (super_admin only)
    """
    vector = db.query(AttackVector).filter(AttackVector.id == vector_id).first()
    if not vector:
        raise HTTPException(status_code=404, detail="Attack vector not found")
        
    update_data = update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(vector, field, value)
        
    db.commit()
    db.refresh(vector)
    
    return {
        "id": vector.id,
        "message": "Attack vector updated",
        "updated_at": datetime.utcnow().isoformat()
    }

# ============================================================================
# HEALTH CHECK
# ============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
