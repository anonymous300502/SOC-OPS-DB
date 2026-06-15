"""
FastAPI Backend for Cybersecurity Intelligence Dashboard
Implements JWT authentication, RBAC, and all core endpoints
"""

from fastapi import FastAPI, HTTPException, Depends, status, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, Response
from pydantic import BaseModel
from typing import List, Optional, Any, Union
from datetime import datetime, timedelta
import jwt
import bcrypt
from functools import wraps
from sqlalchemy.orm import Session, sessionmaker, joinedload
from sqlalchemy import and_, or_, func, select, create_engine
from sqlalchemy.exc import IntegrityError
import os
import csv
import codecs
import json
import io

# Import models
from database_models import (
    Base, User, Framework, FrameworkVector, SourceType, Brand, SourceModel,
    ModelFrameworkMap, CorrelationRule, ModelCorrelationMap, Parser, SOARFlow,
    Compliance, AttackVector, Highlight, RoleEnum, ParserFormatEnum,
    vector_links, init_db
)

# ============================================================================
# CONFIGURATION
# ============================================================================

import secrets as _secrets
import logging

logger = logging.getLogger("cybersec.api")

# Deployment environment: "production" (default) enforces strict security.
ENVIRONMENT = os.getenv("ENVIRONMENT", "production").lower()

# JWT signing key. MUST be provided via the SECRET_KEY env var in production.
# In non-production we fall back to an ephemeral random key (tokens won't
# survive a restart, which is fine for local development).
SECRET_KEY = os.getenv("SECRET_KEY")
_INSECURE_DEFAULTS = {"", "your-secret-key-change-in-production", "changeme"}
if not SECRET_KEY or SECRET_KEY in _INSECURE_DEFAULTS:
    if ENVIRONMENT == "production":
        raise RuntimeError(
            "SECRET_KEY environment variable is not set or uses an insecure "
            "default. Set a strong, unique SECRET_KEY before starting in "
            "production (e.g. `openssl rand -hex 32`)."
        )
    SECRET_KEY = _secrets.token_hex(32)
    logger.warning(
        "SECRET_KEY not set; generated an ephemeral development key. "
        "Tokens will be invalidated on restart. Do NOT use this in production."
    )

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

class UserUpdate(BaseModel):
    email: Optional[str] = None
    password: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True

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
    rule_logic: Any
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

class SourceTypeCreate(BaseModel):
    name: str
    description: Optional[str] = None

class BrandCreate(BaseModel):
    name: str
    description: Optional[str] = None

class SourceModelCreate(BaseModel):
    source_type_id: int
    brand_id: int
    name: str
    description: Optional[str] = None

class SourceModelUpdate(BaseModel):
    source_type_id: Optional[int] = None
    brand_id: Optional[int] = None
    name: Optional[str] = None
    description: Optional[str] = None

class FrameworkVectorMapCreate(BaseModel):
    """Attach a source model to one or more framework vectors (TTPs)."""
    vector_ids: List[int]

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
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_size=10, max_overflow=20)
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
_raw_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost")
ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# AUTH ENDPOINTS
# ============================================================================

MIN_PASSWORD_LENGTH = 8

def _validate_password(password: str):
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"Password must be at least {MIN_PASSWORD_LENGTH} characters long",
        )

def _assignable_roles(actor_role: str) -> set:
    """Roles a given actor is allowed to assign to other users."""
    if actor_role == RoleEnum.SUPER_ADMIN.value:
        return {RoleEnum.ANALYST.value, RoleEnum.ADMIN.value, RoleEnum.SUPER_ADMIN.value}
    if actor_role == RoleEnum.ADMIN.value:
        # Admins manage analysts and other admins, but not super admins.
        return {RoleEnum.ANALYST.value, RoleEnum.ADMIN.value}
    return set()

def _can_manage_target(actor_role: str, target_role: str) -> bool:
    """Whether an actor may modify/delete a user with target_role."""
    if actor_role == RoleEnum.SUPER_ADMIN.value:
        return True
    if actor_role == RoleEnum.ADMIN.value:
        return target_role != RoleEnum.SUPER_ADMIN.value
    return False

@app.get("/auth/me", response_model=UserResponse)
async def get_me(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return the currently authenticated user's profile."""
    user = db.query(User).filter(User.id == current_user["user_id"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.get("/auth/users", response_model=List[UserResponse])
async def list_users(
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db),
):
    """List all users (admin+ only)."""
    return db.query(User).order_by(User.id).all()

@app.post("/auth/users", response_model=UserResponse, status_code=201)
async def create_user(
    user: UserCreate,
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db),
):
    """Create a new user (admin+ only). Role must be one the actor may assign."""
    _validate_password(user.password)

    valid_roles = {r.value for r in RoleEnum}
    if user.role not in valid_roles:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {sorted(valid_roles)}")

    allowed = _assignable_roles(current_user["role"])
    if user.role not in allowed:
        raise HTTPException(
            status_code=403,
            detail=f"You are not permitted to assign the '{user.role}' role.",
        )

    existing_user = db.query(User).filter(
        (User.username == user.username) | (User.email == user.email)
    ).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or email already registered")

    db_user = User(
        username=user.username,
        email=user.email,
        password_hash=hash_password(user.password),
        role=user.role,
        is_active=True,
    )
    db.add(db_user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Username or email already registered")
    db.refresh(db_user)
    return db_user

@app.patch("/auth/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    update: UserUpdate,
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db),
):
    """Update a user's email, password, role, or active status (admin+ only)."""
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    actor_role = current_user["role"]
    if not _can_manage_target(actor_role, target.role):
        raise HTTPException(status_code=403, detail="You are not permitted to manage this user.")

    is_self = target.id == current_user["user_id"]

    if update.role is not None and update.role != target.role:
        valid_roles = {r.value for r in RoleEnum}
        if update.role not in valid_roles:
            raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {sorted(valid_roles)}")
        if update.role not in _assignable_roles(actor_role):
            raise HTTPException(status_code=403, detail=f"You are not permitted to assign the '{update.role}' role.")
        if is_self:
            raise HTTPException(status_code=400, detail="You cannot change your own role.")
        # Prevent removing the last active super admin.
        if target.role == RoleEnum.SUPER_ADMIN.value:
            _guard_last_super_admin(db, exclude_id=target.id)
        target.role = update.role

    if update.is_active is not None and update.is_active != target.is_active:
        if is_self and update.is_active is False:
            raise HTTPException(status_code=400, detail="You cannot deactivate your own account.")
        if update.is_active is False and target.role == RoleEnum.SUPER_ADMIN.value:
            _guard_last_super_admin(db, exclude_id=target.id)
        target.is_active = update.is_active

    if update.email is not None:
        target.email = update.email

    if update.password is not None:
        _validate_password(update.password)
        target.password_hash = hash_password(update.password)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Email already in use")
    db.refresh(target)
    return target

@app.delete("/auth/users/{user_id}")
async def delete_user(
    user_id: int,
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db),
):
    """Delete a user (admin+ only). Cannot delete self or the last super admin."""
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target.id == current_user["user_id"]:
        raise HTTPException(status_code=400, detail="You cannot delete your own account.")
    if not _can_manage_target(current_user["role"], target.role):
        raise HTTPException(status_code=403, detail="You are not permitted to delete this user.")
    if target.role == RoleEnum.SUPER_ADMIN.value:
        _guard_last_super_admin(db, exclude_id=target.id)

    db.delete(target)
    db.commit()
    return {"message": "User deleted successfully"}

def _guard_last_super_admin(db: Session, exclude_id: int):
    """Raise if removing/demoting this user would leave no active super admin."""
    remaining = db.query(User).filter(
        User.role == RoleEnum.SUPER_ADMIN.value,
        User.is_active == True,  # noqa: E712
        User.id != exclude_id,
    ).count()
    if remaining == 0:
        raise HTTPException(
            status_code=400,
            detail="Cannot remove the last active super admin.",
        )

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

def _serialize_vectors(db: Session, vectors: list) -> list:
    """Serialize vectors with child and mapped-model counts (batched)."""
    if not vectors:
        return []
    ids = [v.id for v in vectors]
    child_counts = dict(
        db.query(vector_links.c.parent_id, func.count(vector_links.c.child_id))
        .filter(vector_links.c.parent_id.in_(ids))
        .group_by(vector_links.c.parent_id)
        .all()
    )
    model_counts = dict(
        db.query(ModelFrameworkMap.framework_vector_id, func.count(ModelFrameworkMap.id))
        .filter(ModelFrameworkMap.framework_vector_id.in_(ids))
        .group_by(ModelFrameworkMap.framework_vector_id)
        .all()
    )
    return [
        {
            "id": v.id,
            "external_id": v.external_id,
            "name": v.name,
            "description": v.description,
            "level": v.level,
            "child_count": child_counts.get(v.id, 0),
            "model_count": model_counts.get(v.id, 0),
        }
        for v in vectors
    ]


def _mapped_models(db: Session, vector_id: int) -> list:
    """Source models mapped directly to a vector."""
    mappings = (
        db.query(ModelFrameworkMap)
        .options(
            joinedload(ModelFrameworkMap.source_model).joinedload(SourceModel.source_type),
            joinedload(ModelFrameworkMap.source_model).joinedload(SourceModel.brand),
        )
        .filter(ModelFrameworkMap.framework_vector_id == vector_id)
        .all()
    )
    result = []
    for m in mappings:
        model = m.source_model
        if model:
            result.append({
                "source_type": model.source_type.name if model.source_type else "Unknown",
                "brand": model.brand.name if model.brand else "Unknown",
                "model": model.name,
                "model_id": model.id,
            })
    return result


@app.get("/frameworks/{framework}/vectors")
async def get_framework_vectors(
    framework: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Returns the TOP-LEVEL nodes of a framework (MITRE tactics / NIST functions).
    Use GET /vectors/{id} to drill down into children.
    """
    if framework not in ["mitre", "nist"]:
        raise HTTPException(status_code=400, detail="Invalid framework")

    fw = db.query(Framework).filter(Framework.name == framework).first()
    if not fw:
        raise HTTPException(status_code=404, detail="Framework not found")

    # Top-level = vectors of this framework that are nobody's child.
    child_subq = select(vector_links.c.child_id)
    vectors = (
        db.query(FrameworkVector)
        .filter(FrameworkVector.framework_id == fw.id, ~FrameworkVector.id.in_(child_subq))
        .order_by(FrameworkVector.external_id)
        .all()
    )
    return _serialize_vectors(db, vectors)


@app.get("/frameworks/{framework}/vectors/search")
async def search_framework_vectors(
    framework: str,
    q: str = "",
    level: Optional[str] = None,
    limit: int = 50,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Search a framework's vectors by external_id or name (for mapping UI)."""
    if framework not in ["mitre", "nist"]:
        raise HTTPException(status_code=400, detail="Invalid framework")
    fw = db.query(Framework).filter(Framework.name == framework).first()
    if not fw:
        raise HTTPException(status_code=404, detail="Framework not found")

    query = db.query(FrameworkVector).filter(FrameworkVector.framework_id == fw.id)
    if q:
        like = f"%{q.strip()}%"
        query = query.filter(or_(
            FrameworkVector.external_id.ilike(like),
            FrameworkVector.name.ilike(like),
        ))
    if level:
        query = query.filter(FrameworkVector.level == level)
    vectors = query.order_by(FrameworkVector.external_id).limit(min(limit, 200)).all()
    return _serialize_vectors(db, vectors)


@app.get("/vectors/{vector_id}")
async def get_vector(
    vector_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """A single vector node with its children (next drill-down level) and the
    source models mapped directly to it."""
    v = db.query(FrameworkVector).filter(FrameworkVector.id == vector_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="Vector not found")
    children = sorted(v.children, key=lambda c: c.external_id)
    return {
        "id": v.id,
        "external_id": v.external_id,
        "name": v.name,
        "description": v.description,
        "level": v.level,
        "framework": v.framework.name if v.framework else None,
        "parents": [
            {"id": p.id, "external_id": p.external_id, "name": p.name, "level": p.level}
            for p in sorted(v.parents, key=lambda p: p.external_id)
        ],
        "children": _serialize_vectors(db, children),
        "models": _mapped_models(db, v.id),
    }


@app.get("/frameworks/{framework}/vectors/{vector}/models")
async def get_models_for_vector(
    framework: str,
    vector: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Source models mapped to this vector (kept for backward compatibility)."""
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
    return _mapped_models(db, vec.id)

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
    model = (
        db.query(SourceModel)
        .options(
            joinedload(SourceModel.source_type),
            joinedload(SourceModel.brand),
            joinedload(SourceModel.correlation_mappings).joinedload(ModelCorrelationMap.correlation_rule),
            joinedload(SourceModel.parsers),
            joinedload(SourceModel.soar_flows),
            joinedload(SourceModel.highlights),
            joinedload(SourceModel.framework_mappings)
            .joinedload(ModelFrameworkMap.framework_vector)
            .joinedload(FrameworkVector.framework),
        )
        .filter(SourceModel.id == model_id)
        .first()
    )
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")

    compliances = db.query(Compliance).all()
    attack_vectors = db.query(AttackVector).all()
    highlights = (
        db.query(Highlight)
        .filter((Highlight.source_model_id == model_id) | (Highlight.source_model_id == None))
        .all()
    )

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
            {"framework": c.name, "requirement": req}
            for c in compliances for req in (c.requirements or [])
        ],
        "attack_vectors": [
            {"vector": a.name, "severity": a.severity, "description": a.description}
            for a in attack_vectors
        ],
        "highlights": [
            {"id": h.id, "title": h.title, "content": h.content, "priority": h.priority}
            for h in highlights
        ],
        "framework_vectors": [
            {
                "map_id": fm.id,
                "id": fm.framework_vector.id,
                "external_id": fm.framework_vector.external_id,
                "name": fm.framework_vector.name,
                "level": fm.framework_vector.level,
                "framework": fm.framework_vector.framework.name if fm.framework_vector.framework else None,
            }
            for fm in model.framework_mappings if fm.framework_vector
        ],
    }

# ============================================================================
# SOURCE CATALOG CRUD (Admin required for writes)
# ============================================================================

@app.get("/source-types")
async def list_source_types(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    rows = db.query(SourceType).order_by(SourceType.name).all()
    return [{"id": s.id, "name": s.name, "description": s.description} for s in rows]

@app.post("/source-types", status_code=201)
async def create_source_type(
    payload: SourceTypeCreate,
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db)
):
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Name is required")
    existing = db.query(SourceType).filter(SourceType.name == name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Source type already exists")
    st = SourceType(name=name, description=payload.description)
    db.add(st)
    db.commit()
    db.refresh(st)
    return {"id": st.id, "name": st.name, "description": st.description}

@app.delete("/source-types/{type_id}")
async def delete_source_type(
    type_id: int,
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db)
):
    st = db.query(SourceType).filter(SourceType.id == type_id).first()
    if not st:
        raise HTTPException(status_code=404, detail="Source type not found")
    if db.query(SourceModel).filter(SourceModel.source_type_id == type_id).count():
        raise HTTPException(status_code=400, detail="Cannot delete: source models still use this type")
    db.delete(st)
    db.commit()
    return {"message": "Source type deleted"}

@app.get("/brands")
async def list_brands(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    rows = db.query(Brand).order_by(Brand.name).all()
    return [{"id": b.id, "name": b.name, "description": b.description} for b in rows]

@app.post("/brands", status_code=201)
async def create_brand(
    payload: BrandCreate,
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db)
):
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Name is required")
    if db.query(Brand).filter(Brand.name == name).first():
        raise HTTPException(status_code=400, detail="Brand already exists")
    b = Brand(name=name, description=payload.description)
    db.add(b)
    db.commit()
    db.refresh(b)
    return {"id": b.id, "name": b.name, "description": b.description}

@app.delete("/brands/{brand_id}")
async def delete_brand(
    brand_id: int,
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db)
):
    b = db.query(Brand).filter(Brand.id == brand_id).first()
    if not b:
        raise HTTPException(status_code=404, detail="Brand not found")
    if db.query(SourceModel).filter(SourceModel.brand_id == brand_id).count():
        raise HTTPException(status_code=400, detail="Cannot delete: source models still use this brand")
    db.delete(b)
    db.commit()
    return {"message": "Brand deleted"}

@app.get("/source-models")
async def list_source_models(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    rows = (
        db.query(SourceModel)
        .options(joinedload(SourceModel.source_type), joinedload(SourceModel.brand))
        .order_by(SourceModel.name)
        .all()
    )
    # mapped-vector counts per model (batched)
    map_counts = dict(
        db.query(ModelFrameworkMap.source_model_id, func.count(ModelFrameworkMap.id))
        .group_by(ModelFrameworkMap.source_model_id)
        .all()
    )
    return [
        {
            "id": m.id,
            "name": m.name,
            "description": m.description,
            "source_type_id": m.source_type_id,
            "brand_id": m.brand_id,
            "source_type": m.source_type.name if m.source_type else None,
            "brand": m.brand.name if m.brand else None,
            "mapped_vectors": map_counts.get(m.id, 0),
        }
        for m in rows
    ]

@app.post("/source-models", status_code=201)
async def create_source_model(
    payload: SourceModelCreate,
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db)
):
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Name is required")
    if not db.query(SourceType).filter(SourceType.id == payload.source_type_id).first():
        raise HTTPException(status_code=404, detail="Source type not found")
    if not db.query(Brand).filter(Brand.id == payload.brand_id).first():
        raise HTTPException(status_code=404, detail="Brand not found")
    sm = SourceModel(
        source_type_id=payload.source_type_id,
        brand_id=payload.brand_id,
        name=name,
        description=payload.description,
    )
    db.add(sm)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="A model with this type/brand/name already exists")
    db.refresh(sm)
    return {"id": sm.id, "name": sm.name, "description": sm.description,
            "source_type_id": sm.source_type_id, "brand_id": sm.brand_id}

@app.patch("/source-models/{model_id}")
async def update_source_model(
    model_id: int,
    payload: SourceModelUpdate,
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db)
):
    sm = db.query(SourceModel).filter(SourceModel.id == model_id).first()
    if not sm:
        raise HTTPException(status_code=404, detail="Model not found")
    data = payload.model_dump(exclude_unset=True)
    if "name" in data and data["name"] is not None:
        data["name"] = data["name"].strip()
    for field, value in data.items():
        setattr(sm, field, value)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="A model with this type/brand/name already exists")
    db.refresh(sm)
    return {"id": sm.id, "name": sm.name, "description": sm.description,
            "source_type_id": sm.source_type_id, "brand_id": sm.brand_id}

@app.delete("/source-models/{model_id}")
async def delete_source_model(
    model_id: int,
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db)
):
    sm = db.query(SourceModel).filter(SourceModel.id == model_id).first()
    if not sm:
        raise HTTPException(status_code=404, detail="Model not found")
    db.delete(sm)  # cascades remove parsers/soar/mappings per model relationships
    db.commit()
    return {"message": "Source model deleted"}

# ============================================================================
# MODEL ↔ FRAMEWORK VECTOR (TTP) MAPPING (Admin required for writes)
# ============================================================================

@app.get("/models/{model_id}/framework-vectors")
async def get_model_framework_vectors(
    model_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List the framework vectors (TTPs) a model is mapped to, grouped by framework."""
    model = db.query(SourceModel).filter(SourceModel.id == model_id).first()
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")
    mappings = (
        db.query(ModelFrameworkMap)
        .options(joinedload(ModelFrameworkMap.framework_vector).joinedload(FrameworkVector.framework))
        .filter(ModelFrameworkMap.source_model_id == model_id)
        .all()
    )
    out = []
    for m in mappings:
        v = m.framework_vector
        if not v:
            continue
        out.append({
            "map_id": m.id,
            "vector_id": v.id,
            "external_id": v.external_id,
            "name": v.name,
            "level": v.level,
            "framework": v.framework.name if v.framework else None,
        })
    return out

@app.post("/models/{model_id}/framework-vectors", status_code=201)
async def map_model_framework_vectors(
    model_id: int,
    payload: FrameworkVectorMapCreate,
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db)
):
    """Map a model to one or more framework vectors (TTPs). Idempotent: existing
    mappings are skipped. Vectors may belong to either framework."""
    model = db.query(SourceModel).filter(SourceModel.id == model_id).first()
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")

    requested = set(payload.vector_ids)
    if not requested:
        return {"added": 0, "skipped": 0}
    valid_ids = {
        vid for (vid,) in db.query(FrameworkVector.id).filter(FrameworkVector.id.in_(requested)).all()
    }
    missing = requested - valid_ids
    if missing:
        raise HTTPException(status_code=404, detail=f"Unknown vector id(s): {sorted(missing)}")

    existing = {
        vid for (vid,) in db.query(ModelFrameworkMap.framework_vector_id)
        .filter(ModelFrameworkMap.source_model_id == model_id,
                ModelFrameworkMap.framework_vector_id.in_(valid_ids)).all()
    }
    added = 0
    for vid in valid_ids:
        if vid in existing:
            continue
        db.add(ModelFrameworkMap(source_model_id=model_id, framework_vector_id=vid))
        added += 1
    db.commit()
    return {"added": added, "skipped": len(valid_ids) - added}

@app.delete("/models/{model_id}/framework-vectors/{vector_id}")
async def unmap_model_framework_vector(
    model_id: int,
    vector_id: int,
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db)
):
    mapping = db.query(ModelFrameworkMap).filter(
        ModelFrameworkMap.source_model_id == model_id,
        ModelFrameworkMap.framework_vector_id == vector_id,
    ).first()
    if not mapping:
        raise HTTPException(status_code=404, detail="Mapping not found")
    db.delete(mapping)
    db.commit()
    return {"message": "Mapping removed"}

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

# ============================================================================
# DELETE ENDPOINTS (Admin required)
# ============================================================================

@app.delete("/correlation-rules/{rule_id}")
async def delete_correlation_rule(
    rule_id: int,
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db),
):
    """Delete a correlation rule and any model mappings (admin+ only)."""
    rule = db.query(CorrelationRule).filter(CorrelationRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Correlation rule not found")
    db.query(ModelCorrelationMap).filter(
        ModelCorrelationMap.correlation_rule_id == rule_id
    ).delete(synchronize_session=False)
    db.delete(rule)
    db.commit()
    return {"message": "Correlation rule deleted successfully"}

@app.delete("/model-correlation-map/{map_id}")
async def unmap_correlation_from_model(
    map_id: int,
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db),
):
    """Remove a correlation-rule-to-model mapping without deleting the rule (admin+ only)."""
    mapping = db.query(ModelCorrelationMap).filter(ModelCorrelationMap.id == map_id).first()
    if not mapping:
        raise HTTPException(status_code=404, detail="Mapping not found")
    db.delete(mapping)
    db.commit()
    return {"message": "Mapping removed successfully"}

@app.delete("/soar-flows/{flow_id}")
async def delete_soar_flow(
    flow_id: int,
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db),
):
    """Delete a SOAR flow (admin+ only)."""
    flow = db.query(SOARFlow).filter(SOARFlow.id == flow_id).first()
    if not flow:
        raise HTTPException(status_code=404, detail="SOAR flow not found")
    db.delete(flow)
    db.commit()
    return {"message": "SOAR flow deleted successfully"}

@app.delete("/highlights/{highlight_id}")
async def delete_highlight(
    highlight_id: int,
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db),
):
    """Delete a highlight (admin+ only)."""
    highlight = db.query(Highlight).filter(Highlight.id == highlight_id).first()
    if not highlight:
        raise HTTPException(status_code=404, detail="Highlight not found")
    db.delete(highlight)
    db.commit()
    return {"message": "Highlight deleted successfully"}

@app.post("/import/correlation-rules/csv")
async def import_correlation_rules_csv(
    file: UploadFile = File(...),
    model_id: Optional[int] = None,
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db)
):
    filename = file.filename or ""
    if not (filename.endswith(".csv") or filename.endswith(".txt")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be a .csv or .txt file"
        )

    # When a model is supplied, imported rules are also mapped to it so they
    # appear in that model's detail view. Validate it up front.
    if model_id is not None:
        if not db.query(SourceModel).filter(SourceModel.id == model_id).first():
            raise HTTPException(status_code=404, detail="Model not found")

    def _strip(val):
        """Strip surrounding quotes from a CSV field parsed with QUOTE_NONE."""
        if val is None:
            return ""
        v = val.strip()
        if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
            return v[1:-1]
        return v

    successful_inserts = 0
    failed_rows = []

    try:
        # NOTE: no escapechar — the source `rule_builder`/`Rule` fields contain
        # raw JSON with backslashes (e.g. Windows paths "C:\\Windows\\"). Using
        # a backslash escapechar would corrupt that JSON and make it unparseable.
        reader = csv.DictReader(
            codecs.iterdecode(file.file, "utf-8"),
            delimiter="|",
            quoting=csv.QUOTE_NONE,
        )
        line_num = 1
        for row in reader:
            line_num += 1
            rule_name = _strip(row.get("Rule Name"))
            rule_desc = _strip(row.get("Rule Desc"))
            severity = _strip(row.get("Severity"))
            created_by = _strip(row.get("Created By"))
            rule_builder_str = _strip(row.get("rule_builder"))
            rule_expr = _strip(row.get("Rule"))
            tactics = _strip(row.get("tactics", ""))
            technique = _strip(row.get("technique", ""))

            if not rule_name:
                failed_rows.append({"line": line_num, "reason": "Missing required field: Rule Name"})
                continue

            # Store the human-readable rule expression exactly as it appears in
            # the source `Rule` column. The source wraps literal values in
            # "^&@#^" markers (e.g. ^&@#^4688^&@#^); render those as spaces so
            # the stored/displayed rule looks like the sample, e.g.
            #   {( eventid =  4688  ) and ( process_name !~  C:\Windows\System32\  ... ) }
            rule_logic = (rule_expr or rule_builder_str or "").replace("^&@#^", " ")

            # Combine MITRE tactic and technique identifiers into tags.
            tags = [t.strip() for t in tactics.split(",") if t.strip()] if tactics else []
            if technique:
                tags += [t.strip() for t in technique.split(",") if t.strip()]
            sev = severity.lower() if severity else "medium"

            try:
                with db.begin_nested():
                    rule = CorrelationRule(
                        name=rule_name,
                        description=rule_desc,
                        rule_logic=rule_logic,
                        author=created_by or current_user.get("username", "Unknown"),
                        severity=sev,
                        tags=tags,
                    )
                    db.add(rule)
                    db.flush()
                    if model_id is not None:
                        db.add(ModelCorrelationMap(
                            source_model_id=model_id,
                            correlation_rule_id=rule.id,
                        ))
                successful_inserts += 1
            except IntegrityError as e:
                failed_rows.append({"line": line_num, "reason": f"Duplicate entry: {str(e.orig)}"})
            except Exception as e:
                failed_rows.append({"line": line_num, "reason": f"Database error: {str(e)}"})

        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to parse CSV file: {str(e)}",
        )

    return {
        "successful_inserts": successful_inserts,
        "failed_rows": failed_rows
    }

@app.get("/export/correlation-rules/csv")
async def export_correlation_rules_csv(
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db)
):
    rules = db.query(CorrelationRule).all()
    output = io.StringIO()
    headers = [
        "RuleID", "Rule Name", "Rule", "Rule Desc", "Severity", "Schedule", 
        "Alert Freq", "Weeks", "Status", "Organisations", "Scheduled From", 
        "Scheduled To", "Created On", "Created By", "rule_builder", "rule_type", 
        "rule_properties", "aggr_rule", "aggr_rule_builder", "user_org_group_id", 
        "sub_technique", "tactics", "technique", "alert_keys", "Compliance"
    ]
    
    writer = csv.writer(output, delimiter='|', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
    writer.writerow(headers)
    
    for r in rules:
        # rule_logic holds the human-readable rule expression. Older records may
        # still hold structured JSON; serialize those for the rule_builder column.
        if isinstance(r.rule_logic, (dict, list)):
            rule_expr = ""
            rule_builder_str = json.dumps(r.rule_logic)
        else:
            rule_expr = str(r.rule_logic) if r.rule_logic else ""
            rule_builder_str = ""

        tactics_str = ",".join(r.tags) if isinstance(r.tags, list) else ""

        row = [
            r.id,
            r.name or "",
            rule_expr,
            r.description or "",
            (r.severity or "medium").capitalize(),
            "0",
            "24",
            "",
            "Enabled",
            "2,3,4,5,6,7,8,9,10,15,17,18,19",
            "0",
            "0",
            r.created_at.strftime("%d-%m-%Y %H:%M:%S") if r.created_at else "",
            r.author or "1",
            rule_builder_str,
            "regular",
            "",
            "{}",
            '{"condition":"and","rules":[]}',
            "0",
            "",
            tactics_str,
            "",
            "null",
            "[]"
        ]
        writer.writerow(row)
        
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode('utf-8')),
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=correlation_rules_export.csv",
            "Content-Type": "text/csv"
        }
    )

@app.post("/import/parsers/text")
async def import_parsers_text(
    model_id: int,
    file: UploadFile = File(...),
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db)
):
    model = db.query(SourceModel).filter(SourceModel.id == model_id).first()
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")
        
    successful_inserts = 0
    failed_rows = []

    try:
        content = await file.read()
        lines = content.decode("utf-8").splitlines()

        line_num = 0
        parser_counts: dict = {}
        for line in lines:
            line_num += 1
            stripped = line.strip()
            if not stripped:
                continue

            parser_format = "kv"
            parser_config: dict = {}

            try:
                if stripped.startswith("CEF:"):
                    parser_format = "cef"
                    parser_config = json.loads(stripped[4:])
                elif stripped.startswith("JSON:"):
                    parser_format = "json"
                    parser_config = json.loads(stripped[5:])
                elif stripped.startswith("XML:"):
                    parser_format = "xml"
                    parser_config = json.loads(stripped[4:])
                elif stripped.startswith("<%"):
                    parser_format = "syslog_grok"
                    parser_config = {"pattern": stripped}
                else:
                    parser_format = "kv"
                    parser_config = {"pattern": stripped}

                parser_counts[parser_format] = parser_counts.get(parser_format, 0) + 1
                seq = parser_counts[parser_format]
                parser_name = f"Imported {parser_format.upper()} Parser" + (f" #{seq}" if seq > 1 else "")

                with db.begin_nested():
                    new_parser = Parser(
                        source_model_id=model_id,
                        name=parser_name,
                        format=parser_format,
                        parser_config=parser_config,
                        description=f"Imported from text file (line {line_num})",
                        is_active=True,
                    )
                    db.add(new_parser)
                successful_inserts += 1
            except json.JSONDecodeError as e:
                failed_rows.append({"line": line_num, "reason": f"Invalid JSON config: {str(e)}"})
            except Exception as e:
                failed_rows.append({"line": line_num, "reason": f"Insertion failed: {str(e)}"})

        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process text file: {str(e)}",
        )
        
    return {
        "successful_inserts": successful_inserts,
        "failed_rows": failed_rows
    }

@app.get("/export/parsers/text/{model_id}")
async def export_parsers_text(
    model_id: int,
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db)
):
    model = db.query(SourceModel).filter(SourceModel.id == model_id).first()
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")
        
    parsers = db.query(Parser).filter(Parser.source_model_id == model_id).all()
    
    lines = []
    for p in parsers:
        fmt = p.format.lower() if p.format else "kv"
        config = p.parser_config or {}
        
        if fmt == "cef":
            lines.append(f"CEF:{json.dumps(config)}")
        elif fmt == "json":
            lines.append(f"JSON:{json.dumps(config)}")
        elif fmt == "xml":
            lines.append(f"XML:{json.dumps(config)}")
        elif fmt == "syslog_grok":
            pattern = config.get("pattern", "")
            lines.append(pattern)
        else:
            pattern = config.get("pattern", "")
            lines.append(pattern)
            
    export_content = "\n".join(lines) + "\n"
    
    return Response(
        content=export_content,
        media_type="text/plain",
        headers={
            "Content-Disposition": f"attachment; filename=parsers_export_{model_id}.txt",
            "Content-Type": "text/plain"
        }
    )

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

@app.post("/import/soar-flows/file")
async def import_soar_flows_file(
    model_id: int,
    file: UploadFile = File(...),
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db)
):
    """Securely imports SOAR flows from an uploaded JSON file"""
    model = db.query(SourceModel).filter(SourceModel.id == model_id).first()
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")
        
    if not (file.filename or "").lower().endswith(".json"):
        raise HTTPException(status_code=400, detail="File must be a .json file")

    try:
        content = await file.read()
        data = json.loads(content.decode('utf-8'))
        
        # Unify format: ensure data is always a list to handle both playbook.json (dict) and soar_flows_import.json (list)
        if isinstance(data, dict):
            data = [data]
            
        successful_inserts = 0
        
        for item in data:
            # Handle schema differences: 
            # soar_flows_import.json has data nested in "workflow_json"
            # playbook.json has data at the root level
            if "workflow_json" in item:
                workflow_data = item["workflow_json"]
                name = item.get("name", workflow_data.get("name", "Imported Playbook"))
                desc = item.get("description", workflow_data.get("description", ""))
            else:
                workflow_data = item
                name = item.get("name", "Imported Playbook")
                desc = item.get("description", "")
                
            new_flow = SOARFlow(
                source_model_id=model_id,
                name=name,
                description=desc,
                workflow_json=workflow_data
            )
            db.add(new_flow)
            successful_inserts += 1
            
        db.commit()
        return {"successful_inserts": successful_inserts}
        
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON file format: {str(e)}")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to import SOAR flows: {str(e)}")

@app.get("/export/soar-flows/{model_id}")
async def export_soar_flows(
    model_id: int,
    current_user: dict = Depends(require_role("admin", "super_admin")),
    db: Session = Depends(get_db)
):
    """Exports all SOAR flows for a model into a downloadable JSON file"""
    flows = db.query(SOARFlow).filter(SOARFlow.source_model_id == model_id).all()
    
    export_data = []
    for flow in flows:
        export_data.append({
            "name": flow.name,
            "description": flow.description,
            "workflow_json": flow.workflow_json
        })
        
    return Response(
        content=json.dumps(export_data, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=soar_flows_export_model_{model_id}.json",
            "Content-Type": "application/json"
        }
    )

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
