"""
Database models for Cybersecurity Intelligence Dashboard
Implements MITRE ATT&CK / NIST framework mapping with detection engineering artifacts
"""

from datetime import datetime
from enum import Enum
from sqlalchemy import (
    create_engine, Column, Integer, String, Text, DateTime, 
    ForeignKey, Table, Boolean, UniqueConstraint, Index, JSON
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

# ============================================================================
# ENUMS
# ============================================================================

class RoleEnum(str, Enum):
    ANALYST = "analyst"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"

class FrameworkEnum(str, Enum):
    MITRE = "mitre"
    NIST = "nist"

class ParserFormatEnum(str, Enum):
    KV = "kv"
    JSON = "json"
    GROK = "grok"
    CSV = "csv"
    CEF = "cef"
    XML = "xml"

# ============================================================================
# AUTH & ACCESS CONTROL
# ============================================================================

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True)
    username = Column(String(255), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)  # bcrypt/argon2
    role = Column(String(20), default=RoleEnum.ANALYST, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_user_username', 'username'),
    )

# ============================================================================
# FRAMEWORK LAYER
# ============================================================================

class Framework(Base):
    __tablename__ = "frameworks"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True, nullable=False)  # "mitre" or "nist"
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    vectors = relationship("FrameworkVector", back_populates="framework", cascade="all, delete-orphan")
    
    __table_args__ = (
        Index('idx_framework_name', 'name'),
    )

class FrameworkVector(Base):
    """
    Represents tactics (MITRE) or functions (NIST)
    """
    __tablename__ = "framework_vectors"
    
    id = Column(Integer, primary_key=True)
    framework_id = Column(Integer, ForeignKey('frameworks.id'), nullable=False)
    external_id = Column(String(100), nullable=False)  # e.g., "TA0001", "ID.AM"
    name = Column(String(255), nullable=False)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    framework = relationship("Framework", back_populates="vectors")
    model_mappings = relationship("ModelFrameworkMap", back_populates="framework_vector", cascade="all, delete-orphan")
    
    __table_args__ = (
        UniqueConstraint('framework_id', 'external_id', name='uq_framework_vector'),
        Index('idx_framework_vector_framework', 'framework_id'),
    )

# ============================================================================
# SOURCE LAYER (CORE IDENTITY)
# ============================================================================

class SourceType(Base):
    """server, firewall, endpoint, etc."""
    __tablename__ = "source_types"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    source_models = relationship("SourceModel", back_populates="source_type", cascade="all, delete-orphan")
    
    __table_args__ = (
        Index('idx_source_type_name', 'name'),
    )

class Brand(Base):
    """Microsoft, Palo Alto, Cisco, etc."""
    __tablename__ = "brands"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    source_models = relationship("SourceModel", back_populates="brand", cascade="all, delete-orphan")
    
    __table_args__ = (
        Index('idx_brand_name', 'name'),
    )

class SourceModel(Base):
    """
    CORE IDENTITY: (source_type_id, brand_id, model_name) uniquely identifies a source
    
    Examples:
    - server, Microsoft, Windows Server 2022
    - firewall, Palo Alto, PA-5220
    - endpoint, CrowdStrike, Falcon
    """
    __tablename__ = "source_models"
    
    id = Column(Integer, primary_key=True)
    source_type_id = Column(Integer, ForeignKey('source_types.id'), nullable=False)
    brand_id = Column(Integer, ForeignKey('brands.id'), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    source_type = relationship("SourceType", back_populates="source_models")
    brand = relationship("Brand", back_populates="source_models")
    framework_mappings = relationship("ModelFrameworkMap", back_populates="source_model", cascade="all, delete-orphan")
    parsers = relationship("Parser", back_populates="source_model", cascade="all, delete-orphan")
    soar_flows = relationship("SOARFlow", back_populates="source_model", cascade="all, delete-orphan")
    correlation_mappings = relationship("ModelCorrelationMap", back_populates="source_model", cascade="all, delete-orphan")
    highlights = relationship("Highlight", back_populates="source_model", cascade="all, delete-orphan")
    
    __table_args__ = (
        UniqueConstraint('source_type_id', 'brand_id', 'name', name='uq_source_model_identity'),
        Index('idx_source_model_source_type', 'source_type_id'),
        Index('idx_source_model_brand', 'brand_id'),
    )

# ============================================================================
# MAPPING LAYER (CORE LOGIC)
# ============================================================================

class ModelFrameworkMap(Base):
    """
    Many-to-many mapping: one source_model → multiple framework_vectors
                        one framework_vector → multiple source_models
    """
    __tablename__ = "model_framework_map"
    
    id = Column(Integer, primary_key=True)
    source_model_id = Column(Integer, ForeignKey('source_models.id'), nullable=False)
    framework_vector_id = Column(Integer, ForeignKey('framework_vectors.id'), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    source_model = relationship("SourceModel", back_populates="framework_mappings")
    framework_vector = relationship("FrameworkVector", back_populates="model_mappings")
    
    __table_args__ = (
        UniqueConstraint('source_model_id', 'framework_vector_id', name='uq_model_framework'),
        Index('idx_model_framework_source', 'source_model_id'),
        Index('idx_model_framework_vector', 'framework_vector_id'),
    )

# ============================================================================
# DETECTION ENGINEERING LAYER
# ============================================================================

class CorrelationRule(Base):
    """
    Reusable correlation rules stored once and mapped to multiple models
    """
    __tablename__ = "correlation_rules"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text)
    rule_logic = Column(Text, nullable=False)  # JSON or expression
    author = Column(String(255))
    severity = Column(String(50))  # critical, high, medium, low
    tags = Column(JSON)  # Array of tags for categorization
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    model_mappings = relationship("ModelCorrelationMap", back_populates="correlation_rule", cascade="all, delete-orphan")
    
    __table_args__ = (
        Index('idx_correlation_rule_name', 'name'),
    )

class ModelCorrelationMap(Base):
    """
    Many-to-many mapping: correlation_rules ↔ source_models
    Enables reuse: one rule → multiple models, one model → multiple rules
    """
    __tablename__ = "model_correlation_map"
    
    id = Column(Integer, primary_key=True)
    source_model_id = Column(Integer, ForeignKey('source_models.id'), nullable=False)
    correlation_rule_id = Column(Integer, ForeignKey('correlation_rules.id'), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    source_model = relationship("SourceModel", back_populates="correlation_mappings")
    correlation_rule = relationship("CorrelationRule", back_populates="model_mappings")
    
    __table_args__ = (
        UniqueConstraint('source_model_id', 'correlation_rule_id', name='uq_model_correlation'),
        Index('idx_model_correlation_source', 'source_model_id'),
        Index('idx_model_correlation_rule', 'correlation_rule_id'),
    )

class Parser(Base):
    """
    Model-specific parsers for different formats
    """
    __tablename__ = "parsers"
    
    id = Column(Integer, primary_key=True)
    source_model_id = Column(Integer, ForeignKey('source_models.id'), nullable=False)
    name = Column(String(255), nullable=False)
    format = Column(String(20), nullable=False)  # kv, json, grok, csv, cef, xml
    parser_config = Column(JSON, nullable=False)  # Format-specific configuration
    description = Column(Text)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    source_model = relationship("SourceModel", back_populates="parsers")
    
    __table_args__ = (
        Index('idx_parser_source_model', 'source_model_id'),
        Index('idx_parser_format', 'format'),
    )

class SOARFlow(Base):
    """
    Model-specific SOAR workflows
    """
    __tablename__ = "soar_flows"
    
    id = Column(Integer, primary_key=True)
    source_model_id = Column(Integer, ForeignKey('source_models.id'), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    workflow_json = Column(JSON, nullable=False)  # Stored as JSON
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    source_model = relationship("SourceModel", back_populates="soar_flows")
    
    __table_args__ = (
        Index('idx_soar_source_model', 'source_model_id'),
    )

# ============================================================================
# STATIC INTELLIGENCE LAYER (Read-heavy, restricted modification)
# ============================================================================

class Compliance(Base):
    """
    Compliance frameworks (PCI-DSS, HIPAA, SOC2, etc.)
    Modified only by super_admin
    """
    __tablename__ = "compliances"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    requirements = Column(JSON)  # Array of compliance requirements
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class AttackVector(Base):
    """
    Attack vectors and threat scenarios
    Modified only by super_admin
    """
    __tablename__ = "attack_vectors"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True, nullable=False)
    description = Column(Text)
    category = Column(String(100))
    severity = Column(String(50))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Highlight(Base):
    """
    Security highlights and findings
    Modified only by super_admin
    """
    __tablename__ = "highlights"
    
    id = Column(Integer, primary_key=True)
    source_model_id = Column(Integer, ForeignKey('source_models.id'), nullable=True)
    title = Column(String(255), nullable=False)
    content = Column(Text)
    priority = Column(String(50))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    source_model = relationship("SourceModel", back_populates="highlights")

# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

def init_db(database_url="sqlite:///cybersec_dashboard.db"):
    """Initialize database and create tables"""
    engine = create_engine(database_url)
    Base.metadata.create_all(engine)
    return engine
