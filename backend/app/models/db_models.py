"""MongoDB data models using Pydantic for validation and serialization."""

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, EmailStr, validator
from enum import Enum
from uuid import uuid4


class UserTier(str, Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class ScanStatus(str, Enum):
    QUEUED = "queued"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DetectionMethod(str, Enum):
    REGEX = "regex"
    AST = "ast"
    ML = "ml"
    DEPENDENCY = "dependency"
    SECRET = "secret"
    TAINT = "taint"


# ===================== User Models =====================


class UserRegister(BaseModel):
    """User registration request."""

    email: EmailStr
    password: str
    company_name: Optional[str] = None
    industry: Optional[str] = None
    agree_to_terms: bool

    @validator("password")
    def validate_password(cls, v):
        """Enforce password requirements: min 12 chars, uppercase, lowercase, number, special."""
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        if not any(c in "!@#$%^&*" for c in v):
            raise ValueError("Password must contain at least one special character")
        return v


class APIKeyModel(BaseModel):
    """API Key model - embedded in User."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    key_hash: str  # SHA-256 hash of key
    name: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_used_at: Optional[datetime] = None
    expires_at: datetime
    is_active: bool = True


class User(BaseModel):
    """User model - primary collection."""

    id: str = Field(default_factory=lambda: str(uuid4()), alias="_id")
    email: str
    password_hash: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    company_name: Optional[str] = None
    industry: Optional[str] = None
    tier: UserTier = UserTier.FREE
    
    # External tokens (encrypted in real implementation)
    github_token: Optional[str] = None
    gitlab_token: Optional[str] = None
    bitbucket_token: Optional[str] = None
    
    # MFA
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = None  # Encrypted
    
    # Status
    is_active: bool = True
    last_login_at: Optional[datetime] = None
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        populate_by_name = True


# ===================== Finding Models =====================


class Finding(BaseModel):
    """Security finding/vulnerability - referenced in Scan."""

    id: str = Field(default_factory=lambda: str(uuid4()), alias="_id")
    scan_id: str  # Reference to scan
    issue_id: str  # e.g., "SH-001-1234"
    
    # Vulnerability Details
    vulnerability_type: str  # e.g., "SQLi", "XSS", "HardcodedSecret"
    severity: SeverityLevel
    cvss_score: float = Field(ge=0, le=10)
    cvss_vector: str
    cwe_id: Optional[int] = None
    cwe_name: Optional[str] = None
    
    # Location
    file_path: str
    line_number: int
    column_number: Optional[int] = None
    code_snippet: str
    
    # Description & Impact
    description: str
    impact: str
    
    # Compliance
    owasp_category: Optional[str] = None
    owasp_number: Optional[str] = None
    pci_dss_relevant: bool = False
    hipaa_relevant: bool = False
    
    # Detection
    detection_method: DetectionMethod
    confidence: float = Field(ge=0, le=1)
    false_positive_likelihood: Optional[str] = None
    
    # Remediation
    remediation_guidance: Optional[str] = None
    remediation_code: Optional[str] = None
    remediation_effort: Optional[str] = None
    priority_score: float = Field(ge=0, le=100)
    
    # False Positive Tracking
    is_false_positive: bool = False
    fp_marked_by: Optional[str] = None
    fp_marked_at: Optional[datetime] = None
    
    # Timestamp
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        populate_by_name = True


# ===================== Scan Models =====================


class ScanSummary(BaseModel):
    """Embedded summary in Scan document."""

    total_issues: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    files_scanned: int = 0
    lines_analyzed: int = 0


class Scan(BaseModel):
    """Scan model - primary collection."""

    id: str = Field(default_factory=lambda: str(uuid4()), alias="_id")
    user_id: str  # Reference to user
    project_name: str
    
    # Repository
    repo_url: Optional[str] = None
    repo_provider: Optional[str] = None  # github, gitlab, bitbucket, zip, snippet
    branch: Optional[str] = None
    
    # Scan Status
    status: ScanStatus = ScanStatus.QUEUED
    progress: int = Field(default=0, ge=0, le=100)
    current_step: Optional[str] = None
    
    # Results
    security_score: Optional[int] = None
    risk_level: Optional[SeverityLevel] = None
    summary: ScanSummary = Field(default_factory=ScanSummary)
    
    # Execution
    duration_seconds: Optional[int] = None
    error_message: Optional[str] = None
    celery_task_id: Optional[str] = None
    
    # Storage
    s3_report_path: Optional[str] = None
    finding_ids: List[str] = []  # References to findings
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    class Config:
        populate_by_name = True


# ===================== API Response Models =====================


class ScanResponse(BaseModel):
    """API response for scan details."""

    scan_id: str
    project_name: str
    status: ScanStatus
    progress: int
    security_score: Optional[int]
    risk_level: Optional[SeverityLevel]
    summary: ScanSummary
    findings: List[Finding] = []
    created_at: datetime
    completed_at: Optional[datetime]


class FindingResponse(BaseModel):
    """API response for findings."""

    issue_id: str
    vulnerability_type: str
    severity: SeverityLevel
    cvss_score: float
    file_path: str
    line_number: int
    description: str
    remediation_guidance: Optional[str]
    priority_score: float


# ===================== Audit Log Models =====================


class AuditLog(BaseModel):
    """Audit log - separate collection for compliance."""

    id: str = Field(default_factory=lambda: str(uuid4()), alias="_id")
    user_id: Optional[str] = None
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    status: str  # success, failure
    error_details: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        populate_by_name = True
