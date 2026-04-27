"""Backend API tests."""

import pytest
from httpx import AsyncClient
from unittest.mock import patch, AsyncMock

# Tests for database connection
@pytest.mark.asyncio
async def test_database_connection():
    """Test database connection configuration."""
    from app.database.connection import MongoDBConnection
    
    # Verify settings are loaded
    from app.config import settings
    assert settings.mongodb_url
    assert settings.database_name == "securehub"



# Tests for models
def test_user_model_validation():
    """Test user model validation."""
    from app.models.db_models import User, UserTier
    
    user = User(
        email="test@example.com",
        password_hash="hashed_password",
        tier=UserTier.FREE,
    )
    
    assert user.email == "test@example.com"
    assert user.tier == UserTier.FREE
    assert user.is_active == True


def test_scan_model():
    """Test scan model."""
    from app.models.db_models import Scan, ScanStatus, ScanSummary
    
    summary = ScanSummary(
        total_issues=5,
        critical=1,
        high=2,
        medium=2,
        low=0,
    )
    
    scan = Scan(
        user_id="user123",
        project_name="test-repo",
        status=ScanStatus.COMPLETED,
        summary=summary,
    )
    
    assert scan.project_name == "test-repo"
    assert scan.status == ScanStatus.COMPLETED
    assert scan.summary.total_issues == 5


def test_finding_model():
    """Test finding model."""
    from app.models.db_models import Finding, SeverityLevel, DetectionMethod
    
    finding = Finding(
        scan_id="scan123",
        issue_id="SH-001-1234",
        vulnerability_type="SQLi",
        severity=SeverityLevel.HIGH,
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        file_path="app/routes.py",
        line_number=42,
        code_snippet="query = 'SELECT * FROM users WHERE id = ' + user_input",
        description="SQL Injection vulnerability",
        impact="Database compromise",
        detection_method=DetectionMethod.AST,
        confidence=0.95,
        priority_score=85.0,
    )
    
    assert finding.vulnerability_type == "SQLi"
    assert finding.severity == SeverityLevel.HIGH
    assert finding.confidence == 0.95


# Tests for configuration
def test_config_loading():
    """Test configuration loading."""
    from app.config import settings
    
    assert settings.jwt_algorithm == "HS256"
    assert settings.access_token_expire_hours == 24
    assert settings.rate_limit_requests == 100


# Tests for API routes
@pytest.mark.asyncio
async def test_root_endpoint():
    """Test root API endpoint."""
    from app.main import app
    from fastapi.testclient import TestClient
    
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "SecureHub IntelliScan API"


@pytest.mark.asyncio
async def test_health_endpoint():
    """Test health check endpoint."""
    from app.main import app
    from fastapi.testclient import TestClient
    
    with patch('app.database.connection.MongoDBConnection.health_check', new_callable=AsyncMock) as mock_health:
        mock_health.return_value = True
        
        client = TestClient(app)
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data


# Tests for authentication models
def test_user_registration_validation():
    """Test user registration password validation."""
    from app.models.db_models import UserRegister
    import pytest
    
    # Valid password
    user = UserRegister(
        email="test@example.com",
        password="ValidP@ss123456",
        agree_to_terms=True,
    )
    assert user.email == "test@example.com"
    
    # Invalid password (too short)
    with pytest.raises(Exception):
        UserRegister(
            email="test@example.com",
            password="Short1!",
            agree_to_terms=True,
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--asyncio-mode=auto"])
