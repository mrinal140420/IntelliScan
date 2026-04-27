"""ML model tests for vulnerability detection."""

import pytest
from unittest.mock import Mock, patch
import sys
import os

# Add ml directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from models.detectors import CodeBERTDetector, GraphCodeBERTDetector, EnsembleVulnerabilityDetector


class TestCodeBERTDetector:
    """Test CodeBERT model functionality."""

    @pytest.fixture
    def detector(self):
        """Create detector instance with mocked model."""
        with patch('models.detectors.AutoTokenizer.from_pretrained'):
            with patch('models.detectors.AutoModelForSequenceClassification.from_pretrained'):
                return CodeBERTDetector()

    def test_initialization(self, detector):
        """Test detector initialization."""
        assert detector.model_name == "microsoft/codebert-base"
        assert detector.labels == ["safe", "suspicious", "vulnerable"]
        assert detector.device in ["cpu", "cuda"]

    def test_labels_exist(self, detector):
        """Test that labels are properly defined."""
        assert len(detector.labels) == 3
        assert "vulnerable" in detector.labels


class TestGraphCodeBERTDetector:
    """Test GraphCodeBERT model functionality."""

    @pytest.fixture
    def detector(self):
        """Create detector instance with mocked model."""
        with patch('models.detectors.AutoTokenizer.from_pretrained'):
            with patch('models.detectors.AutoModelForSequenceClassification.from_pretrained'):
                return GraphCodeBERTDetector()

    def test_initialization(self, detector):
        """Test detector initialization."""
        assert detector.model_name == "microsoft/graphcodebert-base"

    def test_sensitive_operations_detection(self, detector):
        """Test detection of sensitive operations."""
        code_with_sql = "result = cursor.execute('SELECT * FROM users')"
        result = detector.detect_sensitive_operations(code_with_sql)

        assert result["operation_count"] > 0
        assert "SQL_QUERY" in result["sensitive_operations"]

    def test_no_sensitive_operations(self, detector):
        """Test code without sensitive operations."""
        safe_code = "x = 5\ny = x + 10\nprint(y)"
        result = detector.detect_sensitive_operations(safe_code)

        assert result["operation_count"] == 0
        assert len(result["sensitive_operations"]) == 0


class TestEnsembleDetector:
    """Test ensemble vulnerability detector."""

    @pytest.fixture
    def ensemble(self):
        """Create ensemble detector with mocked models."""
        with patch('models.detectors.CodeBERTDetector'):
            with patch('models.detectors.GraphCodeBERTDetector'):
                detector = EnsembleVulnerabilityDetector()
                # Mock the model instances
                detector.codebert = Mock()
                detector.graphcodebert = Mock()
                return detector

    def test_ensemble_initialization(self, ensemble):
        """Test ensemble initialization."""
        assert ensemble.decision_threshold == 0.7
        assert "codebert" in ensemble.weights
        assert "graphcodebert" in ensemble.weights

    def test_weights_sum(self, ensemble):
        """Test that weights sum to 1."""
        total_weight = sum(ensemble.weights.values())
        assert abs(total_weight - 1.0) < 0.01

    def test_score_to_severity_critical(self, ensemble):
        """Test severity classification - critical."""
        severity = ensemble._score_to_severity(0.9)
        assert severity == "critical"

    def test_score_to_severity_high(self, ensemble):
        """Test severity classification - high."""
        severity = ensemble._score_to_severity(0.7)
        assert severity == "high"

    def test_score_to_severity_medium(self, ensemble):
        """Test severity classification - medium."""
        severity = ensemble._score_to_severity(0.5)
        assert severity == "medium"

    def test_score_to_severity_low(self, ensemble):
        """Test severity classification - low."""
        severity = ensemble._score_to_severity(0.3)
        assert severity == "low"

    def test_score_to_severity_info(self, ensemble):
        """Test severity classification - info."""
        severity = ensemble._score_to_severity(0.1)
        assert severity == "info"

    def test_ensemble_prediction_structure(self, ensemble):
        """Test ensemble prediction returns correct structure."""
        # Mock model results
        ensemble.codebert.predict.return_value = {
            "scores": {"vulnerable": 0.8, "suspicious": 0.15, "safe": 0.05}
        }
        ensemble.graphcodebert.detect_sensitive_operations.return_value = {
            "operation_count": 1,
            "sensitive_operations": ["SQL_QUERY"]
        }

        result = ensemble.predict("SELECT * FROM users WHERE id = " + str(1))

        # Check structure
        assert "is_vulnerable" in result
        assert "ensemble_score" in result
        assert "severity" in result
        assert "confidence" in result
        assert "model_scores" in result


class TestVulnerabilityDetectionExamples:
    """Test with realistic vulnerability examples."""

    @pytest.fixture
    def ensemble(self):
        """Create ensemble detector with mocked models."""
        with patch('models.detectors.CodeBERTDetector'):
            with patch('models.detectors.GraphCodeBERTDetector'):
                detector = EnsembleVulnerabilityDetector()
                detector.codebert = Mock()
                detector.graphcodebert = Mock()
                return detector

    def test_sql_injection_detection(self, ensemble):
        """Test SQL injection pattern detection."""
        sql_injection_code = """
        user_id = request.GET.get('id')
        query = "SELECT * FROM users WHERE id = " + user_id
        cursor.execute(query)
        """

        ensemble.codebert.predict.return_value = {
            "scores": {"vulnerable": 0.92, "suspicious": 0.07, "safe": 0.01}
        }
        ensemble.graphcodebert.detect_sensitive_operations.return_value = {
            "operation_count": 2,
            "sensitive_operations": ["SQL_QUERY", "FILE_OPERATION"]
        }

        result = ensemble.predict(sql_injection_code, rule_score=0.95)

        assert result["is_vulnerable"] == True
        assert result["ensemble_score"] > 0.7
        assert "critical" in result["severity"] or "high" in result["severity"]

    def test_hardcoded_secret_detection(self, ensemble):
        """Test hardcoded credential detection."""
        hardcoded_secret_code = """
        api_key = "AKIA2I7Q3XXXXXXXXXXX"
        password = "SecureP@ssw0rd123"
        token = "ghp_XXXXXXXXXXXXXXXXXXXXXX"
        """

        ensemble.codebert.predict.return_value = {
            "scores": {"vulnerable": 0.85, "suspicious": 0.12, "safe": 0.03}
        }
        ensemble.graphcodebert.detect_sensitive_operations.return_value = {
            "operation_count": 0,
            "sensitive_operations": []
        }

        result = ensemble.predict(hardcoded_secret_code, rule_score=0.98)

        assert result["is_vulnerable"] == True
        assert result["ensemble_score"] > 0.7

    def test_safe_code_detection(self, ensemble):
        """Test that safe code is not flagged."""
        safe_code = """
        def calculate_sum(a, b):
            return a + b
        
        result = calculate_sum(5, 10)
        print(result)
        """

        ensemble.codebert.predict.return_value = {
            "scores": {"vulnerable": 0.02, "suspicious": 0.08, "safe": 0.90}
        }
        ensemble.graphcodebert.detect_sensitive_operations.return_value = {
            "operation_count": 0,
            "sensitive_operations": []
        }

        result = ensemble.predict(safe_code, rule_score=0.05)

        assert result["is_vulnerable"] == False
        assert result["ensemble_score"] < 0.7
        assert result["severity"] == "info"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=models"])
