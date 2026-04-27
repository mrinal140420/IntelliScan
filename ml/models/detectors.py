"""ML Model handlers for vulnerability detection using CodeBERT and GraphCodeBERT."""

import logging
import numpy as np
from typing import Dict, List, Tuple, Any, Optional
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

logger = logging.getLogger(__name__)


class CodeBERTDetector:
    """CodeBERT-based vulnerability detection model."""

    def __init__(self, model_name: str = "microsoft/codebert-base", use_gpu: bool = False):
        """
        Initialize CodeBERT model for code classification.

        Args:
            model_name: HuggingFace model identifier
            use_gpu: Whether to use GPU for inference
        """
        self.model_name = model_name
        self.device = "cuda" if use_gpu and torch.cuda.is_available() else "cpu"
        self.use_gpu = use_gpu and torch.cuda.is_available()

        logger.info(f"Loading CodeBERT model: {model_name} on device: {self.device}")

        try:
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(model_name)
            self.model.to(self.device)
            self.model.eval()
            logger.info("CodeBERT model loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load CodeBERT model: {str(e)}")
            raise

        # Classification labels
        self.labels = ["safe", "suspicious", "vulnerable"]

    def predict(self, code_snippet: str, max_length: int = 512) -> Dict[str, Any]:
        """
        Predict vulnerability risk for code snippet.

        Args:
            code_snippet: Code to analyze (max 512 tokens)
            max_length: Maximum token length

        Returns:
            Dict with prediction, confidence, and scores
        """
        try:
            # Tokenize
            inputs = self.tokenizer(
                code_snippet,
                truncation=True,
                max_length=max_length,
                padding=True,
                return_tensors="pt",
            )

            # Move inputs to device
            inputs = {key: val.to(self.device) for key, val in inputs.items()}

            # Inference
            with torch.no_grad():
                outputs = self.model(**inputs)
                logits = outputs.logits
                probabilities = torch.softmax(logits, dim=1)[0].cpu().numpy()

            # Get prediction
            predicted_class = np.argmax(probabilities)
            predicted_label = self.labels[predicted_class]
            confidence = float(probabilities[predicted_class])

            return {
                "prediction": predicted_label,
                "confidence": confidence,
                "scores": {
                    label: float(score) for label, score in zip(self.labels, probabilities)
                },
                "is_vulnerable": predicted_label == "vulnerable",
                "is_suspicious": predicted_label == "suspicious",
            }

        except Exception as e:
            logger.error(f"Prediction failed: {str(e)}")
            return {
                "prediction": "error",
                "confidence": 0.0,
                "error": str(e),
                "is_vulnerable": False,
            }

    def batch_predict(self, code_snippets: List[str]) -> List[Dict[str, Any]]:
        """
        Batch predict multiple code snippets.

        Args:
            code_snippets: List of code snippets

        Returns:
            List of predictions
        """
        logger.info(f"Running batch prediction on {len(code_snippets)} snippets")
        return [self.predict(snippet) for snippet in code_snippets]


class GraphCodeBERTDetector:
    """GraphCodeBERT-based data flow and taint analysis."""

    def __init__(self, model_name: str = "microsoft/graphcodebert-base", use_gpu: bool = False):
        """
        Initialize GraphCodeBERT model for data flow analysis.

        Args:
            model_name: HuggingFace model identifier
            use_gpu: Whether to use GPU for inference
        """
        self.model_name = model_name
        self.device = "cuda" if use_gpu and torch.cuda.is_available() else "cpu"
        self.use_gpu = use_gpu and torch.cuda.is_available()

        logger.info(f"Loading GraphCodeBERT model: {model_name} on device: {self.device}")

        try:
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(model_name)
            self.model.to(self.device)
            self.model.eval()
            logger.info("GraphCodeBERT model loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load GraphCodeBERT model: {str(e)}")
            raise

    def detect_taint_flow(self, source: str, sink: str, intermediate_code: str) -> Dict[str, Any]:
        """
        Detect if tainted data flows from source to sink.

        Args:
            source: Source of user input
            sink: Potentially dangerous operation
            intermediate_code: Code between source and sink

        Returns:
            Dict with taint flow analysis results
        """
        try:
            # Create input combining source, code, and sink
            combined_input = f"{source} {intermediate_code} {sink}"

            inputs = self.tokenizer(
                combined_input,
                truncation=True,
                max_length=512,
                padding=True,
                return_tensors="pt",
            )

            inputs = {key: val.to(self.device) for key, val in inputs.items()}

            with torch.no_grad():
                outputs = self.model(**inputs)
                logits = outputs.logits
                probabilities = torch.softmax(logits, dim=1)[0].cpu().numpy()

            # Binary classification: taint flows (1) or not (0)
            has_taint_flow = probabilities[1] > 0.5
            confidence = float(probabilities[1])

            return {
                "has_taint_flow": bool(has_taint_flow),
                "confidence": confidence,
                "risk_score": float(confidence) if has_taint_flow else 0.0,
            }

        except Exception as e:
            logger.error(f"Taint analysis failed: {str(e)}")
            return {"has_taint_flow": False, "confidence": 0.0, "error": str(e)}

    def detect_sensitive_operations(self, code_snippet: str) -> Dict[str, Any]:
        """
        Identify sensitive operations in code.

        Args:
            code_snippet: Code to analyze

        Returns:
            Dict with detected sensitive operations
        """
        import re
        
        sensitive_patterns = [
            ("SQL_QUERY", r"\b(select|insert|update|delete|from|where)\b"),
            ("FILE_OPERATION", r"\b(open|read|write|delete|os\.path)\b"),
            ("CRYPTO_OP", r"\b(encrypt|decrypt|hash|cipher|hashlib)\b"),
            ("SHELL_COMMAND", r"\b(exec|system|subprocess|shell|os\.system)\b"),
        ]

        detected_operations = []
        code_lower = code_snippet.lower()
        
        for op_name, pattern in sensitive_patterns:
            if re.search(pattern, code_lower, re.IGNORECASE):
                detected_operations.append(op_name)

        return {
            "sensitive_operations": detected_operations,
            "operation_count": len(detected_operations),
        }


class EnsembleVulnerabilityDetector:
    """Ensemble voting system combining multiple models."""

    def __init__(self, use_gpu: bool = False):
        """Initialize ensemble with CodeBERT and GraphCodeBERT."""
        self.use_gpu = use_gpu
        self.codebert = CodeBERTDetector(use_gpu=use_gpu)
        self.graphcodebert = GraphCodeBERTDetector(use_gpu=use_gpu)

        # Ensemble weights
        self.weights = {
            "codebert": 0.4,
            "graphcodebert": 0.3,
            "rule_based": 0.2,
            "taint_analysis": 0.1,
        }

        self.decision_threshold = 0.7

    def predict(self, code_snippet: str, rule_score: float = 0.0) -> Dict[str, Any]:
        """
        Ensemble prediction combining multiple models.

        Args:
            code_snippet: Code to analyze
            rule_score: Score from rule-based detection (0-1)

        Returns:
            Ensemble prediction result
        """
        logger.info("Running ensemble vulnerability detection")

        # CodeBERT prediction
        codebert_result = self.codebert.predict(code_snippet)
        codebert_score = codebert_result["scores"].get("vulnerable", 0.0)

        # GraphCodeBERT taint analysis
        graphcodebert_result = self.graphcodebert.detect_sensitive_operations(code_snippet)
        graphcodebert_score = 0.5 if graphcodebert_result["operation_count"] > 0 else 0.0

        # Weighted ensemble with boost for high rule scores
        ensemble_score = (
            self.weights["codebert"] * codebert_score
            + self.weights["graphcodebert"] * graphcodebert_score
            + self.weights["rule_based"] * rule_score
            + self.weights["taint_analysis"] * rule_score
        )
        
        # Boost score if rule_score is very high (strong indicator)
        if rule_score >= 0.9:
            ensemble_score = max(ensemble_score, 0.75)

        # Decision
        is_vulnerable = ensemble_score >= self.decision_threshold
        severity = self._score_to_severity(ensemble_score)

        return {
            "is_vulnerable": is_vulnerable,
            "ensemble_score": float(ensemble_score),
            "threshold": self.decision_threshold,
            "severity": severity,
            "confidence": float(ensemble_score),
            "model_scores": {
                "codebert": float(codebert_score),
                "graphcodebert": float(graphcodebert_score),
                "rule_based": float(rule_score),
            },
            "codebert_details": codebert_result,
            "sensitive_operations": graphcodebert_result["sensitive_operations"],
        }

    @staticmethod
    def _score_to_severity(score: float) -> str:
        """Convert numerical score to severity level."""
        if score >= 0.8:
            return "critical"
        elif score >= 0.6:
            return "high"
        elif score >= 0.4:
            return "medium"
        elif score >= 0.2:
            return "low"
        else:
            return "info"
