"""Code scanning service using ML models."""

import os
import sys
import zipfile
import tempfile
from pathlib import Path
from typing import List, Dict, Any
import logging

# Add project root to path so we can import ml module
# From backend/app/services/scan_service.py -> go up 3 levels to project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../'))

logger = logging.getLogger(__name__)


class ScanService:
    """Service to process code files and extract vulnerabilities."""

    _detector = None

    # Supported code file extensions
    SUPPORTED_EXTENSIONS = {
        '.py', '.js', '.ts', '.java', '.cpp', '.c', '.cs', '.go',
        '.rb', '.php', '.swift', '.kotlin', '.scala', '.rs',
        '.sql', '.html', '.xml', '.json', '.yaml', '.yml'
    }

    @staticmethod
    def extract_code_from_files(file_path: str) -> List[Dict[str, str]]:
        """
        Extract code from uploaded ZIP, directory, or process single file.
        
        Args:
            file_path: Path to ZIP file, directory, or code file
            
        Returns:
            List of dicts with 'filename' and 'content' keys
        """
        code_files = []

        if os.path.isdir(file_path):
            # Handle directory (e.g., cloned Git repository)
            logger.info(f"Processing directory: {file_path}")
            for root, dirs, files in os.walk(file_path):
                # Skip common non-code directories
                dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '.venv', 'venv', '__pycache__', '.pytest_cache', '.vscode', 'dist', 'build'}]
                
                for file in files:
                    file_full_path = os.path.join(root, file)
                    file_ext = Path(file_full_path).suffix.lower()

                    # Check if file is a supported code file
                    if file_ext in ScanService.SUPPORTED_EXTENSIONS:
                        try:
                            with open(file_full_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                # Only include files with content > 10 chars
                                if len(content.strip()) > 10:
                                    relative_path = os.path.relpath(file_full_path, file_path)
                                    code_files.append({
                                        'filename': relative_path,
                                        'content': content
                                    })
                        except Exception as e:
                            logger.warning(f"Failed to read {file_full_path}: {str(e)}")

        elif file_path.endswith('.zip'):
            # Extract ZIP file
            with tempfile.TemporaryDirectory() as temp_dir:
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)

                # Scan all files in extracted directory
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        file_full_path = os.path.join(root, file)
                        file_ext = Path(file_full_path).suffix.lower()

                        # Check if file is a supported code file
                        if file_ext in ScanService.SUPPORTED_EXTENSIONS:
                            try:
                                with open(file_full_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                    # Only include files with content > 10 chars
                                    if len(content.strip()) > 10:
                                        relative_path = os.path.relpath(file_full_path, temp_dir)
                                        code_files.append({
                                            'filename': relative_path,
                                            'content': content
                                        })
                            except Exception as e:
                                logger.warning(f"Failed to read {file_full_path}: {str(e)}")
        else:
            # Single file
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if len(content.strip()) > 10:
                        code_files.append({
                            'filename': Path(file_path).name,
                            'content': content
                        })
            except Exception as e:
                logger.error(f"Failed to read {file_path}: {str(e)}")

        return code_files

    @staticmethod
    def analyze_code(code_content: str, filename: str) -> Dict[str, Any]:
        """
        Analyze code for vulnerabilities using hybrid detection (regex + AST + TF-IDF).
        
        No runtime model downloads. CPU-efficient. Instant analysis.
        
        Args:
            code_content: Raw code content to analyze
            filename: Name of the file being analyzed
            
        Returns:
            Dictionary with findings
        """
        try:
            from ml.models.hybrid_detector import HybridVulnerabilityDetector
        except ImportError as e:
            logger.error(f"Hybrid detector not available: {str(e)}")
            return {
                'filename': filename,
                'detections': [],
                'status': 'error',
                'error': 'Hybrid detector unavailable'
            }

        try:
            # Reuse a single detector instance for the scan service
            if ScanService._detector is None:
                ScanService._detector = HybridVulnerabilityDetector()
            detector = ScanService._detector
            
            # Run comprehensive analysis
            analysis = detector.analyze(code_content, filename)
            
            # Convert findings to API format
            detections = []
            for finding in analysis.get('findings', []):
                detections.append({
                    'type': finding['type'].replace('_', ' ').title(),
                    'severity': finding['severity'],
                    'confidence': finding.get('confidence', 0.8),
                    'cve_score': finding.get('cvss_score', 0),
                    'description': finding.get('description', ''),
                    'line_number': finding.get('line_number', 0),
                    'code_snippet': finding.get('code_snippet', ''),
                    'cwe_id': finding.get('cwe_id'),
                    'suggested_fix': finding.get('suggested_fix', ''),
                    'source': finding.get('detection_method', 'hybrid'),
                })
            
            return {
                'filename': filename,
                'detections': detections,
                'status': 'analyzed',
                'total_findings': len(detections),
                'security_score': analysis.get('security_score', 100),
                'severity_breakdown': analysis.get('severity_breakdown', {}),
                'tfidf_score': analysis.get('tfidf_score', 0),
            }

        except Exception as e:
            logger.error(f"Error analyzing {filename}: {str(e)}", exc_info=True)
            return {
                'filename': filename,
                'detections': [],
                'status': 'error',
                'error': str(e)
            }

    @staticmethod
    def scan_codebase(code_files: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Scan multiple code files and aggregate findings.
        
        Args:
            code_files: List of code file dicts with 'filename' and 'content'
            
        Returns:
            Aggregated scan results
        """
        all_findings = []
        file_results = []
        seen_findings = set()
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }

        for code_file in code_files:
            filename = code_file['filename']
            content = code_file['content']

            # Analyze this file
            result = ScanService.analyze_code(content, filename)
            file_results.append(result)

            # Aggregate findings with deduplication by file, type, line, and description
            for detection in result.get('detections', []):
                finding_key = (
                    filename,
                    detection.get('type'),
                    detection.get('line_number'),
                    detection.get('description'),
                )
                if finding_key in seen_findings:
                    continue

                seen_findings.add(finding_key)

                finding = {
                    'filename': filename,
                    'type': detection['type'],
                    'severity': detection['severity'],
                    'confidence': detection.get('confidence', 0),
                    'cve_score': detection.get('cve_score', 0),
                    'description': detection['description'],
                    'line_number': detection.get('line_number', 0),
                    'code_snippet': detection.get('code_snippet', ''),
                    'suggested_fix': detection.get('suggested_fix', ''),
                    'source': detection.get('source', 'unknown')
                }
                all_findings.append(finding)

                # Count by severity
                severity = detection['severity'].lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1

        # Calculate overall security score
        total_findings = len(all_findings)
        critical_weight = severity_counts['critical'] * 10
        high_weight = severity_counts['high'] * 7
        medium_weight = severity_counts['medium'] * 4
        low_weight = severity_counts['low'] * 1

        total_weight = critical_weight + high_weight + medium_weight + low_weight
        security_score = max(0, 100 - min(total_weight, 100))

        return {
            'files_analyzed': len(code_files),
            'total_findings': total_findings,
            'severity_breakdown': severity_counts,
            'findings': all_findings,
            'security_score': security_score,
            'file_results': file_results
        }
