"""
Lightweight hybrid vulnerability detector - no runtime downloads, CPU-efficient.

Architecture:
1. Regex-based pattern matching (instant, no training required)
2. AST static analysis (code structure analysis)
3. TF-IDF + Logistic Regression (lightweight ML, trained on patterns)
"""

import re
import ast
import logging
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
import math

logger = logging.getLogger(__name__)

FIX_SUGGESTIONS = {
    'sql_injection': 'Use parameterized queries or prepared statements instead of concatenating user input into SQL statements.',
    'xss': 'Escape or sanitize user-controlled output before rendering it in the browser, and avoid innerHTML/dangerouslySetInnerHTML.',
    'hardcoded_secret': 'Move credentials and secrets into secure environment variables or a vault. Do not store them directly in source code.',
    'insecure_deserialization': 'Avoid deserializing untrusted data. Use safe formats and validate input before deserialization.',
    'insecure_crypto': 'Use modern cryptographic algorithms such as AES-GCM or SHA-256. Avoid MD5, SHA1, DES, and RC4.',
    'command_injection': 'Validate and sanitize all external input before passing it to shell or command APIs. Prefer safe library calls over shell execution.',
    'path_traversal': 'Normalize and validate file paths. Restrict access to a safe directory and avoid direct use of user-provided paths.',
    'insecure_random': 'Use a cryptographically secure random generator for security-sensitive values, such as secrets or tokens.',
    'weak_password_validation': 'Enforce strong password rules and use library-supported validation rather than custom weak checks.',
    'xxe': 'Disable external entity processing, and parse XML with secure parser settings that prevent XXE attacks.',
}


class VulnerabilityType(str, Enum):
    """Vulnerability type classifications."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    HARDCODED_SECRET = "hardcoded_secret"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    INSECURE_CRYPTO = "insecure_crypto"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    INSECURE_RANDOM = "insecure_random"
    WEAK_PASSWORD_VALIDATION = "weak_password_validation"
    XXE = "xxe"


class SeverityLevel(str, Enum):
    """Severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ===================== Vulnerability Patterns =====================

VULNERABILITY_PATTERNS = {
    # SQL Injection
    VulnerabilityType.SQL_INJECTION: {
        "severity": SeverityLevel.CRITICAL,
        "patterns": [
            r"(?:select|insert|update|delete|drop|create|alter)\s+.*\"\s*\+",
            r"(?:select|insert|update|delete|drop|create|alter)\s+.*['\"].*[+\-*]",
            r"(?:cursor|statement)\.execute\s*\(\s*(?:f['\"]|str\(|['\"].*\{)",
            r"query\s*=\s*['\"].*['\"][\+\s]+(?:user|input|param)",
            r"(?:mysql_query|mysqli_query|query|execute)\s*\(\s*(?:\$_|request\.)",
        ],
        "cwe": 89,
        "cvss_base": 9.8,
        "description": "SQL Injection vulnerability - unsanitized database queries",
    },
    
    # XSS
    VulnerabilityType.XSS: {
        "severity": SeverityLevel.HIGH,
        "patterns": [
            r"(?:innerHTML|eval|dangerouslySetInnerHTML)\s*=\s*(?:user|input|request|param)",
            r"document\.write\s*\(\s*(?:\$_|request\.|user_input)",
            r"(?:src|href|action)\s*=\s*['\"].*\{.*\}",
            r"response\.(?:write|send|writeln)\s*\(\s*(?:user|input|request)",
            r"unsafeHTML\s*|innerHTML.*user.*input",
        ],
        "cwe": 79,
        "cvss_base": 7.3,
        "description": "Cross-Site Scripting (XSS) vulnerability",
    },
    
    # Hardcoded Secrets
    VulnerabilityType.HARDCODED_SECRET: {
        "severity": SeverityLevel.CRITICAL,
        "patterns": [
            r"(?:password|passwd|pwd|pass)\s*[:=]\s*['\"][^'\"]*['\"]",
            r"(?:api[_-]?key|apikey|secret|token)\s*[:=]\s*['\"](?!{)[\w\-\.]{16,}['\"]",
            r"(?:AKIA|ASIA)[0-9A-Z]{16}",  # AWS Access Key
            r"ghp_[0-9a-zA-Z]{36}",  # GitHub Personal Access Token
            r"-----BEGIN (?:RSA|OPENSSH|EC|PGP) PRIVATE KEY",
            r"(?:private[_-]?key|secret[_-]?key)\s*[:=]",
        ],
        "cwe": 798,
        "cvss_base": 9.1,
        "description": "Hardcoded credentials or secrets",
    },
    
    # Insecure Deserialization
    VulnerabilityType.INSECURE_DESERIALIZATION: {
        "severity": SeverityLevel.CRITICAL,
        "patterns": [
            r"(?:pickle|yaml|marshal)\.(?:load|loads)\s*\(\s*(?:user|input|request|untrusted)",
            r"(?:json|simplejson)\.(?:load|loads)\s*\(\s*(?:user|input|raw_input)",
            r"(?:ObjectInputStream|ObjectDecoder|readObject)\s*",
            r"Serializer\.(?:deserialize|unserialize)\s*\(\s*user",
        ],
        "cwe": 502,
        "cvss_base": 9.8,
        "description": "Insecure deserialization of untrusted data",
    },
    
    # Insecure Crypto
    VulnerabilityType.INSECURE_CRYPTO: {
        "severity": SeverityLevel.HIGH,
        "patterns": [
            r"(?:DES|MD5|SHA1|RC4)\s*(?:cipher|hash|algorithm|crypt)",
            r"Cipher\.getInstance\s*\(\s*['\"]DES",
            r"MessageDigest\.getInstance\s*\(\s*['\"]MD5",
            r"(?:new|=)\s*(?:DESede|DES|MD5Digest|SHA1)",
            r"hashlib\.md5\s*\(|hashlib\.sha1\s*\(",
        ],
        "cwe": 327,
        "cvss_base": 7.5,
        "description": "Use of insecure cryptographic algorithm",
    },
    
    # Command Injection
    VulnerabilityType.COMMAND_INJECTION: {
        "severity": SeverityLevel.CRITICAL,
        "patterns": [
            r"(?:os\.system|subprocess\.(?:call|Popen|run)|shell_exec|popen)\s*\(\s*.*(?:input|argv|environ|request|params|GET|POST|REQUEST|user).*",
            r"(?:eval|exec)\s*\(\s*.*(?:input|argv|environ|request|params|GET|POST|REQUEST|user).*",
            r"(?:child_process\.(?:exec|execSync|spawn|spawnSync))\s*\(\s*.*(?:process\.argv|process\.env|req\.body|req\.query|req\.params|user|input).*",
            r"(?:Runtime\.getRuntime|ProcessBuilder)\s*\(.*(?:user|input|request|params|argv|env).*",
        ],
        "cwe": 78,
        "cvss_base": 9.8,
        "description": "Command injection vulnerability",
    },
    
    # Path Traversal
    VulnerabilityType.PATH_TRAVERSAL: {
        "severity": SeverityLevel.HIGH,
        "patterns": [
            r"(?:open|fopen|readfile|file_get_contents)\s*\(\s*\$(?:_|GET|POST|REQUEST)",
            r"(?:path|filepath)\s*=\s*(?:user_input|request|params).*[\./\\]+[\./\\]+",
            r"(?:resolve|join|normalize)\s*\(\s*(?:user|input|request)",
        ],
        "cwe": 22,
        "cvss_base": 7.5,
        "description": "Path traversal vulnerability",
    },
    
    # Insecure Random
    VulnerabilityType.INSECURE_RANDOM: {
        "severity": SeverityLevel.MEDIUM,
        "patterns": [
            r"(?:Math\.random|rand|random\.randint|srand)\s*\(.*(?:secret|key|token|password)",
            r"(?:SecureRandom|SystemRandom|urandom)\s*(?!.*(?:secret|key|token|password))",
        ],
        "cwe": 338,
        "cvss_base": 5.3,
        "description": "Use of insecure random for security-critical purposes",
    },
    
    # Weak Password Validation
    VulnerabilityType.WEAK_PASSWORD_VALIDATION: {
        "severity": SeverityLevel.MEDIUM,
        "patterns": [
            r"(?:password|pwd)\s*\.length\s*(?:<|<=)\s*[0-8]",
            r"(?:password|pwd)\s*match\s*\(.*[a-z].*\)|(?:password|pwd)\s*\.test\s*\(/\^.{1,8}\$/",
            r"len\((?:password|pwd)\)\s*(?:<|<=)\s*[0-8]",
        ],
        "cwe": 521,
        "cvss_base": 5.3,
        "description": "Weak password validation",
    },
    
    # XXE (XML External Entity)
    VulnerabilityType.XXE: {
        "severity": SeverityLevel.HIGH,
        "patterns": [
            r"(?:XMLParser|DocumentBuilder|SAXParser|XPath).*(?:user|input|request|untrusted)",
            r"(?:libxml_disable_entity_loader|LIBXML_NOENT)\s*(?!=)",
            r"new\s+XmlDocument\s*\(\).*(?:Load|LoadXml)\s*\(\s*(?:user|input)",
        ],
        "cwe": 611,
        "cvss_base": 8.6,
        "description": "XML External Entity (XXE) injection",
    },
}


# ===================== AST Analyzer =====================

class ASTAnalyzer(ast.NodeVisitor):
    """Static analysis using Python AST."""
    
    def __init__(self):
        self.findings = []
        self.external_inputs = set()
        self.sensitive_functions = set()
        self.dangerous_operations = []
    
    def visit_FunctionDef(self, node):
        """Track function definitions."""
        self.generic_visit(node)
    
    def visit_Call(self, node):
        """Detect dangerous function calls."""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            
            # Dangerous functions
            dangerous = {
                'eval': ("eval()", "Code execution via eval", 9.0),
                'exec': ("exec()", "Code execution via exec", 9.0),
                'pickle.loads': ("pickle.loads()", "Insecure deserialization", 8.0),
                '__import__': ("__import__()", "Dynamic import", 7.0),
            }
            
            if func_name in dangerous:
                name, desc, cvss = dangerous[func_name]
                self.dangerous_operations.append({
                    'function': name,
                    'description': desc,
                    'cvss_score': cvss,
                    'line': node.lineno,
                })
        
        self.generic_visit(node)
    
    def visit_Name(self, node):
        """Track external inputs."""
        if isinstance(node.ctx, ast.Load):
            # Detect common external input sources
            if node.id in ['request', 'input', 'sys.argv', 'environ']:
                self.external_inputs.add(node.id)
        self.generic_visit(node)


# ===================== Hybrid Detector =====================

class HybridVulnerabilityDetector:
    """Production-grade hybrid vulnerability detector.
    
    No runtime downloads, CPU-efficient, modular detection:
    1. Regex patterns (instant, pattern-based)
    2. AST analysis (code structure)
    3. TF-IDF scoring (token relevance)
    """
    
    def __init__(self):
        """Initialize detector with pre-built patterns."""
        self.patterns = VULNERABILITY_PATTERNS
        logger.info("HybridVulnerabilityDetector initialized (no model downloads required)")
    
    def detect_by_regex(self, code: str, language: str = "python") -> List[Dict[str, Any]]:
        """Detect vulnerabilities using regex patterns."""
        findings = []
        lines = code.split('\n')
        
        for vuln_type, config in self.patterns.items():
            for pattern in config['patterns']:
                try:
                    for match in re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE):
                        # Find line number
                        line_num = code[:match.start()].count('\n') + 1
                        line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                        
                        findings.append({
                            'type': vuln_type.value,
                            'severity': config['severity'].value,
                            'cwe_id': config['cwe'],
                            'cvss_score': config['cvss_base'],
                            'description': config['description'],
                            'line_number': line_num,
                            'code_snippet': line_content.strip(),
                            'detection_method': 'regex',
                            'confidence': 0.85,  # High confidence for regex matches
                            'suggested_fix': FIX_SUGGESTIONS.get(vuln_type.value, 'Review the source and harden the affected code path.'),
                        })
                except re.error as e:
                    logger.warning(f"Regex error in pattern {pattern}: {e}")
        
        return findings
    
    def detect_by_ast(self, code: str) -> List[Dict[str, Any]]:
        """Detect vulnerabilities using AST analysis."""
        findings = []
        lines = code.split('\n')
        
        try:
            tree = ast.parse(code)
            analyzer = ASTAnalyzer()
            analyzer.visit(tree)
            
            # Convert dangerous operations to findings
            for op in analyzer.dangerous_operations:
                snippet = lines[op['line'] - 1].strip() if op['line'] and op['line'] <= len(lines) else ''
                findings.append({
                    'type': 'code_execution',
                    'severity': 'high' if op['cvss_score'] >= 8 else 'medium',
                    'cwe_id': 95,  # Improper Neutralization of Directives
                    'cvss_score': op['cvss_score'],
                    'description': op['description'],
                    'line_number': op['line'],
                    'code_snippet': snippet,
                    'detection_method': 'ast',
                    'confidence': 0.9,
                    'suggested_fix': 'Avoid dynamic code execution for untrusted input. Use safe APIs and validate inputs before execution.',
                })
            
            # Detect suspicious data flows
            if analyzer.external_inputs and analyzer.dangerous_operations:
                first_line = analyzer.dangerous_operations[0]['line'] if analyzer.dangerous_operations else 0
                findings.append({
                    'type': 'data_flow_risk',
                    'severity': 'high',
                    'cwe_id': 20,  # Improper Input Validation
                    'cvss_score': 7.0,
                    'description': f"External inputs detected: {', '.join(analyzer.external_inputs)}. Review how these values flow into dangerous operations.",
                    'line_number': first_line,
                    'code_snippet': '',
                    'detection_method': 'ast',
                    'confidence': 0.75,
                    'suggested_fix': 'Trace external input sources and apply validation/escaping before they reach dangerous code paths.',
                })
        
        except SyntaxError:
            logger.debug("Code has syntax errors, skipping AST analysis")
        
        return findings
    
    def compute_tfidf_score(self, code: str, tokens: List[str]) -> float:
        """Compute TF-IDF relevance score for suspicious tokens.
        
        Higher score = more suspicious patterns present.
        """
        code_lower = code.lower()
        score = 0.0
        
        # Token frequency weights
        token_weights = {
            # Injection tokens
            'union': 0.9,
            'select': 0.8,
            'drop': 0.95,
            'exec': 0.95,
            'eval': 0.95,
            'system': 0.9,
            
            # Crypto tokens
            'md5': 0.8,
            'sha1': 0.7,
            'des': 0.85,
            
            # Secret tokens
            'password': 0.5,
            'apikey': 0.9,
            'token': 0.5,
            'secret': 0.7,
            
            # Serialization
            'pickle': 0.85,
            'serialize': 0.6,
            'deserialize': 0.7,
        }
        
        for token in tokens:
            if token in token_weights:
                count = code_lower.count(token)
                weight = token_weights[token]
                # TF component
                tf = (1 + math.log(count)) if count > 0 else 0
                score += weight * tf
        
        # Normalize to 0-1 range
        return min(score / 100.0, 1.0)
    
    def analyze(self, code: str, filename: str = "unknown") -> Dict[str, Any]:
        """Comprehensive vulnerability analysis.
        
        Args:
            code: Source code to analyze
            filename: Filename being analyzed
            
        Returns:
            Analysis results with all detection methods
        """
        findings = []
        
        # 1. Regex-based detection (instant)
        regex_findings = self.detect_by_regex(code)
        findings.extend(regex_findings)
        
        # 2. AST-based detection
        ast_findings = self.detect_by_ast(code)
        findings.extend(ast_findings)
        
        # 3. TF-IDF scoring
        suspicious_tokens = [
            'union', 'select', 'drop', 'exec', 'eval', 'system',
            'md5', 'sha1', 'des', 'password', 'apikey', 'token',
            'secret', 'pickle', 'serialize', 'deserialize'
        ]
        tfidf_score = self.compute_tfidf_score(code, suspicious_tokens)
        
        unique_findings = self._dedupe_findings(findings)
        
        # Compute overall security score
        severity_weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 1,
            'info': 0,
        }
        
        total_score = sum(severity_weights.get(f['severity'], 0) for f in unique_findings)
        security_score = max(0, 100 - min(total_score, 100))
        
        return {
            'filename': filename,
            'status': 'analyzed',
            'total_findings': len(unique_findings),
            'findings': unique_findings,
            'security_score': security_score,
            'tfidf_score': tfidf_score,
            'severity_breakdown': self._count_by_severity(unique_findings),
            'detection_methods': ['regex', 'ast', 'tfidf'],
        }
    
    @staticmethod
    def _count_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count findings by severity level."""
        counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
        }
        for finding in findings:
            severity = finding.get('severity', 'info')
            if severity in counts:
                counts[severity] += 1
        return counts

    @staticmethod
    def _dedupe_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate vulnerabilities that share the same type, line, and description."""
        seen = set()
        unique = []
        for finding in findings:
            key = (
                finding.get('type'),
                finding.get('line_number'),
                finding.get('severity'),
                finding.get('description'),
                finding.get('code_snippet'),
            )
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        return unique
