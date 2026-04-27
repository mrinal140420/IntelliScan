"""Report generation service - creates detailed security reports."""

import os
import json
import base64
from datetime import datetime
from typing import Dict, List, Any, Optional
from io import BytesIO
import logging

logger = logging.getLogger(__name__)


# Inline SVG logo fallback
LOGO_SVG = """
<svg width="80" height="80" viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg">
  <path d="M 40 10 L 65 25 L 65 45 Q 40 70 40 70 Q 15 45 15 45 L 15 25 Z" 
        fill="#1e3a8a" stroke="#0f172a" stroke-width="2"/>
  <path d="M 28 40 L 36 50 L 52 30" 
        fill="none" stroke="#10b981" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
"""

LOGO_PATH = os.path.join(os.path.dirname(__file__), '../../../frontend/logo.png')


class ReportService:
    """Service to generate vulnerability reports in HTML format."""
    
    @staticmethod
    def get_logo_base64() -> str:
        """Get logo as a base64-encoded image data URL, preferring the provided frontend logo."""
        if os.path.isfile(LOGO_PATH):
            try:
                with open(LOGO_PATH, 'rb') as f:
                    logo_bytes = f.read()
                    b64 = base64.b64encode(logo_bytes).decode('utf-8')
                    return f"data:image/png;base64,{b64}"
            except Exception:
                pass

        svg_bytes = LOGO_SVG.encode('utf-8')
        b64 = base64.b64encode(svg_bytes).decode('utf-8')
        return f"data:image/svg+xml;base64,{b64}"
    
    @staticmethod
    def generate_html_report(
        scan_id: str,
        project_name: str,
        timestamp: str,
        security_score: float,
        findings: List[Dict[str, Any]],
        severity_breakdown: Dict[str, int],
        files_analyzed: int,
    ) -> str:
        """Generate comprehensive HTML vulnerability report.
        
        Args:
            scan_id: Unique scan identifier
            project_name: Name of analyzed project
            timestamp: When scan was performed
            security_score: Overall security score (0-100)
            findings: List of vulnerability findings
            severity_breakdown: Count by severity level
            files_analyzed: Number of files scanned
            
        Returns:
            HTML report string
        """
        logo_url = ReportService.get_logo_base64()
        
        # Risk level based on score
        if security_score >= 80:
            risk_level = "Low Risk"
            risk_color = "#10b981"
        elif security_score >= 60:
            risk_level = "Medium Risk"
            risk_color = "#f59e0b"
        elif security_score >= 40:
            risk_level = "High Risk"
            risk_color = "#ef4444"
        else:
            risk_level = "Critical Risk"
            risk_color = "#7c2d12"
        
        # Build findings HTML
        findings_html = ""
        for i, finding in enumerate(findings, 1):
            severity = finding.get('severity', 'info').upper()
            
            # Severity color
            severity_colors = {
                'CRITICAL': '#7c2d12',
                'HIGH': '#dc2626',
                'MEDIUM': '#f59e0b',
                'LOW': '#6366f1',
                'INFO': '#06b6d4',
            }
            severity_color = severity_colors.get(severity, '#9ca3af')
            
            cvss = finding.get('cvss_score', 0)
            cwe = finding.get('cwe_id', 'N/A')
            vuln_type = finding.get('type', 'Unknown').replace('_', ' ').title()
            description = finding.get('description', 'No description')
            line = finding.get('line_number', 0)
            snippet = finding.get('code_snippet', '')
            
            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {severity_color}; margin-bottom: 20px;">
                <div class="finding-header">
                    <span class="finding-type">{vuln_type}</span>
                    <span class="severity" style="background-color: {severity_color}">{severity}</span>
                </div>
                <div class="finding-details">
                    <p><strong>Description:</strong> {description}</p>
                    <p><strong>CVSS Score:</strong> {cvss}/10 | <strong>CWE:</strong> CWE-{cwe}</p>
                    <p><strong>Location:</strong> Line {line}</p>
                    {f'<p><strong>Code:</strong> <code style="background-color: #f3f4f6; padding: 8px; border-radius: 4px; display: block;">{snippet}</code></p>' if snippet else ''}
                    {f'<p><strong>Suggested Fix:</strong> {finding.get("suggested_fix", "Review the vulnerable code and apply secure coding practices.")}</p>'}
                </div>
            </div>
            """
        
        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>SecureHub IntelliScan Report - {project_name}</title>
            <style>
                * {{
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }}
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    color: #1f2937;
                    background-color: #f9fafb;
                }}
                .container {{
                    max-width: 900px;
                    margin: 0 auto;
                    background-color: white;
                    padding: 40px;
                    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
                }}
                header {{
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    border-bottom: 2px solid #e5e7eb;
                    padding-bottom: 20px;
                    margin-bottom: 30px;
                }}
                .logo {{
                    width: 60px;
                    height: 60px;
                }}
                .header-text h1 {{
                    font-size: 28px;
                    color: #1e3a8a;
                    margin-bottom: 5px;
                }}
                .header-text p {{
                    color: #6b7280;
                    font-size: 14px;
                }}
                .summary {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }}
                .summary-card {{
                    background: linear-gradient(135deg, #f3f4f6 0%, #e5e7eb 100%);
                    padding: 20px;
                    border-radius: 8px;
                    border: 1px solid #d1d5db;
                }}
                .summary-card h3 {{
                    font-size: 12px;
                    color: #6b7280;
                    text-transform: uppercase;
                    margin-bottom: 10px;
                    font-weight: 600;
                }}
                .summary-card .value {{
                    font-size: 32px;
                    font-weight: bold;
                    color: #1f2937;
                }}
                .score-card {{
                    background: linear-gradient(135deg, {risk_color}20 0%, {risk_color}40 100%);
                    border-left: 4px solid {risk_color};
                }}
                .score-card .value {{
                    color: {risk_color};
                }}
                .risk-level {{
                    font-size: 16px;
                    color: {risk_color};
                    font-weight: 600;
                    margin-top: 8px;
                }}
                .severity-breakdown {{
                    display: flex;
                    gap: 15px;
                    margin-bottom: 30px;
                    flex-wrap: wrap;
                }}
                .severity-item {{
                    display: flex;
                    align-items: center;
                    gap: 8px;
                    padding: 8px 12px;
                    background: #f3f4f6;
                    border-radius: 4px;
                    font-size: 14px;
                }}
                .severity-indicator {{
                    width: 12px;
                    height: 12px;
                    border-radius: 2px;
                }}
                .findings-section {{
                    margin-top: 30px;
                }}
                .findings-section h2 {{
                    font-size: 20px;
                    color: #1f2937;
                    margin-bottom: 20px;
                    padding-bottom: 10px;
                    border-bottom: 2px solid #e5e7eb;
                }}
                .finding {{
                    background: #fafafa;
                    padding: 15px;
                    border-radius: 6px;
                    margin-bottom: 15px;
                }}
                .finding-header {{
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 10px;
                }}
                .finding-type {{
                    font-weight: 600;
                    font-size: 16px;
                    color: #1f2937;
                }}
                .severity {{
                    padding: 4px 12px;
                    border-radius: 4px;
                    color: white;
                    font-size: 12px;
                    font-weight: 600;
                }}
                .finding-details {{
                    font-size: 14px;
                    color: #4b5563;
                }}
                .finding-details p {{
                    margin: 8px 0;
                }}
                .finding-details code {{
                    font-family: 'Courier New', monospace;
                    color: #dc2626;
                }}
                footer {{
                    margin-top: 40px;
                    padding-top: 20px;
                    border-top: 1px solid #e5e7eb;
                    color: #6b7280;
                    font-size: 12px;
                    text-align: center;
                }}
                .metadata {{
                    display: grid;
                    grid-template-columns: repeat(2, 1fr);
                    gap: 15px;
                    font-size: 13px;
                    color: #6b7280;
                    margin-bottom: 20px;
                }}
                .metadata-item {{
                    display: flex;
                    justify-content: space-between;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <header>
                    <div class="header-text">
                        <h1>SecureHub IntelliScan</h1>
                        <p>Vulnerability Assessment Report</p>
                    </div>
                    <img src="{logo_url}" alt="SecureHub Logo" class="logo">
                </header>
                
                <div class="metadata">
                    <div class="metadata-item">
                        <span><strong>Project:</strong></span>
                        <span>{project_name}</span>
                    </div>
                    <div class="metadata-item">
                        <span><strong>Scan ID:</strong></span>
                        <span>{scan_id}</span>
                    </div>
                    <div class="metadata-item">
                        <span><strong>Date:</strong></span>
                        <span>{timestamp}</span>
                    </div>
                    <div class="metadata-item">
                        <span><strong>Files Analyzed:</strong></span>
                        <span>{files_analyzed}</span>
                    </div>
                </div>
                
                <div class="summary">
                    <div class="summary-card score-card">
                        <h3>Security Score</h3>
                        <div class="value">{security_score:.0f}%</div>
                        <div class="risk-level">{risk_level}</div>
                    </div>
                    <div class="summary-card">
                        <h3>Total Findings</h3>
                        <div class="value">{len(findings)}</div>
                    </div>
                    <div class="summary-card">
                        <h3>Critical Issues</h3>
                        <div class="value">{severity_breakdown.get('critical', 0)}</div>
                    </div>
                    <div class="summary-card">
                        <h3>High Issues</h3>
                        <div class="value">{severity_breakdown.get('high', 0)}</div>
                    </div>
                </div>
                
                <div class="severity-breakdown">
                    <div class="severity-item">
                        <div class="severity-indicator" style="background-color: #7c2d12;"></div>
                        <span>Critical: {severity_breakdown.get('critical', 0)}</span>
                    </div>
                    <div class="severity-item">
                        <div class="severity-indicator" style="background-color: #dc2626;"></div>
                        <span>High: {severity_breakdown.get('high', 0)}</span>
                    </div>
                    <div class="severity-item">
                        <div class="severity-indicator" style="background-color: #f59e0b;"></div>
                        <span>Medium: {severity_breakdown.get('medium', 0)}</span>
                    </div>
                    <div class="severity-item">
                        <div class="severity-indicator" style="background-color: #6366f1;"></div>
                        <span>Low: {severity_breakdown.get('low', 0)}</span>
                    </div>
                </div>
                
                {f'''<div class="findings-section">
                    <h2>Vulnerability Findings ({len(findings)})</h2>
                    {findings_html if findings else '<p style="color: #6b7280;">No vulnerabilities found. Great job!</p>'}
                </div>''' if findings else '<div class="findings-section"><h2>Vulnerability Findings</h2><p style="color: #10b981; font-size: 16px;"><strong>✓ No vulnerabilities found!</strong> Your code is secure.</p></div>'}
                
                <footer>
                    <p>This report was generated by SecureHub IntelliScan</p>
                    <p>For more information, visit https://securehub.intelli-scan.dev</p>
                    <p style="margin-top: 10px; color: #9ca3af;">Report generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                </footer>
            </div>
        </body>
        </html>
        """
        
        return html
    
    @staticmethod
    def generate_json_report(
        scan_id: str,
        project_name: str,
        timestamp: str,
        security_score: float,
        findings: List[Dict[str, Any]],
        severity_breakdown: Dict[str, int],
        files_analyzed: int,
        duration_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Generate JSON report for API consumption.
        
        Args:
            scan_id: Unique scan identifier
            project_name: Name of analyzed project
            timestamp: When scan was performed
            security_score: Overall security score (0-100)
            findings: List of vulnerability findings
            severity_breakdown: Count by severity level
            files_analyzed: Number of files scanned
            duration_seconds: How long scan took
            
        Returns:
            JSON-serializable report dictionary
        """
        return {
            "report_id": scan_id,
            "project_name": project_name,
            "timestamp": timestamp,
            "security_score": security_score,
            "risk_level": (
                "low" if security_score >= 80 else
                "medium" if security_score >= 60 else
                "high" if security_score >= 40 else
                "critical"
            ),
            "files_analyzed": files_analyzed,
            "total_findings": len(findings),
            "severity_breakdown": severity_breakdown,
            "findings": findings,
            "duration_seconds": duration_seconds,
            "report_version": "1.0",
            "generator": "SecureHub IntelliScan",
        }
    
    @staticmethod
    def save_html_report(report_html: str, output_path: str) -> bool:
        """Save HTML report to file.
        
        Args:
            report_html: HTML content
            output_path: File path to save to
            
        Returns:
            True if successful, False otherwise
        """
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report_html)
            logger.info(f"Report saved to {output_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
            return False
    
    @staticmethod
    def save_json_report(report_json: Dict[str, Any], output_path: str) -> bool:
        """Save JSON report to file.
        
        Args:
            report_json: JSON report dictionary
            output_path: File path to save to
            
        Returns:
            True if successful, False otherwise
        """
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_json, f, indent=2)
            logger.info(f"JSON report saved to {output_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save JSON report: {e}")
            return False
