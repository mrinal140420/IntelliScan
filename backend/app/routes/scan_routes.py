"""Scan routes for code vulnerability analysis."""

from fastapi import APIRouter, UploadFile, File, HTTPException, Form, Depends
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from pydantic import BaseModel
from typing import List, Optional
import os
import logging
import uuid
from datetime import datetime
import tempfile
import time

from app.services.scan_service import ScanService
from app.services.report_service import ReportService
from app.models.db_models import Scan, ScanStatus, Finding, ScanSummary
from app.database.connection import MongoDBConnection

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


# Add OPTIONS handler for preflight requests
@router.options("/{path:path}")
async def preflight(path: str):
    """Handle CORS preflight requests."""
    return JSONResponse(content={}, status_code=200)


class ScanRequest(BaseModel):
    """Request model for starting a scan."""
    project_name: str
    scan_type: str = "full"  # full, quick, custom


class ScanResponse(BaseModel):
    """Response model for scan results."""
    scan_id: str
    project_name: str
    status: str
    files_analyzed: int
    total_findings: int
    security_score: float
    findings: List[dict]
    severity_breakdown: dict
    timestamp: str


@router.post("/upload")
async def upload_and_scan(
    file: UploadFile = File(...),
    project_name: str = Form(...),
    scan_type: str = Form(default="full")
):
    """
    Upload code file/ZIP and perform vulnerability scan.
    
    Args:
        file: ZIP file or code file to scan
        project_name: Name of the project
        scan_type: Type of scan (full, quick, custom)
        
    Returns:
        Scan results with findings
    """
    temp_path = None
    start_time = time.time()
    
    try:
        # Validate file
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file provided")

        # Check file type
        supported_extensions = [
            '.py', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
            '.java', '.cpp', '.cc', '.c', '.cs',
            '.go', '.rb', '.php', '.swift', '.kt', '.kts', '.scala',
            '.rs', '.sql',
            '.html', '.htm', '.css', '.scss', '.sass', '.less',
            '.xml', '.json', '.yaml', '.yml', '.md',
            '.vue', '.svelte', '.graphql', '.gql',
            '.env', '.ini'
        ]
        
        if not (file.filename.endswith('.zip') or
                any(file.filename.lower().endswith(ext) for ext in supported_extensions)):
            raise HTTPException(
                status_code=400,
                detail="File type not supported. Upload ZIP, Python, JavaScript, JSX, TypeScript, Java, C/C++, C#, Go, Ruby, PHP, Swift, Kotlin, Rust, SQL, HTML, CSS, SCSS, XML, JSON, YAML, Markdown, Vue, Svelte, or other code files."
            )

        # Save uploaded file to temp location
        try:
            with tempfile.NamedTemporaryFile(
                delete=False,
                suffix=os.path.splitext(file.filename)[1]
            ) as temp_file:
                contents = await file.read()
                temp_file.write(contents)
                temp_path = temp_file.name

            # Extract code from files
            logger.info(f"Extracting code from {file.filename}")
            code_files = ScanService.extract_code_from_files(temp_path)

            if not code_files:
                raise HTTPException(
                    status_code=400,
                    detail="No code files found in the uploaded file"
                )

            logger.info(f"Found {len(code_files)} code files to analyze")

            # Perform scan
            logger.info(f"Starting scan for project: {project_name}")
            scan_results = ScanService.scan_codebase(code_files)

            # Generate scan ID and timestamp
            scan_id = str(uuid.uuid4())
            timestamp = datetime.utcnow().isoformat()
            duration_seconds = int(time.time() - start_time)

            # Generate reports
            report_html = ReportService.generate_html_report(
                scan_id=scan_id,
                project_name=project_name,
                timestamp=timestamp,
                security_score=scan_results['security_score'],
                findings=scan_results['findings'],
                severity_breakdown=scan_results['severity_breakdown'],
                files_analyzed=scan_results['files_analyzed'],
            )
            
            report_json = ReportService.generate_json_report(
                scan_id=scan_id,
                project_name=project_name,
                timestamp=timestamp,
                security_score=scan_results['security_score'],
                findings=scan_results['findings'],
                severity_breakdown=scan_results['severity_breakdown'],
                files_analyzed=scan_results['files_analyzed'],
                duration_seconds=duration_seconds,
            )

            # Prepare response
            response = {
                "scan_id": scan_id,
                "project_name": project_name,
                "status": "completed",
                "files_analyzed": scan_results['files_analyzed'],
                "total_findings": scan_results['total_findings'],
                "security_score": scan_results['security_score'],
                "severity_breakdown": scan_results['severity_breakdown'],
                "findings": scan_results['findings'],
                "timestamp": timestamp,
                "scan_type": scan_type,
                "duration_seconds": duration_seconds,
            }

            # Persist to MongoDB (async, non-blocking)
            try:
                db = MongoDBConnection.get_database()
                scans_collection = db['scans']
                
                # Create scan document
                scan_doc = {
                    "_id": scan_id,
                    "project_name": project_name,
                    "scan_type": scan_type,
                    "status": "completed",
                    "security_score": scan_results['security_score'],
                    "risk_level": (
                        "low" if scan_results['security_score'] >= 80 else
                        "medium" if scan_results['security_score'] >= 60 else
                        "high" if scan_results['security_score'] >= 40 else
                        "critical"
                    ),
                    "summary": {
                        "total_issues": scan_results['total_findings'],
                        "critical": scan_results['severity_breakdown'].get('critical', 0),
                        "high": scan_results['severity_breakdown'].get('high', 0),
                        "medium": scan_results['severity_breakdown'].get('medium', 0),
                        "low": scan_results['severity_breakdown'].get('low', 0),
                        "info": scan_results['severity_breakdown'].get('info', 0),
                        "files_scanned": scan_results['files_analyzed'],
                        "lines_analyzed": sum(len(f.get('content', '').split('\n')) for f in code_files),
                    },
                    "duration_seconds": duration_seconds,
                    "created_at": datetime.utcnow(),
                    "completed_at": datetime.utcnow(),
                    "report_html": report_html,
                    "report_json": report_json,
                }
                
                await scans_collection.insert_one(scan_doc)
                logger.info(f"Scan {scan_id} persisted to MongoDB")
            except Exception as e:
                logger.warning(f"Failed to persist scan to MongoDB: {e}")
                # Continue even if DB persistence fails

            logger.info(
                f"Scan {scan_id} completed: {scan_results['total_findings']} findings, "
                f"score: {scan_results['security_score']:.1f}%"
            )

            return JSONResponse(content=response, status_code=200)

        finally:
            # Clean up temp file
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except Exception as e:
                    logger.warning(f"Failed to delete temp file: {str(e)}")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/analyze-code")
async def analyze_code_direct(project_name: str, code_content: str):
    """
    Analyze code provided directly as text.
    
    Args:
        project_name: Name of the project
        code_content: Raw code to analyze
        
    Returns:
        Scan results with findings
    """
    start_time = time.time()
    
    try:
        if not code_content or len(code_content.strip()) < 10:
            raise HTTPException(
                status_code=400,
                detail="Code content too short (minimum 10 characters)"
            )

        # Create temporary file with code
        code_files = [{
            'filename': 'uploaded_code.txt',
            'content': code_content
        }]

        # Perform scan
        logger.info(f"Starting code analysis for project: {project_name}")
        scan_results = ScanService.scan_codebase(code_files)

        scan_id = str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat()
        duration_seconds = int(time.time() - start_time)

        # Generate reports
        report_html = ReportService.generate_html_report(
            scan_id=scan_id,
            project_name=project_name,
            timestamp=timestamp,
            security_score=scan_results['security_score'],
            findings=scan_results['findings'],
            severity_breakdown=scan_results['severity_breakdown'],
            files_analyzed=scan_results['files_analyzed'],
        )
        
        report_json = ReportService.generate_json_report(
            scan_id=scan_id,
            project_name=project_name,
            timestamp=timestamp,
            security_score=scan_results['security_score'],
            findings=scan_results['findings'],
            severity_breakdown=scan_results['severity_breakdown'],
            files_analyzed=scan_results['files_analyzed'],
            duration_seconds=duration_seconds,
        )

        response = {
            "scan_id": scan_id,
            "project_name": project_name,
            "status": "completed",
            "files_analyzed": scan_results['files_analyzed'],
            "total_findings": scan_results['total_findings'],
            "security_score": scan_results['security_score'],
            "severity_breakdown": scan_results['severity_breakdown'],
            "findings": scan_results['findings'],
            "timestamp": timestamp,
            "duration_seconds": duration_seconds,
        }

        # Persist to MongoDB
        try:
            db = MongoDBConnection.get_database()
            scans_collection = db['scans']
            
            scan_doc = {
                "_id": scan_id,
                "project_name": project_name,
                "scan_type": "direct",
                "status": "completed",
                "security_score": scan_results['security_score'],
                "risk_level": (
                    "low" if scan_results['security_score'] >= 80 else
                    "medium" if scan_results['security_score'] >= 60 else
                    "high" if scan_results['security_score'] >= 40 else
                    "critical"
                ),
                "summary": {
                    "total_issues": scan_results['total_findings'],
                    "critical": scan_results['severity_breakdown'].get('critical', 0),
                    "high": scan_results['severity_breakdown'].get('high', 0),
                    "medium": scan_results['severity_breakdown'].get('medium', 0),
                    "low": scan_results['severity_breakdown'].get('low', 0),
                    "info": scan_results['severity_breakdown'].get('info', 0),
                    "files_scanned": scan_results['files_analyzed'],
                    "lines_analyzed": len(code_content.split('\n')),
                },
                "duration_seconds": duration_seconds,
                "created_at": datetime.utcnow(),
                "completed_at": datetime.utcnow(),
                "report_html": report_html,
                "report_json": report_json,
            }
            
            await scans_collection.insert_one(scan_doc)
            logger.info(f"Code analysis {scan_id} persisted to MongoDB")
        except Exception as e:
            logger.warning(f"Failed to persist analysis to MongoDB: {e}")

        logger.info(
            f"Analysis {scan_id} completed: {scan_results['total_findings']} findings"
        )

        return JSONResponse(content=response, status_code=200)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


class RepositoryScanRequest(BaseModel):
    """Request model for repository scanning."""
    repository_url: str
    project_name: str
    scan_type: str = "full"


@router.post("/scan-repo")
async def scan_repository(req: RepositoryScanRequest):
    """
    Clone and scan a Git repository for vulnerabilities.
    
    Args:
        req: RepositoryScanRequest with repository_url, project_name, and scan_type
        
    Returns:
        Scan results with findings
    """
    repository_url = req.repository_url
    project_name = req.project_name
    scan_type = req.scan_type
    temp_repo_path = None
    start_time = time.time()
    
    try:
        # Validate repository URL format
        if not repository_url.startswith(('http://', 'https://', 'git://')):
            raise HTTPException(
                status_code=400,
                detail="Invalid repository URL. Must start with http://, https://, or git://"
            )

        logger.info(f"Extracting code from repository: {repository_url}")

        # Create temporary directory for cloning
        temp_repo_path = tempfile.mkdtemp()

        # Clone repository (using GitPython)
        try:
            import git
            repo = git.Repo.clone_from(repository_url, temp_repo_path)
            logger.info(f"Repository cloned successfully to {temp_repo_path}")
        except ImportError:
            logger.warning("GitPython not installed, attempting shell git command")
            import subprocess
            result = subprocess.run(
                ['git', 'clone', '--depth', '1', repository_url, temp_repo_path],
                capture_output=True,
                timeout=60
            )
            if result.returncode != 0:
                raise HTTPException(
                    status_code=400,
                    detail=f"Failed to clone repository: {result.stderr.decode()}"
                )
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to clone repository: {str(e)}"
            )

        # Extract code files from repository
        code_files = ScanService.extract_code_from_files(temp_repo_path)
        
        if not code_files:
            raise HTTPException(
                status_code=400,
                detail="No code files found in repository"
            )

        logger.info(f"Found {len(code_files)} code files to analyze")

        # Perform scan
        logger.info(f"Starting scan for project: {project_name}")
        scan_results = ScanService.scan_codebase(code_files)

        # Generate scan ID and timestamp
        scan_id = str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat()
        duration_seconds = int(time.time() - start_time)

        # Generate reports
        report_html = ReportService.generate_html_report(
            scan_id=scan_id,
            project_name=project_name,
            timestamp=timestamp,
            security_score=scan_results['security_score'],
            findings=scan_results['findings'],
            severity_breakdown=scan_results['severity_breakdown'],
            files_analyzed=scan_results['files_analyzed'],
        )
        
        report_json = ReportService.generate_json_report(
            scan_id=scan_id,
            project_name=project_name,
            timestamp=timestamp,
            security_score=scan_results['security_score'],
            findings=scan_results['findings'],
            severity_breakdown=scan_results['severity_breakdown'],
            files_analyzed=scan_results['files_analyzed'],
            duration_seconds=duration_seconds,
        )

        # Prepare response
        response = {
            "scan_id": scan_id,
            "project_name": project_name,
            "status": "completed",
            "files_analyzed": scan_results['files_analyzed'],
            "total_findings": scan_results['total_findings'],
            "security_score": scan_results['security_score'],
            "severity_breakdown": scan_results['severity_breakdown'],
            "findings": scan_results['findings'],
            "timestamp": timestamp,
            "scan_type": scan_type,
            "repository_url": repository_url,
            "duration_seconds": duration_seconds,
        }

        # Persist to MongoDB
        try:
            db = MongoDBConnection.get_database()
            scans_collection = db['scans']
            
            scan_doc = {
                "_id": scan_id,
                "project_name": project_name,
                "scan_type": scan_type,
                "repository_url": repository_url,
                "status": "completed",
                "security_score": scan_results['security_score'],
                "risk_level": (
                    "low" if scan_results['security_score'] >= 80 else
                    "medium" if scan_results['security_score'] >= 60 else
                    "high" if scan_results['security_score'] >= 40 else
                    "critical"
                ),
                "summary": {
                    "total_issues": scan_results['total_findings'],
                    "critical": scan_results['severity_breakdown'].get('critical', 0),
                    "high": scan_results['severity_breakdown'].get('high', 0),
                    "medium": scan_results['severity_breakdown'].get('medium', 0),
                    "low": scan_results['severity_breakdown'].get('low', 0),
                    "info": scan_results['severity_breakdown'].get('info', 0),
                    "files_scanned": scan_results['files_analyzed'],
                    "lines_analyzed": sum(len(f.get('content', '').split('\n')) for f in code_files),
                },
                "duration_seconds": duration_seconds,
                "created_at": datetime.utcnow(),
                "completed_at": datetime.utcnow(),
                "report_html": report_html,
                "report_json": report_json,
            }
            
            await scans_collection.insert_one(scan_doc)
            logger.info(f"Scan {scan_id} persisted to MongoDB")
        except Exception as e:
            logger.warning(f"Failed to persist scan to MongoDB: {e}")

        logger.info(
            f"Scan {scan_id} completed: {scan_results['total_findings']} findings, "
            f"score: {scan_results['security_score']:.1f}%"
        )

        return JSONResponse(content=response, status_code=200)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Repository scan failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Repository scan failed: {str(e)}")
    
    finally:
        # Clean up temp directory
        if temp_repo_path and os.path.exists(temp_repo_path):
            try:
                import shutil
                shutil.rmtree(temp_repo_path)
                logger.info(f"Cleaned up temporary repository directory: {temp_repo_path}")
            except Exception as e:
                logger.warning(f"Failed to delete temp directory {temp_repo_path}: {str(e)}")


@router.get("/recent")
async def get_recent_scans(limit: int = 10):
    """Get recent scans from database."""
    try:
        db = MongoDBConnection.get_database()
        scans_collection = db['scans']
        
        # Get most recent scans
        scans = await scans_collection.find(
            {},
            {"report_html": 0, "report_json": 0}  # Exclude large fields
        ).sort("created_at", -1).limit(limit).to_list(length=limit)
        
        # Transform scans to match frontend schema
        formatted_scans = []
        for scan in scans:
            summary = scan.get('summary', {})
            formatted_scan = {
                'scan_id': str(scan.get('_id', '')),
                'project_name': scan.get('project_name', 'Unknown'),
                'scan_type': scan.get('repo_provider', 'manual'),
                'status': scan.get('status', 'unknown'),
                'created_at': scan.get('created_at', '').isoformat() if scan.get('created_at') else '',
                'files_analyzed': summary.get('files_scanned', 0),
                'security_score': scan.get('security_score', 0),
                'total_findings': summary.get('total_issues', 0),
                'severity_breakdown': {
                    'critical': summary.get('critical', 0),
                    'high': summary.get('high', 0),
                    'medium': summary.get('medium', 0),
                    'low': summary.get('low', 0),
                    'info': summary.get('info', 0),
                }
            }
            formatted_scans.append(formatted_scan)
        
        return {
            "scans": formatted_scans,
            "total": len(formatted_scans)
        }
    except Exception as e:
        logger.error(f"Failed to fetch recent scans: {e}")
        return {
            "scans": [],
            "total": 0
        }


@router.get("/{scan_id}")
async def get_scan_results(scan_id: str):
    """Get specific scan results and report."""
    try:
        db = MongoDBConnection.get_database()
        scans_collection = db['scans']
        
        scan = await scans_collection.find_one({"_id": scan_id})
        
        if not scan:
            raise HTTPException(
                status_code=404,
                detail=f"Scan {scan_id} not found"
            )
        
        # Return with report data
        scan['scan_id'] = scan.pop('_id', '')
        return scan
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch scan {scan_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch scan: {str(e)}"
        )


@router.get("/{scan_id}/report")
async def get_scan_report(scan_id: str, format: str = "html"):
    """Get scan report in HTML or JSON format."""
    try:
        db = MongoDBConnection.get_database()
        scans_collection = db['scans']
        
        scan = await scans_collection.find_one({"_id": scan_id})
        
        if not scan:
            raise HTTPException(
                status_code=404,
                detail=f"Scan {scan_id} not found"
            )
        
        if format.lower() == "json":
            report = scan.get('report_json', {})
            return JSONResponse(content=report, status_code=200)
        elif format.lower() == "html":
            report_html = scan.get('report_html', '<h1>Report not available</h1>')
            return HTMLResponse(content=report_html, status_code=200)
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported report format: {format}")
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch report for {scan_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch report: {str(e)}"
        )


@router.delete("/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan from history."""
    try:
        db = MongoDBConnection.get_database()
        scans_collection = db['scans']
        
        result = await scans_collection.delete_one({"_id": scan_id})
        
        if result.deleted_count == 0:
            raise HTTPException(
                status_code=404,
                detail=f"Scan {scan_id} not found"
            )
        
        return {
            "message": f"Scan {scan_id} deleted successfully",
            "scan_id": scan_id
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete scan {scan_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete scan: {str(e)}"
        )
