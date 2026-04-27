# SecureHub IntelliScan

AI-powered static code security analysis platform with a FastAPI backend, React + TypeScript frontend, MongoDB Atlas persistence, and hybrid detection logic (regex + AST + ML-assisted heuristics).

## Table of Contents
- Overview
- Key Features
- Project Architecture
- Tech Stack
- Repository Structure
- Quick Start
- Environment Configuration
- API Reference
- Scan Workflow
- Running Tests
- Troubleshooting
- Security and Operational Notes
- Future Improvements

## Overview
SecureHub IntelliScan analyzes source code from uploaded files, ZIP archives, or remote repositories and produces:
- vulnerability findings with severity and metadata
- weighted risk scoring and security score
- structured JSON report and human-readable HTML report
- persisted scan history in MongoDB for dashboard and history views

The frontend visualizes scan metrics, scan history, and report access. The backend handles scan orchestration, persistence, and report generation.

## Live Deployment
- Frontend: https://intelliscan-frontend.onrender.com
- Backend API: https://intelliscan-q1rk.onrender.com
- API Docs: https://intelliscan-q1rk.onrender.com/docs
- Health Check: https://intelliscan-q1rk.onrender.com/health

## Key Features
- Multi-input scanning:
  - upload source file(s) and ZIP archives
  - scan remote Git repositories
- Hybrid vulnerability analysis pipeline:
  - rule and pattern-based detection
  - AST/static analysis signals
  - ML-assisted scoring (project module under ml)
- Security scoring:
  - severity breakdown (critical/high/medium/low/info)
  - aggregate security score (0-100)
  - risk-level mapping for reporting
- Report generation:
  - HTML report endpoint
  - JSON report endpoint
- MongoDB-backed history:
  - recent scans endpoint
  - scan details endpoint
  - report retrieval endpoint
  - delete scan endpoint
- Frontend dashboards:
  - KPI metric cards
  - latest scan snapshot
  - top vulnerabilities
  - scan history and report links

## Project Architecture
```text
Frontend (React + Vite)
  -> calls REST API (/api/v1/scans/*)
Backend (FastAPI)
  -> scan routes + report service + scan service
  -> MongoDB connection layer (Motor async client)
Detection Engine (ml module)
  -> hybrid_detector + model utilities
Persistence
  -> MongoDB Atlas database (collection: scans)
```

## Tech Stack

### Frontend
- React 18
- TypeScript
- Vite
- React Router
- CSS-based design system
- Vitest + Testing Library

### Backend
- FastAPI
- Uvicorn
- Motor / PyMongo (MongoDB async)
- Pydantic Settings
- JWT-related auth packages (foundation ready)

### ML Module
- transformers
- torch
- scikit-learn
- pandas / numpy
- shap

## Repository Structure
```text
Intelli-Scan/
├─ backend/
│  ├─ app/
│  │  ├─ main.py
│  │  ├─ config.py
│  │  ├─ database/
│  │  │  └─ connection.py
│  │  ├─ routes/
│  │  │  └─ scan_routes.py
│  │  └─ services/
│  │     ├─ scan_service.py
│  │     └─ report_service.py
│  ├─ requirements.txt
│  └─ .env
├─ frontend/
│  ├─ src/
│  │  ├─ App.tsx
│  │  ├─ components/
│  │  ├─ pages/
│  │  └─ styles/
│  └─ package.json
├─ ml/
│  ├─ models/
│  ├─ tests/
│  └─ requirements.txt
└─ external/
   └─ UDB-CA/
```

## Quick Start

### 1. Prerequisites
- Python 3.11+ (3.12 also fine)
- Node.js 18+
- npm 9+
- Git (required for repository scan mode)
- MongoDB Atlas connection string

### 2. Backend Setup
From repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
pip install -r ml\requirements.txt
```

Create/update backend environment file at backend/.env:

```dotenv
MONGODB_URL=<your-mongodb-atlas-connection-string>
DATABASE_NAME=IntelliScan
HOST=0.0.0.0
PORT=8000
DEBUG=False
ENV=development
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173,http://localhost:5174,http://localhost:5175,http://localhost:8080
```

Run backend:

```powershell
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Health checks:
- http://localhost:8000/
- http://localhost:8000/health
- http://localhost:8000/docs

### 3. Frontend Setup
In a new terminal:

```powershell
cd frontend
npm install
npm run dev
```

Optional frontend env at frontend/.env:

```dotenv
VITE_API_URL=http://localhost:8000
```

If VITE_API_URL is not set, frontend falls back to http://localhost:8000.

## Environment Configuration

### Backend Variables (backend/.env)

| Variable | Purpose | Example |
|---|---|---|
| MONGODB_URL | Atlas or local Mongo connection string | mongodb+srv://... |
| DATABASE_NAME | Target Mongo database | IntelliScan |
| HOST | API bind host | 0.0.0.0 |
| PORT | API port | 8000 |
| DEBUG | Debug mode | False |
| ENV | Runtime environment | development |
| JWT_SECRET | Token secret | change-in-production |
| JWT_ALGORITHM | Token algorithm | HS256 |
| ACCESS_TOKEN_EXPIRE_HOURS | Access token TTL | 24 |
| REFRESH_TOKEN_EXPIRE_DAYS | Refresh token TTL | 7 |
| RATE_LIMIT_REQUESTS | Request limit | 100 |
| RATE_LIMIT_PERIOD | Rate window in seconds | 3600 |
| LOG_LEVEL | Logging level | INFO |
| ALLOWED_ORIGINS | Comma-separated CORS origins | http://localhost:5173,... |

### Frontend Variables (frontend/.env)

| Variable | Purpose | Default |
|---|---|---|
| VITE_API_URL | Backend base URL | http://localhost:8000 |

## API Reference
Base path: /api/v1/scans

### POST /upload
Upload and scan a file or ZIP.
- Content-Type: multipart/form-data
- Fields:
  - file
  - project_name
  - scan_type (optional, default full)

### POST /scan-repo
Scan a remote git repository.
- Content-Type: application/json
- Body:
```json
{
  "repository_url": "https://github.com/org/repo.git",
  "project_name": "example-repo",
  "scan_type": "full"
}
```

### POST /analyze-code
Analyze raw code text directly.
- Parameters expected by backend function:
  - project_name
  - code_content

### GET /recent?limit=10
Fetch recent scan summaries for dashboard/history.

### GET /{scan_id}
Fetch full scan details (including findings and report fields).

### GET /{scan_id}/report?format=html|json
Fetch HTML or JSON report.

### DELETE /{scan_id}
Delete a scan record from history.

## Scan Workflow
1. Frontend submits scan request (file or repo URL).
2. Backend normalizes and extracts code files.
3. Scan service performs per-file analysis using hybrid detector path.
4. Findings are aggregated and deduplicated.
5. Security score and severity distribution are computed.
6. HTML + JSON reports are generated.
7. Scan document is persisted to MongoDB collection scans.
8. Frontend updates dashboard/history and enables report download/view.

## Running Tests

### Backend tests
```powershell
cd backend
pytest -v
```

### ML tests
```powershell
cd ml
pytest -v
```

### Frontend tests
```powershell
cd frontend
npm test
```

## Troubleshooting

### 1) Frontend shows ERR_CONNECTION_REFUSED to :8000
Cause: backend is not running or not reachable.
Fix:
- start backend on port 8000
- verify http://localhost:8000/health
- confirm frontend uses correct VITE_API_URL

### 2) Uvicorn startup fails with WinError 10013
Cause: port access denied or conflict.
Fix:
- run terminal as Administrator
- check for another process on port 8000
- run on another port (for example 8001) and update VITE_API_URL

### 3) MongoDB connection/auth errors
Fix:
- validate MONGODB_URL credentials
- ensure Atlas IP Access List allows your public IP
- verify DATABASE_NAME exists/expected
- test with backend /health endpoint

### 4) Repository scan fails
Fix:
- ensure Git is installed and available in PATH
- confirm repository URL is accessible
- verify private repos have required credentials/token strategy

### 5) React Router v7 future warnings
These are deprecation warnings from react-router-dom v6 preparing for v7 behavior changes. They are non-blocking but can be addressed by opting into future flags when you are ready.

## Security and Operational Notes
- Do not commit real secrets in .env files.
- Rotate database credentials periodically.
- Replace placeholder JWT secret in production.
- Restrict CORS origins to trusted frontend domains only.
- Consider adding API authentication and per-user scan ownership before production rollout.

## Future Improvements
- Add CI pipeline for frontend/backend/ml test matrices
- Add Docker Compose for one-command local startup
- Add RBAC and API key scopes
- Add background job queue for large repository scans
- Add scan diffing and trend analytics over time
- Add SAST rule packs versioning and update pipeline

---

If you want, I can also generate:
- a concise README for contributors (CONTRIBUTING)
- a production deployment guide (Docker + Nginx + TLS)
- a Postman collection from the API routes above
