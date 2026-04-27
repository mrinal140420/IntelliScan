"""FastAPI main application setup with MongoDB integration."""

import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.config import settings
from app.database.connection import MongoDBConnection
from app.routes.scan_routes import router as scan_router

# Configure logging
logging.basicConfig(level=settings.log_level)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manage application lifespan events.
    - Startup: Connect to MongoDB
    - Shutdown: Disconnect from MongoDB
    """
    # Startup
    logger.info("Starting SecureHub IntelliScan API...")
    try:
        db = await MongoDBConnection.connect()
        logger.info("MongoDB connected successfully")
    except Exception as e:
        logger.error(f"Failed to start application: {str(e)}")
        raise

    yield

    # Shutdown
    logger.info("Shutting down SecureHub IntelliScan API...")
    await MongoDBConnection.disconnect()
    logger.info("Application shutdown complete")


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""

    app = FastAPI(
        title="SecureHub IntelliScan API",
        description="Enterprise-grade AI-powered code security platform",
        version="3.0.0-enterprise",
        lifespan=lifespan,
    )

    # Configure CORS - explicitly allow preflight requests
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.get_allowed_origins(),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        max_age=3600,  # Cache preflight requests for 1 hour
    )

    # Root endpoint
    @app.get("/")
    async def root():
        """API health check."""
        return {
            "name": "SecureHub IntelliScan API",
            "version": "3.0.0-enterprise",
            "status": "active",
        }

    # Health check endpoint
    @app.get("/health")
    async def health_check():
        """Detailed health check including database status."""
        db_healthy = await MongoDBConnection.health_check()
        return {
            "status": "healthy" if db_healthy else "degraded",
            "database": "connected" if db_healthy else "disconnected",
        }

    # API v1 routes (to be added)
    @app.get("/api/v1/")
    async def api_v1_root():
        """API v1 root endpoint."""
        return {"version": "1.0.0", "endpoints": {}}

    # Include scan routes
    app.include_router(scan_router)

    return app


# Create application instance
app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
    )
