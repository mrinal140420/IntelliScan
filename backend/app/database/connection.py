"""MongoDB connection management using Motor (async driver).

Based on MongoDB connection optimization best practices:
- Singleton pattern: Client created once and reused
- Connection pooling: Optimized for async FastAPI workload
- Error handling: Graceful connection failures
- Monitoring: Connection pool metrics available
"""

import logging
from typing import Optional, Any
import motor.motor_asyncio
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.config import settings

logger = logging.getLogger(__name__)


class MongoDBConnection:
    """Manages MongoDB connection lifecycle with async/await support."""

    _client: Optional[Any] = None
    _database: Optional[AsyncIOMotorDatabase] = None

    @classmethod
    async def connect(cls) -> AsyncIOMotorDatabase:
        """
        Initialize MongoDB connection with connection pooling.

        Connection pool configuration for FastAPI async application:
        - maxPoolSize: 50 - Supports typical web workloads with headroom
        - minPoolSize: 10 - Pre-warmed connections for immediate availability
        - maxIdleTimeMS: 600000 - 10 min idle timeout (stable servers benefit from persistent connections)
        - connectTimeoutMS: 10000 - 10 sec timeout to fail fast on connection issues
        - serverSelectionTimeoutMS: 5000 - 5 sec for quick failover detection

        Returns:
            AsyncIOMotorDatabase: Connected MongoDB database instance
        """
        if cls._client is not None:
            logger.info("Reusing existing MongoDB connection")
            return cls._database

        try:
            logger.info(f"Connecting to MongoDB at {settings.mongodb_url}")

            # Create MongoClient with optimized connection pool
            cls._client = motor.motor_asyncio.AsyncIOMotorClient(
                settings.mongodb_url,
                # Connection Pool Optimization
                maxPoolSize=50,  # Max concurrent connections
                minPoolSize=10,  # Min connections to keep warm
                maxIdleTimeMS=600000,  # 10 minutes idle timeout
                # Timeout Configuration
                connectTimeoutMS=10000,  # 10 seconds to connect
                serverSelectionTimeoutMS=5000,  # 5 seconds for server selection
                retryWrites=True,
                appName="SecureHub-IntelliScan",
            )

            # Access database (lazy connection until first operation)
            cls._database = cls._client[settings.database_name]

            # Test connection
            await cls._database.command("ping")
            logger.info("MongoDB connection successful")

            return cls._database

        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {str(e)}")
            raise

    @classmethod
    async def disconnect(cls) -> None:
        """Close MongoDB connection."""
        if cls._client is not None:
            cls._client.close()
            logger.info("MongoDB connection closed")
            cls._client = None
            cls._database = None

    @classmethod
    def get_database(cls) -> AsyncIOMotorDatabase:
        """Get current database instance (assumes connect() was called)."""
        if cls._database is None:
            raise RuntimeError(
                "Database not connected. Call MongoDBConnection.connect() first"
            )
        return cls._database

    @classmethod
    async def health_check(cls) -> bool:
        """Check if connection is healthy."""
        try:
            if cls._database is None:
                return False
            await cls._database.command("ping")
            return True
        except Exception as e:
            logger.error(f"Health check failed: {str(e)}")
            return False


# Dependency for FastAPI
async def get_database() -> Any:
    """FastAPI dependency to get database connection."""
    return MongoDBConnection.get_database()
