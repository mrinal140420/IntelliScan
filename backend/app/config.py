from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    """Application configuration loaded from environment variables."""

    # Database
    mongodb_url: str = "mongodb://localhost:27017"
    database_name: str = "securehub"

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    env: str = "development"

    # Security
    jwt_secret: str = "your-secret-key-change-in-production-min-32-bytes"
    jwt_algorithm: str = "HS256"
    access_token_expire_hours: int = 24
    refresh_token_expire_days: int = 7

    # API Keys
    api_key_prefix: str = "sh_"
    api_key_length: int = 32

    # GitHub OAuth
    github_client_id: str = ""
    github_client_secret: str = ""

    # Rate Limiting
    rate_limit_requests: int = 100
    rate_limit_period: int = 3600

    # ML Settings
    ml_model_cache_size: int = 2
    use_gpu: bool = False

    # Logging
    log_level: str = "INFO"

    # CORS - handle both comma-separated string and list
    allowed_origins: str = "http://localhost:3000,http://localhost:5173,http://localhost:5174,http://localhost:5175,http://localhost:8080"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

    def get_allowed_origins(self) -> List[str]:
        """Parse allowed origins from comma-separated string or list."""
        if isinstance(self.allowed_origins, list):
            return self.allowed_origins
        return [origin.strip() for origin in self.allowed_origins.split(",")]


settings = Settings()
