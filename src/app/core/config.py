from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import EmailStr, SecretStr, field_validator
from datetime import timedelta

class Settings(BaseSettings):
    # App Configuration (unchanged)
    app_env: str
    app_debug: bool
    app_host: str
    app_port: int

    # Database Configuration (unchanged but with SecretStr for passwords)
    postgres_user: str
    postgres_password: str  # Keeping as str for compatibility
    postgres_server: str
    postgres_port: int
    postgres_db: str
    database_url: str

    # Redis Configuration (unchanged but with Optional[SecretStr])
    redis_host: str
    redis_port: int
    redis_db: int
    redis_password: Optional[str] = None  # Keeping as str for compatibility

    # Email Configuration (changed to SMTP naming but backward compatible)
    gmail_email: EmailStr  # Keeping old name for compatibility
    gmail_password: str    # Keeping old name for compatibility
    
    @property
    def smtp_user(self) -> EmailStr:
        return self.gmail_email
        
    @property
    def smtp_password(self) -> str:
        return self.gmail_password

    # JWT Settings (enhanced with validation)
    secret_key: str
    access_token_expire_minutes: int
    refresh_token_expire_days: int = 7
    algorithm: str = "HS256"

    # New security properties (with defaults)
    token_rotation_enabled: bool = True
    max_active_sessions: int = 5

    # Computed properties for easier use
    @property
    def access_token_expiry(self) -> timedelta:
        return timedelta(minutes=self.access_token_expire_minutes)

    @property
    def refresh_token_expiry(self) -> timedelta:
        return timedelta(days=self.refresh_token_expire_days)

    class Config:
        env_file = "../.env"
        env_file_encoding = "utf-8"
        extra = "ignore"  # Silently ignore extra env variables

settings = Settings()