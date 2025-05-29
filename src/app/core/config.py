from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import EmailStr
from datetime import timedelta

class Settings(BaseSettings):
    # App Configuration
    app_env: str
    app_debug: bool
    app_host: str
    app_port: int

    # Database Configuration
    postgres_user: str
    postgres_password: str
    postgres_server: str
    postgres_port: int
    postgres_db: str
    database_url: str

    # Redis Configuration
    redis_host: str
    redis_port: int
    redis_db: int
    redis_password: Optional[str] = None

    # Brevo Email Configuration
    brevo_email: EmailStr
    brevo_smtp_key: str  # Changed from brevo_api_key to match .env

    # JWT Settings
    secret_key: str
    access_token_expire_minutes: int
    refresh_token_expire_days: int = 7
    algorithm: str = "HS256"

    # Security properties
    token_rotation_enabled: bool = True
    max_active_sessions: int = 5

    # Computed properties for token expiry
    @property
    def access_token_expiry(self) -> timedelta:
        return timedelta(minutes=self.access_token_expire_minutes)

    @property
    def refresh_token_expiry(self) -> timedelta:
        return timedelta(days=self.refresh_token_expire_days)

    class Config:
        env_file = "../.env"  # Confirmed correct based on your setup
        env_file_encoding = "utf-8"
        extra = "ignore"  # Silently ignore extra env variables

settings = Settings()