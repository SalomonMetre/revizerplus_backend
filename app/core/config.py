from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import EmailStr
from datetime import timedelta, timezone

class Settings(BaseSettings):
    # App Configuration
    APP_ENV: str
    APP_DEBUG: bool
    APP_HOST: str
    APP_PORT: int

    # Database Configuration
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_SERVER: str
    POSTGRES_PORT: int
    POSTGRES_DB: str

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@"
            f"{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    # Redis Configuration
    REDIS_HOST: str
    REDIS_PORT: int
    REDIS_DB: int
    REDIS_PASSWORD: Optional[str] = None

    # Brevo Email Configuration
    BREVO_EMAIL: EmailStr
    BREVO_SMTP_KEY: str

    # JWT Settings
    SECRET_KEY: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ALGORITHM: str = "HS256"

    # Security Properties
    TOKEN_ROTATION_ENABLED: bool = True
    MAX_ACTIVE_SESSIONS: int = 5

    # Computed Expiry Values
    @property
    def access_token_expiry(self) -> timedelta:
        return timedelta(minutes=self.ACCESS_TOKEN_EXPIRE_MINUTES)

    @property
    def refresh_token_expiry(self) -> timedelta:
        return timedelta(days=self.REFRESH_TOKEN_EXPIRE_DAYS)

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"

settings = Settings()

def get_settings() -> Settings:
    return settings