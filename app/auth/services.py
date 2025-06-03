import random
import string
from datetime import datetime, timedelta, timezone
from jose import JWTError
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from utils.token import create_token, decode_token # These are the low-level JWT functions
from utils.email import send_email_via_api
from users import crud as user_crud

import redis.asyncio as redis

# Redis client
r = redis.Redis(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    db=settings.REDIS_DB,
    password=settings.REDIS_PASSWORD,
    decode_responses=True
)

# === OTP Generation & Redis Logic ===

def generate_otp(length: int = 6) -> str:
    """Generates a random numeric OTP of specified length."""
    return ''.join(random.choices(string.digits, k=length))

async def save_otp_to_redis(email: str, otp: str, expires_in: int = 300):
    """Saves an OTP to Redis with an expiration time."""
    await r.set(f"otp:{email}", otp, ex=expires_in)

async def verify_otp(email: str, otp: str) -> bool:
    """Verifies an OTP against the one stored in Redis."""
    stored_otp = await r.get(f"otp:{email}")
    if stored_otp and stored_otp == otp:
        await r.delete(f"otp:{email}") # Delete OTP after successful verification
        return True
    return False

# === Email Sending ===

async def send_otp_email(email: str, otp: str):
    """Sends an OTP to the user's email."""
    subject = "Your Revizer Plus Verification Code"
    content = f"<p>Bonjour 👋,</p><p>Voici votre code de vérification : <strong>{otp}</strong></p><p>Ce code expire dans 5 minutes.</p>"
    return await send_email_via_api(email, subject, content)

# === Token Logic ===

async def create_access_token_pair(user_id: int, email: str) -> tuple[str, datetime]:
    """
    Generates a new access token and its expiration datetime.
    """
    access_token_expires = datetime.now(timezone.utc) + settings.access_token_expiry
    access_payload = {"sub": email, "user_id": user_id, "type": "access"}
    access_token = create_token(
        access_payload,
        expires_delta=settings.access_token_expiry
    )
    return access_token, access_token_expires

async def create_refresh_token_pair(user_id: int, email: str) -> tuple[str, datetime]:
    """
    Generates a new refresh token and its expiration datetime.
    """
    refresh_token_expires = datetime.now(timezone.utc) + settings.refresh_token_expiry
    refresh_payload = {"sub": email, "user_id": user_id, "type": "refresh"}
    refresh_token = create_token(
        refresh_payload,
        expires_delta=settings.refresh_token_expiry
    )
    return refresh_token, refresh_token_expires

async def create_tokens(user_id: int, email: str) -> dict:
    """
    Generates both access and refresh tokens.
    This is useful for initial login/signup when both need to be created.
    """
    try:
        access_token, access_token_expires = await create_access_token_pair(user_id, email)
        refresh_token, refresh_token_expires = await create_refresh_token_pair(user_id, email)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "access_token_expires": access_token_expires.isoformat(),
            "refresh_token_expires": refresh_token_expires.isoformat()
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create tokens: {str(e)}"
        )

async def validate_token(token: str) -> dict:
    """
    Validates a JWT token and returns its payload.
    """
    try:
        payload = decode_token(token)
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )