import random
import string
from datetime import datetime, timedelta, timezone
from jose import JWTError
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from utils.token import create_token, decode_token
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
    return ''.join(random.choices(string.digits, k=length))

async def save_otp_to_redis(email: str, otp: str, expires_in: int = 300):
    await r.set(f"otp:{email}", otp, ex=expires_in)

async def verify_otp(email: str, otp: str) -> bool:
    stored_otp = await r.get(f"otp:{email}")
    if stored_otp and stored_otp == otp:
        await r.delete(f"otp:{email}")
        return True
    return False

# === Email Sending ===

async def send_otp_email(email: str, otp: str):
    subject = "Your Revizer Plus Verification Code"
    content = f"<p>Bonjour 👋,</p><p>Voici votre code de vérification : <strong>{otp}</strong></p><p>Ce code expire dans 5 minutes.</p>"
    return await send_email_via_api(email, subject, content)

# === Token Logic ===

async def create_tokens(user_id: int, email: str) -> dict:
    try:
        # Calculate expiration times using timezone-aware UTC
        access_token_expires = datetime.now(timezone.utc) + settings.access_token_expiry
        refresh_token_expires = datetime.now(timezone.utc) + settings.refresh_token_expiry

        # Payloads for access and refresh tokens
        access_payload = {"sub": email, "user_id": user_id, "type": "access"}
        refresh_payload = {"sub": email, "user_id": user_id, "type": "refresh"}

        # Generate tokens using settings for expiration
        access_token = create_token(
            access_payload,
            expires_delta=settings.access_token_expiry
        )
        refresh_token = create_token(
            refresh_payload,
            expires_delta=settings.refresh_token_expiry
        )

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
    try:
        payload = decode_token(token)
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )