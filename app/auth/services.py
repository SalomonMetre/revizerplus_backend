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
        
async def check_otp_validity(otp: str) -> bool:
    """
    Checks if an OTP is valid without requiring the email.
    This scans through all OTP keys in Redis to find a matching OTP.
    Note: This is less efficient than email-based lookup but necessary for the API design.
    """
    try:
        # Get all OTP keys from Redis
        otp_keys = await r.keys("otp:*")
        
        # Check each stored OTP to see if it matches
        for key in otp_keys:
            stored_otp = await r.get(key)
            if stored_otp == otp:
                return True
        
        return False
    except Exception as e:
        print(f"ERROR: Failed to check OTP validity: {e}")
        return False


async def get_email_by_otp(otp: str) -> str | None:
    """
    Retrieves the email associated with a given OTP.
    This is used when we have an OTP but need to find which user it belongs to.
    """
    try:
        # Get all OTP keys from Redis
        otp_keys = await r.keys("otp:*")
        
        # Check each stored OTP to find the matching one
        for key in otp_keys:
            stored_otp = await r.get(key)
            if stored_otp == otp:
                # Extract email from the key format "otp:email@example.com"
                email = key.replace("otp:", "")
                return email
        
        return None
    except Exception as e:
        print(f"ERROR: Failed to get email by OTP: {e}")
        return None


async def delete_otp_from_redis(email: str):
    """
    Deletes an OTP from Redis for a given email.
    This is used for cleanup after successful password reset.
    """
    try:
        await r.delete(f"otp:{email}")
    except Exception as e:
        print(f"ERROR: Failed to delete OTP from Redis: {e}")


# === Enhanced OTP Functions ===

async def save_otp_with_reverse_lookup(email: str, otp: str, expires_in: int = 300):
    """
    Enhanced version of save_otp_to_redis that also stores a reverse lookup.
    This makes OTP-to-email lookups more efficient.
    """
    try:
        # Store the main OTP mapping (email -> OTP)
        await r.set(f"otp:{email}", otp, ex=expires_in)
        
        # Store reverse lookup (OTP -> email) for efficient lookups
        await r.set(f"otp_reverse:{otp}", email, ex=expires_in)
    except Exception as e:
        print(f"ERROR: Failed to save OTP with reverse lookup: {e}")
        raise


async def get_email_by_otp_efficient(otp: str) -> str | None:
    """
    More efficient version of get_email_by_otp using reverse lookup.
    Use this if you implement save_otp_with_reverse_lookup.
    """
    try:
        email = await r.get(f"otp_reverse:{otp}")
        return email
    except Exception as e:
        print(f"ERROR: Failed to get email by OTP (efficient): {e}")
        return None

async def delete_otp_with_reverse_cleanup(email: str, otp: str = None):
    """
    Enhanced cleanup that removes both main and reverse lookup entries.
    If OTP is not provided, it will fetch it first.
    """
    try:
        if not otp:
            otp = await r.get(f"otp:{email}")
        
        if otp:
            # Delete both the main entry and reverse lookup
            await r.delete(f"otp:{email}")
            await r.delete(f"otp_reverse:{otp}")
    except Exception as e:
        print(f"ERROR: Failed to delete OTP with reverse cleanup: {e}")


# === Optional: OTP Management Functions ===

async def cleanup_expired_otps():
    """
    Optional utility function to clean up any orphaned OTP entries.
    This can be called periodically or on application startup.
    """
    try:
        # Redis should handle expiration automatically, but this provides manual cleanup
        otp_keys = await r.keys("otp:*")
        reverse_keys = await r.keys("otp_reverse:*")
        
        # Check for orphaned entries and clean them up
        for key in otp_keys:
            if not await r.exists(key):
                await r.delete(key)
                
        for key in reverse_keys:
            if not await r.exists(key):
                await r.delete(key)
                
    except Exception as e:
        print(f"ERROR: Failed to cleanup expired OTPs: {e}")


async def get_otp_ttl(email: str) -> int:
    """
    Gets the remaining time-to-live for an OTP in seconds.
    Returns -1 if the key doesn't exist, -2 if it exists but has no expiry.
    """
    try:
        ttl = await r.ttl(f"otp:{email}")
        return ttl
    except Exception as e:
        print(f"ERROR: Failed to get OTP TTL: {e}")
        return -1