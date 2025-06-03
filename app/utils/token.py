from datetime import datetime, timedelta, timezone # Added timezone import
from typing import Optional
from jose import JWTError, jwt
from core.config import settings

def create_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Creates a JWT token with the given data and expiration.

    Args:
        data (dict): The payload to encode into the token.
        expires_delta (Optional[timedelta]): The timedelta for token expiration.
                                             If None, uses settings.access_token_expiry.

    Returns:
        str: The encoded JWT token.
    """
    to_encode = data.copy()
    # Use timezone-aware datetime.now(timezone.utc) instead of utcnow()
    expire = datetime.now(timezone.utc) + (expires_delta or settings.access_token_expiry)
    to_encode.update({"exp": expire})
    
    # FIX: Use correct casing for SECRET_KEY and ALGORITHM
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def decode_token(token: str) -> dict:
    """
    Decodes a JWT token and returns its payload.

    Args:
        token (str): The JWT token string.

    Returns:
        dict: The decoded token payload.

    Raises:
        ValueError: If the token is invalid or expired.
    """
    try:
        # FIX: Use correct casing for SECRET_KEY and ALGORITHM
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError as e:
        # Re-raise as HTTPException or a custom exception if preferred in a FastAPI context
        # For now, keeping ValueError as per original, but consider FastAPI HTTPException
        raise ValueError("Invalid token") from e