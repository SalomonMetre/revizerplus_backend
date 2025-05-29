from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import sib_api_v3_sdk
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import delete
from pydantic import BaseModel, EmailStr
from jose import JWTError, jwt
from typing import Optional, List
import random
import redis.asyncio as redis
import bcrypt
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
import aiosmtplib

# Import your local modules
from app.schemas.user import UserCreate, UserOut
from app.crud.user import create_user, get_user_by_email, confirm_user_otp
from app.crud.user_token import get_valid_tokens_by_user_id, create_user_tokens
from app.core.database import get_db
from app.core.config import settings
from app.models import user, user_token

# sib_api_v3_sdk is the new name for Brevo's API client
from sib_api_v3_sdk import SendSmtpEmail, TransactionalEmailsApi
from sib_api_v3_sdk.rest import ApiException

router = APIRouter(prefix="/users", tags=["users"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="users/login")

# Redis client
redis_client = redis.Redis(
    host=settings.redis_host,
    port=settings.redis_port,
    db=settings.redis_db,
    password=settings.redis_password,
    decode_responses=True,
)

# Auth Utilities
async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> user.User:
    try:
        # Check if token is blacklisted
        is_blacklisted = await redis_client.get(f"blacklist:{token}")
        if is_blacklisted:
            raise HTTPException(status_code=401, detail="Token revoked")

        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        user = await get_user_by_email(db, payload.get("sub"))
        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid credentials")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), 
                            hashed_password.encode('utf-8'))
    except Exception:
        return False

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=settings.access_token_expire_minutes))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)

def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(days=settings.refresh_token_expire_days))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)

# Email Utility

async def send_email_via_api(recipient: str, subject: str, content: str):
    configuration = sib_api_v3_sdk.Configuration()
    configuration.api_key['api-key'] = settings.brevo_smtp_key  # Different from SMTP key

    api_instance = TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))
    
    sender = {"name": "Your App", "email": settings.brevo_email}
    to = [{"email": recipient}]
    
    try:
        send_smtp_email = SendSmtpEmail(
            sender=sender,
            to=to,
            subject=subject,
            html_content=content
        )
        
        api_response = api_instance.send_transac_email(send_smtp_email)
        return api_response
    except ApiException as e:
        raise HTTPException(
            status_code=500,
            detail=f"Brevo API error: {e}"
        )

# Schemas
class EmailSchema(BaseModel):
    email: EmailStr

class ConfirmOTPSchema(EmailSchema):
    otp_code: str

class LoginSchema(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class UserMeResponse(UserOut):
    pass

# Endpoints
@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
    existing = await get_user_by_email(db, user.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = await create_user(db, user)
    otp = str(random.randint(100000, 999999))
    await redis_client.setex(f"otp:{user.email}", 300, otp)

    await send_email_via_api(
        recipient=user.email,
        subject="Your OTP Code",
        content=f"Your OTP code is: {otp}"
    )
    return new_user

@router.post("/get_otp")
async def get_otp(data: EmailSchema):
    otp = str(random.randint(100000, 999999))
    await redis_client.setex(f"otp:{data.email}", 300, otp)

    await send_email_via_api(
        recipient=data.email,
        subject="Your OTP Code",
        content=f"Your OTP code is: {otp}"
    )
    return {"message": "OTP sent to your email"}

@router.post("/confirm_otp")
async def confirm_otp(data: ConfirmOTPSchema, db: AsyncSession = Depends(get_db)):
    stored_otp = await redis_client.get(f"otp:{data.email}")
    if not stored_otp or stored_otp != data.otp_code:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    user = await confirm_user_otp(db, data.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    await redis_client.delete(f"otp:{data.email}")
    return {"message": "OTP confirmed. You can now log in."}

@router.post("/login", response_model=TokenResponse)
async def login(data: LoginSchema, db: AsyncSession = Depends(get_db)):
    user = await get_user_by_email(db, data.email)
    if not user or not verify_password(data.password, user.password):
        raise HTTPException(400, "Incorrect email or password")
    if not user.is_active or not user.otp_confirmed:
        raise HTTPException(403, "Account not activated")

    now = datetime.now(timezone.utc)
    
    # Invalidate all previous tokens (optional security measure)
    await db.execute(
        delete(user_token.UserToken)
        .where(user_token.UserToken.user_id == user.id)
    )
    
    # Generate new tokens
    token_data = {"sub": user.email, "role": user.role.value}
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    await create_user_tokens(
        db=db,
        user_id=user.id,
        access_token=access_token,
        refresh_token=refresh_token,
        access_token_expiry=now + timedelta(minutes=settings.access_token_expire_minutes),
        refresh_token_expiry=now + timedelta(days=settings.refresh_token_expire_days)
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@router.get("/me", response_model=UserMeResponse)
async def read_current_user(
    current_user: user.User = Depends(get_current_user)
):
    """Get current user details"""
    return current_user

@router.post("/logout")
async def logout(
    token: str = Depends(oauth2_scheme),  # Get the token from the header
    user: user.User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Invalidate the current token and all user tokens"""
    # Add current token to Redis blacklist (expire when token expires)
    payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    expiry = datetime.fromtimestamp(payload["exp"], timezone.utc)
    remaining_ttl = (expiry - datetime.now(timezone.utc)).total_seconds()
    
    await redis_client.setex(f"blacklist:{token}", int(remaining_ttl), "revoked")
    
    # Delete all user tokens from DB (optional)
    await db.execute(delete(user_token.UserToken).where(user_token.UserToken.user_id == user.id))
    await db.commit()
    
    return {"message": "Successfully logged out"}