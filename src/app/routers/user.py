from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import delete
from pydantic import BaseModel, EmailStr
from jose import JWTError, jwt
from typing import Optional
import random
import redis.asyncio as redis
import bcrypt
from datetime import datetime, timedelta, timezone

# Brevo API
from sib_api_v3_sdk import Configuration, ApiClient, SendSmtpEmail, TransactionalEmailsApi
from sib_api_v3_sdk.rest import ApiException

# Local modules
from app.schemas.user import UserCreate, UserOut
from app.crud.user import create_user, get_user_by_email, confirm_user_otp
from app.crud.user_token import get_valid_tokens_by_user_id, create_user_tokens
from app.core.database import get_db
from app.core.config import settings
from app.models import user, user_token

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

# ------------------------- Utility Functions -------------------------

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> user.User:
    try:
        # Check if token is blacklisted
        if await redis_client.get(f"blacklist:{token}"):
            raise HTTPException(status_code=401, detail="Token revoked")

        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token payload")

        user_obj = await get_user_by_email(db, email)
        if not user_obj:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        return user_obj
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())
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


async def send_email_via_api(recipient: str, subject: str, content: str):
    configuration = Configuration()
    configuration.api_key['api-key'] = settings.brevo_smtp_key

    api_instance = TransactionalEmailsApi(ApiClient(configuration))
    sender = {"name": "Revizer Plus", "email": settings.brevo_email}
    to = [{"email": recipient}]

    try:
        email = SendSmtpEmail(sender=sender, to=to, subject=subject, html_content=content)
        return api_instance.send_transac_email(email)
    except ApiException as e:
        raise HTTPException(status_code=500, detail=f"Brevo API error: {e}")


# ------------------------- Schemas -------------------------

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
    token_type: str = "bearer"


class UserMeResponse(UserOut):
    pass


# ------------------------- Endpoints -------------------------

@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
    if await get_user_by_email(db, user.email):
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = await create_user(db, user)
    otp = str(random.randint(100000, 999999))
    await redis_client.setex(f"otp:{user.email}", 300, otp)

    await send_email_via_api(user.email, "Your OTP Code", f"Your OTP code is: {otp}")
    return new_user

@router.post("/get_otp")
async def get_otp(data: EmailSchema, db: AsyncSession = Depends(get_db)):
    user = await get_user_by_email(db, data.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.otp_confirmed:
        raise HTTPException(status_code=400, detail="OTP already confirmed for this user")

    otp = str(random.randint(100000, 999999))
    await redis_client.setex(f"otp:{data.email}", 300, otp)

    await send_email_via_api(
        recipient=data.email,
        subject="Your OTP Code",
        content=f"Your OTP code is: {otp}"
    )
    return {"message": "OTP sent to your email"}

@router.post("/confirm_otp", response_model=TokenResponse)
async def confirm_otp(data: ConfirmOTPSchema, db: AsyncSession = Depends(get_db)):
    user = await get_user_by_email(db, data.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.otp_confirmed:
        raise HTTPException(status_code=400, detail="OTP already confirmed for this user")

    stored_otp = await redis_client.get(f"otp:{data.email}")
    if not stored_otp or stored_otp != data.otp_code:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    await confirm_user_otp(db, data.email)
    await redis_client.delete(f"otp:{data.email}")

    now = datetime.now(timezone.utc)
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

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )

@router.post("/login", response_model=TokenResponse)
async def login(data: LoginSchema, db: AsyncSession = Depends(get_db)):
    user = await get_user_by_email(db, data.email)
    
    if not user or not verify_password(data.password, user.password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    if not user.is_active or not user.otp_confirmed:
        raise HTTPException(status_code=403, detail="Account not activated")

    now = datetime.now(timezone.utc)

    # Fetch latest valid token (if any)
    existing_token = await get_valid_tokens_by_user_id(db=db, user_id=user.id, current_time=now)

    if existing_token:
        return TokenResponse(
            access_token=existing_token.access_token,
            refresh_token=existing_token.refresh_token,
            token_type="bearer"
        )

    # Generate new tokens if none are valid
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

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )

@router.get("/me", response_model=UserMeResponse)
async def read_current_user(current_user: user.User = Depends(get_current_user)):
    """Returns current authenticated user's info."""
    return current_user


@router.post("/logout")
async def logout(
    token: str = Depends(oauth2_scheme),
    current_user: user.User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Blacklist current token and optionally remove all tokens from DB."""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        exp = datetime.fromtimestamp(payload["exp"], timezone.utc)
        ttl = (exp - datetime.now(timezone.utc)).total_seconds()
        await redis_client.setex(f"blacklist:{token}", int(ttl), "revoked")

        await db.execute(delete(user_token.UserToken).where(user_token.UserToken.user_id == current_user.id))
        await db.commit()

        return {"message": "Successfully logged out"}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
