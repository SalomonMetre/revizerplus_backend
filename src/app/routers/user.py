from fastapi import APIRouter, Depends, HTTPException, Header, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import delete, select
from pydantic import BaseModel, EmailStr
from jose import JWTError, jwt
from typing import Optional
import random
import redis.asyncio as redis
import bcrypt
from datetime import datetime, timedelta, timezone
from app.schemas.user import UpdateProfileSchema, ProfileUpdateResponse
from app.crud.user import update_user_profile

# Brevo API
from sib_api_v3_sdk import Configuration, ApiClient, SendSmtpEmail, TransactionalEmailsApi
from sib_api_v3_sdk.rest import ApiException

# Local modules
from app.schemas.user import UserCreate, UserOut
from app.crud.user import create_user, get_user_by_email, confirm_user_otp
from app.crud.user_token import get_latest_token_for_user, create_user_tokens
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

class RefreshTokenResponse(BaseModel):
    access_token: str
    access_token_expiry: str
    refresh_token: str
    refresh_token_expiry: str

class UserMeResponse(UserOut):
    pass

# ------------------------- Endpoints -------------------------

@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate, db: AsyncSession = Depends(get_db)):
    """Register a new user and send OTP for email verification."""
    if await get_user_by_email(db, user_data.email):
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = await create_user(db, user_data)
    otp = str(random.randint(100000, 999999))
    await redis_client.setex(f"otp:{user_data.email}", 300, otp)

    await send_email_via_api(
        recipient=user_data.email, 
        subject="Your OTP Code", 
        content=f"<p>Your OTP code is: <strong>{otp}</strong></p><p>This code will expire in 5 minutes.</p>"
    )
    return new_user

@router.post("/get_otp")
async def get_otp(data: EmailSchema, db: AsyncSession = Depends(get_db)):
    """Send OTP to user's email for verification."""
    user_obj = await get_user_by_email(db, data.email)
    if not user_obj:
        raise HTTPException(status_code=404, detail="User not found")

    if user_obj.otp_confirmed:
        raise HTTPException(status_code=400, detail="OTP already confirmed for this user")

    otp = str(random.randint(100000, 999999))
    await redis_client.setex(f"otp:{data.email}", 300, otp)

    await send_email_via_api(
        recipient=data.email,
        subject="Your OTP Code",
        content=f"<p>Your OTP code is: <strong>{otp}</strong></p><p>This code will expire in 5 minutes.</p>"
    )
    return {"message": "OTP sent to your email"}

@router.post("/confirm_otp", response_model=TokenResponse)
async def confirm_otp(data: ConfirmOTPSchema, db: AsyncSession = Depends(get_db)):
    """Confirm OTP and return authentication tokens."""
    user_obj = await get_user_by_email(db, data.email)
    if not user_obj:
        raise HTTPException(status_code=404, detail="User not found")

    if user_obj.otp_confirmed:
        raise HTTPException(status_code=400, detail="OTP already confirmed for this user")

    stored_otp = await redis_client.get(f"otp:{data.email}")
    if not stored_otp or stored_otp != data.otp_code:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    # Mark OTP as confirmed in DB
    await confirm_user_otp(db, data.email)
    await redis_client.delete(f"otp:{data.email}")

    # Re-fetch the updated user to ensure fresh state
    user_obj = await get_user_by_email(db, data.email)

    now = datetime.now(timezone.utc)
    token_data = {"sub": user_obj.email, "role": user_obj.role.value}
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    await create_user_tokens(
        db=db,
        user_id=user_obj.id,
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
    """Authenticate user and return tokens."""
    user_obj = await get_user_by_email(db, data.email)
    
    if not user_obj or not verify_password(data.password, user_obj.password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    if not user_obj.is_active or not user_obj.otp_confirmed:
        raise HTTPException(status_code=403, detail="Account not activated")

    now = datetime.now(timezone.utc)
    token_data = {"sub": user_obj.email, "role": user_obj.role.value}

    # Get the latest token (even if expired)
    existing_token = await get_latest_token_for_user(db, user_obj.id)
    
    # Initialize new token variables
    new_access_token = None
    new_refresh_token = None
    access_token_expiry = None
    refresh_token_expiry = None
    needs_update = False

    if existing_token:
        # Check if access token expired
        if existing_token.access_token_expiry <= now:
            new_access_token = create_access_token(token_data)
            access_token_expiry = now + timedelta(minutes=settings.access_token_expire_minutes)
            needs_update = True
        else:
            new_access_token = existing_token.access_token
            access_token_expiry = existing_token.access_token_expiry

        # Check if refresh token expired
        if existing_token.refresh_token_expiry <= now:
            new_refresh_token = create_refresh_token(token_data)
            refresh_token_expiry = now + timedelta(days=settings.refresh_token_expire_days)
            needs_update = True
        else:
            new_refresh_token = existing_token.refresh_token
            refresh_token_expiry = existing_token.refresh_token_expiry

        # Update DB if any token was renewed
        if needs_update:
            await create_user_tokens(
                db=db,
                user_id=user_obj.id,
                access_token=new_access_token,
                refresh_token=new_refresh_token,
                access_token_expiry=access_token_expiry,
                refresh_token_expiry=refresh_token_expiry
            )
    else:
        # No existing token, generate both
        new_access_token = create_access_token(token_data)
        new_refresh_token = create_refresh_token(token_data)
        access_token_expiry = now + timedelta(minutes=settings.access_token_expire_minutes)
        refresh_token_expiry = now + timedelta(days=settings.refresh_token_expire_days)

        await create_user_tokens(
            db=db,
            user_id=user_obj.id,
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            access_token_expiry=access_token_expiry,
            refresh_token_expiry=refresh_token_expiry
        )

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer"
    )

@router.get("/me", response_model=UserMeResponse)
async def read_current_user(current_user: user.User = Depends(get_current_user)):
    """Returns current authenticated user's info."""
    return current_user

@router.post("/refresh", response_model=RefreshTokenResponse)
async def refresh_token(
    refresh_token: str = Header(..., alias="X-Refresh-Token"),
    db: AsyncSession = Depends(get_db),
):
    """Refresh access and refresh tokens using a valid refresh token."""
    now = datetime.now(timezone.utc)

    # Step 1: Check if refresh token exists and is valid
    result = await db.execute(
        select(user_token.UserToken).where(user_token.UserToken.refresh_token == refresh_token)
    )
    token_record = result.scalars().first()

    if not token_record or token_record.refresh_token_expiry <= now:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    # Step 2: Get user information for token payload
    user_result = await db.execute(
        select(user.User).where(user.User.id == token_record.user_id)
    )
    user_obj = user_result.scalars().first()
    
    if not user_obj:
        raise HTTPException(status_code=401, detail="User not found")

    # Step 3: Generate new tokens with proper user data
    token_data = {"sub": user_obj.email, "role": user_obj.role.value}
    access_token_expiry = timedelta(minutes=settings.access_token_expire_minutes)
    refresh_token_expiry = timedelta(days=settings.refresh_token_expire_days)

    new_access_token = create_access_token(data=token_data, expires_delta=access_token_expiry)
    new_refresh_token = create_refresh_token(data=token_data, expires_delta=refresh_token_expiry)

    # Step 4: Save to DB (old token is deleted inside create_user_tokens)
    new_token = await create_user_tokens(
        db=db,
        user_id=user_obj.id,
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        access_token_expiry=now + access_token_expiry,
        refresh_token_expiry=now + refresh_token_expiry,
    )

    return RefreshTokenResponse(
        access_token=new_token.access_token,
        access_token_expiry=new_token.access_token_expiry.isoformat(),
        refresh_token=new_token.refresh_token,
        refresh_token_expiry=new_token.refresh_token_expiry.isoformat(),
    )
    
@router.put("/profile", response_model=ProfileUpdateResponse)
async def update_profile(
    profile_data: UpdateProfileSchema,
    current_user: user.User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Update user profile information."""
    from datetime import datetime, date
    
    updated_fields = []
    update_data = {}
    
    # Validate password change requirements
    if profile_data.new_password and not profile_data.current_password:
        raise HTTPException(
            status_code=400, 
            detail="Current password is required to change password"
        )
    
    if profile_data.current_password and not profile_data.new_password:
        raise HTTPException(
            status_code=400, 
            detail="New password is required when current password is provided"
        )
    
    # Verify current password if password change is requested
    if profile_data.current_password and profile_data.new_password:
        if not verify_password(profile_data.current_password, current_user.password):
            raise HTTPException(status_code=400, detail="Current password is incorrect")
        
        # Hash new password and add to update data
        update_data["password"] = hash_password(profile_data.new_password)
        updated_fields.append("password")
    
    # Update profile fields based on User model
    if profile_data.name is not None:
        update_data["name"] = profile_data.name.strip()
        updated_fields.append("name")
    
    if profile_data.gender is not None:
        update_data["gender"] = profile_data.gender.strip()
        updated_fields.append("gender")
    
    if profile_data.phone_no is not None:
        update_data["phone_no"] = profile_data.phone_no.strip()
        updated_fields.append("phone_no")
    
    if profile_data.filiere is not None:
        update_data["filiere"] = profile_data.filiere.strip()
        updated_fields.append("filiere")
    
    if profile_data.profession is not None:
        update_data["profession"] = profile_data.profession.strip()
        updated_fields.append("profession")
    
    if profile_data.country is not None:
        update_data["country"] = profile_data.country.strip()
        updated_fields.append("country")
    
    if profile_data.town is not None:
        update_data["town"] = profile_data.town.strip()
        updated_fields.append("town")
    
    if profile_data.academic_year is not None:
        update_data["academic_year"] = profile_data.academic_year.strip()
        updated_fields.append("academic_year")
    
    if profile_data.dob is not None:
        try:
            # Parse the date string (expected format: YYYY-MM-DD)
            dob_date = datetime.strptime(profile_data.dob, "%Y-%m-%d").date()
            update_data["dob"] = dob_date
            updated_fields.append("dob")
        except ValueError:
            raise HTTPException(
                status_code=400, 
                detail="Invalid date format. Use YYYY-MM-DD format (e.g., 1995-05-15)"
            )
    
    # Add updated_at timestamp
    if update_data:
        update_data["updated_at"] = datetime.now(timezone.utc)
    
    # Check if there's actually something to update
    if not update_data:
        raise HTTPException(status_code=400, detail="No valid fields provided for update")
    
    # Update user profile in database
    try:
        await update_user_profile(db, current_user.id, update_data)
        await db.commit()
        
        return ProfileUpdateResponse(
            message="Profile updated successfully",
            updated_fields=updated_fields
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to update profile: {str(e)}")

@router.post("/logout")
async def logout(
    token: str = Depends(oauth2_scheme),
    current_user: user.User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Blacklist current token and remove all user tokens from DB."""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        exp = datetime.fromtimestamp(payload["exp"], timezone.utc)
        ttl = max(1, int((exp - datetime.now(timezone.utc)).total_seconds()))
        await redis_client.setex(f"blacklist:{token}", ttl, "revoked")

        # Remove all tokens for this user from database
        await db.execute(delete(user_token.UserToken).where(user_token.UserToken.user_id == current_user.id))
        await db.commit()

        return {"message": "Successfully logged out"}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")