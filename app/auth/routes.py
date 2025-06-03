from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
# Removed OAuth2PasswordRequestForm as we're using a custom schema
from datetime import datetime, timezone

from db.session import get_db
from auth import schemas, services # Ensure schemas is imported to access LoginSchema
from users import crud as user_crud
from core.security import hash_password, verify_password
from utils.dependencies import get_current_user
from auth.models import User, Token # Ensure Token model is imported

router = APIRouter(prefix="/auth", tags=["Auth"])

# === Signup ===
@router.post("/signup", status_code=201)
async def sign_up(user_data: schemas.SignUpSchema, db: AsyncSession = Depends(get_db)):
    """
    Registers a new user and sends an OTP for email verification.
    """
    if await user_crud.get_user_by_email(db, user_data.email):
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = hash_password(user_data.password)
    user = await user_crud.create_user(db, user_data, hashed_password)

    otp = services.generate_otp()
    await services.save_otp_to_redis(user.email, otp)
    await services.send_otp_email(user.email, otp)

    return {"msg": "User created. OTP sent to email."}

# === Verify Account (OTP) ===
@router.post("/verify-account")
async def verify_account(data: schemas.OTPVerifySchema, db: AsyncSession = Depends(get_db)):
    """
    Verifies a user's account using an OTP.
    Upon successful verification, generates and saves tokens.
    """
    user = await user_crud.get_user_by_email(db, data.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if await services.verify_otp(data.email, data.otp):
        await user_crud.mark_user_verified(db, user.id)
        tokens = await services.create_tokens(user.id, user.email)
        await user_crud.save_tokens(db, user.id, tokens) # This will now update or create
        return tokens
    raise HTTPException(status_code=400, detail="Invalid OTP")

# === Login ===
@router.post("/login")
async def login(login_data: schemas.LoginSchema, db: AsyncSession = Depends(get_db)): # Changed to LoginSchema
    """
    Authenticates a user with email and password, and provides tokens.
    Tokens are renewed only if expired.
    """
    # Use login_data.email instead of form_data.username
    user = await user_crud.get_user_by_email(db, login_data.email)
    if not user or not verify_password(login_data.password, user.password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    if not user.otp_confirmed:
        raise HTTPException(status_code=403, detail="Email not confirmed")

    # --- Token Renewal Logic ---
    current_time = datetime.now(timezone.utc)
    
    # Try to fetch existing tokens for the user
    existing_token_record_result = await db.execute(select(Token).filter_by(user_id=user.id))
    existing_token_record = existing_token_record_result.scalars().first()

    tokens_to_return = None

    if existing_token_record:
        # Check if existing access token is still valid
        is_access_token_valid = existing_token_record.access_token_expiry > current_time
        # Check if existing refresh token is still valid
        is_refresh_token_valid = existing_token_record.refresh_token_expiry > current_time

        if is_access_token_valid and is_refresh_token_valid:
            # Both tokens are still valid, return them
            tokens_to_return = {
                "access_token": existing_token_record.access_token,
                "refresh_token": existing_token_record.refresh_token,
                "access_token_expires": existing_token_record.access_token_expiry.isoformat(),
                "refresh_token_expires": existing_token_record.refresh_token_expiry.isoformat()
            }
        else:
            # At least one token is expired, generate new ones
            new_tokens = await services.create_tokens(user.id, user.email)
            await user_crud.save_tokens(db, user.id, new_tokens) # This will now update existing
            tokens_to_return = new_tokens
    else:
        # No existing tokens, generate new ones
        new_tokens = await services.create_tokens(user.id, user.email)
        await user_crud.save_tokens(db, user.id, new_tokens) # This will create a new record
        tokens_to_return = new_tokens
    
    return tokens_to_return

# === Logout ===
@router.post("/logout")
async def logout(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """
    Logs out the current user by revoking their tokens.
    """
    await user_crud.revoke_tokens(db, current_user.id)
    return {"msg": "Logged out successfully."}

# === Refresh Token ===
@router.post("/refresh-token")
async def refresh_token(data: schemas.RefreshTokenSchema, db: AsyncSession = Depends(get_db)):
    """
    Refreshes access and refresh tokens using a valid refresh token.
    """
    payload = await services.validate_token(data.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    user = await user_crud.get_user_by_email(db, payload["sub"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # In a refresh scenario, we always generate new tokens if the refresh token itself is valid
    tokens = await services.create_tokens(user.id, user.email)
    await user_crud.save_tokens(db, user.id, tokens)
    return tokens

# === Reset Password Request ===
@router.post("/reset-password")
async def reset_password_request(data: schemas.EmailSchema, db: AsyncSession = Depends(get_db)):
    """
    Initiates a password reset by sending an OTP to the user's email.
    """
    user = await user_crud.get_user_by_email(db, data.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    otp = services.generate_otp()
    await services.save_otp_to_redis(user.email, otp)
    await services.send_otp_email(user.email, otp)

    return {"msg": "OTP sent to your email for password reset."}

# === Change Password ===
@router.post("/change-password")
async def change_password(data: schemas.ChangePasswordSchema, db: AsyncSession = Depends(get_db)):
    """
    Changes a user's password after successful OTP verification.
    """
    if not await services.verify_otp(data.email, data.otp):
        raise HTTPException(status_code=400, detail="Invalid OTP")

    hashed_password = hash_password(data.new_password)
    await user_crud.update_password(db, data.email, hashed_password)
    return {"msg": "Password changed successfully."}