from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timezone
from sqlalchemy.future import select

from db.session import get_db
from auth import schemas, services
from users import crud as user_crud
from core.security import hash_password, verify_password
from utils.dependencies import get_current_user
from auth.models import User, Token


router = APIRouter(prefix="/auth", tags=["Auth"])


# === Signup ===
@router.post("/signup", status_code=201)
async def sign_up(user_data: schemas.SignUpSchema, db: AsyncSession = Depends(get_db)):
    """
    Registers a new user account.
    - Checks if the email is already registered.
    - Hashes the user's password.
    - Creates the user in the database.
    - Generates and sends an OTP to the user's email for verification.
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
    Verifies a user's account using an OTP received via email.
    - Checks if the user exists.
    - Verifies the OTP against the stored one.
    - Marks the user's account as confirmed.
    - Generates and saves initial access and refresh tokens for the user.
    """
    user = await user_crud.get_user_by_email(db, data.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if await services.verify_otp(data.email, data.otp):
        await user_crud.mark_user_verified(db, user.id)
        # For initial verification, always create both tokens
        tokens = await services.create_tokens(user.id, user.email)
        await user_crud.save_tokens(db, user.id, tokens) # This will now update or create
        return tokens
    raise HTTPException(status_code=400, detail="Invalid OTP")


# === Login ===
@router.post("/login")
async def login(login_data: schemas.LoginSchema, db: AsyncSession = Depends(get_db)):
    """
    Authenticates a user with email and password.
    - Verifies credentials and OTP confirmation status.
    - Implements granular token renewal: only expired access or refresh tokens are renewed.
    - Returns current or newly generated tokens.
    """
    user = await user_crud.get_user_by_email(db, login_data.email)
    if not user or not verify_password(login_data.password, user.password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    if not user.otp_confirmed:
        raise HTTPException(status_code=403, detail="Email not confirmed")

    current_time = datetime.now(timezone.utc)
    
    # Try to fetch existing tokens for the user
    existing_token_record_result = await db.execute(select(Token).filter_by(user_id=user.id))
    existing_token_record = existing_token_record_result.scalars().first()

    # Initialize variables for the tokens to be returned
    access_token_str = None
    refresh_token_str = None
    access_token_expiry_dt = None
    refresh_token_expiry_dt = None

    if existing_token_record:
        # Assume existing tokens are the ones to return initially
        access_token_str = existing_token_record.access_token
        refresh_token_str = existing_token_record.refresh_token
        access_token_expiry_dt = existing_token_record.access_token_expiry
        refresh_token_expiry_dt = existing_token_record.refresh_token_expiry

        # Check if existing access token is expired
        if existing_token_record.access_token_expiry <= current_time:
            # Generate new access token
            access_token_str, access_token_expiry_dt = await services.create_access_token_pair(user.id, user.email)
            # Mark for update in DB
            existing_token_record.access_token = access_token_str
            existing_token_record.access_token_expiry = access_token_expiry_dt
        
        # Check if existing refresh token is expired
        if existing_token_record.refresh_token_expiry <= current_time:
            # Generate new refresh token
            refresh_token_str, refresh_token_expiry_dt = await services.create_refresh_token_pair(user.id, user.email)
            # Mark for update in DB
            existing_token_record.refresh_token = refresh_token_str
            existing_token_record.refresh_token_expiry = refresh_token_expiry_dt
        
        # Commit any updates to the existing token record if changes were made
        # This check ensures we only commit if something actually changed
        # (e.g., if one or both tokens were renewed)
        if existing_token_record.access_token != access_token_str or \
           existing_token_record.refresh_token != refresh_token_str:
            await db.commit()
            await db.refresh(existing_token_record) # Refresh to ensure latest state

    else:
        # No existing tokens, generate both new ones
        access_token_str, access_token_expiry_dt = await services.create_access_token_pair(user.id, user.email)
        refresh_token_str, refresh_token_expiry_dt = await services.create_refresh_token_pair(user.id, user.email)
        
        # Create a new token record in the database via user_crud.save_tokens
        new_tokens_data = {
            "access_token": access_token_str,
            "refresh_token": refresh_token_str,
            "access_token_expires": access_token_expiry_dt.isoformat(),
            "refresh_token_expires": refresh_token_expiry_dt.isoformat()
        }
        await user_crud.save_tokens(db, user.id, new_tokens_data)
        # Note: save_tokens handles db.add, db.commit, db.refresh internally

    # Construct the response dictionary with the current (potentially renewed) tokens
    tokens_to_return = {
        "access_token": access_token_str,
        "refresh_token": refresh_token_str,
        "access_token_expires": access_token_expiry_dt.isoformat(),
        "refresh_token_expires": refresh_token_expiry_dt.isoformat()
    }
    
    return tokens_to_return


# === Logout ===
@router.post("/logout")
async def logout(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """
    Logs out the current user by revoking their tokens (deleting them from DB).
    Requires valid authentication.
    """
    await user_crud.revoke_tokens(db, current_user.id)
    return {"msg": "Logged out successfully."}


# === Refresh Token ===
@router.post("/refresh-token")
async def refresh_token(data: schemas.RefreshTokenSchema, db: AsyncSession = Depends(get_db)):
    """
    Refreshes access and refresh tokens using a valid refresh token.
    - Validates the provided refresh token.
    - Generates new access and refresh tokens for the user.
    - Updates the tokens in the database.
    """
    payload = await services.validate_token(data.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    user = await user_crud.get_user_by_email(db, payload["sub"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # In a dedicated refresh scenario, if the refresh token itself is valid,
    # we typically generate *new* access and *new* refresh tokens
    # to maintain rolling refresh token security and prevent indefinite use of old tokens.
    tokens = await services.create_tokens(user.id, user.email)
    await user_crud.save_tokens(db, user.id, tokens) # This will update the existing record
    return tokens


# === Reset Password Request ===
@router.post("/reset-password")
async def reset_password_request(data: schemas.EmailSchema, db: AsyncSession = Depends(get_db)):
    """
    Initiates a password reset process.
    - Checks if the user exists.
    - Generates and sends an OTP to the user's email for password reset verification.
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
    - Verifies the provided OTP.
    - Hashes the new password.
    - Updates the user's password in the database.
    """
    if not await services.verify_otp(data.email, data.otp):
        raise HTTPException(status_code=400, detail="Invalid OTP")

    hashed_password = hash_password(data.new_password)
    await user_crud.update_password(db, data.email, hashed_password)
    return {"msg": "Password changed successfully."}