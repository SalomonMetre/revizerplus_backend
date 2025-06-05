from fastapi import APIRouter, Depends, HTTPException, Header, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timezone # Ensure timezone is imported
from sqlalchemy.future import select # Ensure this import is present for database queries

from db.session import get_db
from auth import schemas, services
from users import crud as user_crud
from core.security import hash_password, verify_password
from utils.dependencies import get_current_user
from auth.models import User, Token


router = APIRouter(prefix="/auth", tags=["Auth"])

# Helper function to ensure a datetime object is UTC-aware
# This is crucial for comparing datetimes from different sources (e.g., DB and current time)
def ensure_utc_aware(dt_obj: datetime) -> datetime:
    """
    Ensures a datetime object is timezone-aware (UTC).
    If it's naive, it's assumed to be UTC and made aware.
    If it's already aware, it's converted to UTC.
    """
    if dt_obj.tzinfo is None:
        # If it's offset-naive, assume it's UTC and make it timezone-aware
        return dt_obj.replace(tzinfo=timezone.utc)
    # If it's already timezone-aware, convert it to UTC for consistent comparison
    return dt_obj.astimezone(timezone.utc)


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

    current_time = datetime.now(timezone.utc) # This is timezone-aware UTC
    
    # Try to fetch existing tokens for the user
    existing_token_record_result = await db.execute(select(Token).filter_by(user_id=user.id))
    existing_token_record = existing_token_record_result.scalars().first()

    # Initialize variables for the tokens to be returned
    access_token_str = None
    refresh_token_str = None
    access_token_expiry_dt = None
    refresh_token_expiry_dt = None

    if existing_token_record:
        # Get existing token data
        access_token_str = existing_token_record.access_token
        refresh_token_str = existing_token_record.refresh_token

        # Ensure database-retrieved expiry datetimes are UTC-aware for comparison
        # This is the crucial step to prevent TypeError
        access_token_expiry_dt = ensure_utc_aware(existing_token_record.access_token_expiry)
        refresh_token_expiry_dt = ensure_utc_aware(existing_token_record.refresh_token_expiry)

        # Flag to track if any token was renewed
        token_renewed = False

        # Check if existing access token is expired
        if access_token_expiry_dt <= current_time:
            # Generate new access token
            access_token_str, access_token_expiry_dt = await services.create_access_token_pair(user.id, user.email)
            # Update existing_token_record with the new, timezone-aware expiry
            existing_token_record.access_token = access_token_str
            existing_token_record.access_token_expiry = access_token_expiry_dt
            token_renewed = True
        
        # Check if existing refresh token is expired
        if refresh_token_expiry_dt <= current_time:
            # Generate new refresh token
            refresh_token_str, refresh_token_expiry_dt = await services.create_refresh_token_pair(user.id, user.email)
            # Update existing_token_record with the new, timezone-aware expiry
            existing_token_record.refresh_token = refresh_token_str
            existing_token_record.refresh_token_expiry = refresh_token_expiry_dt
            token_renewed = True
        
        # Commit any updates to the existing token record if changes were made
        if token_renewed:
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
async def refresh_token(
    # Refresh token is now expected in the X-Refresh-Token header
    x_refresh_token: str = Header(..., alias="X-Refresh-Token", description="Your refresh token"),
    db: AsyncSession = Depends(get_db)
):
    """
    Refreshes access and refresh tokens using a valid refresh token provided in the X-Refresh-Token header.
    - Validates the provided refresh token.
    - **Crucially, it checks the expiry of the *existing* tokens in the DB and only renews expired ones.**
    """
    # 1. Validate the incoming refresh token from the header
    payload = await services.validate_token(x_refresh_token)
    
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token type")

    # 2. Retrieve the user associated with the token's subject (email)
    user = await user_crud.get_user_by_email(db, payload["sub"])
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # 3. Fetch the existing token record for this user from the database
    existing_token_record_result = await db.execute(select(Token).filter_by(user_id=user.id))
    existing_token_record = existing_token_record_result.scalars().first()

    # Error handling: If no token record exists for the user, or the provided refresh token
    # doesn't match the one stored in the DB, it's an invalid state.
    if not existing_token_record or existing_token_record.refresh_token != x_refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or revoked refresh token")

    current_time = datetime.now(timezone.utc) # Current time, UTC-aware

    # Initialize variables for the tokens to be returned
    # Start with the existing tokens from the database
    access_token_str = existing_token_record.access_token
    refresh_token_str = existing_token_record.refresh_token
    access_token_expiry_dt = ensure_utc_aware(existing_token_record.access_token_expiry)
    refresh_token_expiry_dt = ensure_utc_aware(existing_token_record.refresh_token_expiry)

    token_renewed = False # Flag to track if any token was renewed

    # Check if access token is expired and needs renewal
    if access_token_expiry_dt <= current_time:
        access_token_str, access_token_expiry_dt = await services.create_access_token_pair(user.id, user.email)
        existing_token_record.access_token = access_token_str
        existing_token_record.access_token_expiry = access_token_expiry_dt
        token_renewed = True
    
    # Check if refresh token is expired and needs renewal
    # Note: If the refresh token itself is expired, we typically generate a *new* one
    # to maintain rolling refresh token security.
    if refresh_token_expiry_dt <= current_time:
        refresh_token_str, refresh_token_expiry_dt = await services.create_refresh_token_pair(user.id, user.email)
        existing_token_record.refresh_token = refresh_token_str
        existing_token_record.refresh_token_expiry = refresh_token_expiry_dt
        token_renewed = True
    
    # Commit changes to the database only if at least one token was renewed
    if token_renewed:
        await db.commit()
        await db.refresh(existing_token_record) # Refresh to ensure latest state from DB

    # Construct the response dictionary with the current (potentially renewed) tokens
    tokens_to_return = {
        "access_token": access_token_str,
        "refresh_token": refresh_token_str,
        "access_token_expires": access_token_expiry_dt.isoformat(),
        "refresh_token_expires": refresh_token_expiry_dt.isoformat()
    }
    
    return tokens_to_return

# === Initialize Password Reset ===
@router.post("/init-reset-password")
async def init_reset_password(data: schemas.EmailSchema, db: AsyncSession = Depends(get_db)):
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


# === Check Reset Password OTP Validity ===
@router.get("/check-reset-password-validity")
async def check_reset_password_validity(otp: str = Query(..., description="OTP to validate")):
    """
    Checks if the provided OTP is valid for password reset.
    Returns a boolean indicating OTP validity.
    """
    # Since we need to check OTP validity without knowing the email,
    # we'll need to modify the verify_otp function or create a new one
    # For now, assuming we have a function that can check OTP validity by OTP code
    is_valid = await services.check_otp_validity(otp)
    return {"valid": is_valid}


# === Reset Password ===
@router.post("/reset-password")
async def reset_password(
    data: schemas.ResetPasswordSchema, 
    otp: str = Query(..., description="OTP for password reset verification"),
    db: AsyncSession = Depends(get_db)
):
    """
    Resets a user's password after successful OTP verification.
    - Verifies the provided OTP and retrieves the associated user.
    - Validates that password and confirmPassword match.
    - Hashes the new password and updates it in the database.
    """
    # Validate that password and confirmPassword match
    if data.password != data.confirmPassword:
        raise HTTPException(status_code=400, detail="Password and confirm password do not match")
    
    # Get user email associated with the OTP and verify OTP
    user_email = await services.get_email_by_otp(otp)
    if not user_email:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")
    
    # Verify the OTP is still valid
    if not await services.verify_otp(user_email, otp):
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    # Hash the new password and update it
    hashed_password = hash_password(data.password)
    await user_crud.update_password(db, user_email, hashed_password)
    
    # Clean up the OTP from Redis after successful password reset
    await services.delete_otp_from_redis(user_email)
    
    return {"msg": "Password reset successfully. Please login with your new password."}


# === Change Password (for logged-in users) ===
@router.post("/change-password")
async def change_password(
    data: schemas.ChangePasswordAuthenticatedSchema, 
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Changes a user's password when they are already authenticated.
    - Verifies the current password.
    - Validates that new password and confirmPassword match.
    - Updates the password in the database.
    - Optionally returns new tokens after password change.
    """
    # Verify current password
    if not verify_password(data.currentPassword, current_user.password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    # Validate that new password and confirmPassword match
    if data.password != data.confirmPassword:
        raise HTTPException(status_code=400, detail="New password and confirm password do not match")
    
    # Hash the new password and update it
    hashed_password = hash_password(data.password)
    await user_crud.update_password(db, current_user.email, hashed_password)
    
    # Optionally generate new tokens after password change for security
    tokens = await services.create_tokens(current_user.id, current_user.email)
    await user_crud.save_tokens(db, current_user.id, tokens)
    
    return {
        "msg": "Password changed successfully. Please use your new password for future logins.",
        "tokens": tokens
    }


# === Legacy Reset Password Request (kept for backward compatibility) ===
@router.post("/reset-password-legacy")
async def reset_password_request(data: schemas.EmailSchema, db: AsyncSession = Depends(get_db)):
    """
    Legacy endpoint - use /init-reset-password instead.
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