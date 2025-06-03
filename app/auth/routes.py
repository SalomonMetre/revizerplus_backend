from fastapi import APIRouter, Depends, HTTPException, status, File, Form, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.security import OAuth2PasswordRequestForm

from db.session import get_db
from auth import schemas, services
from users import crud as user_crud
from core.security import hash_password, verify_password
from utils.dependencies import get_current_user
from auth.models import User
from utils.image_upload import save_profile_image

router = APIRouter(prefix="/auth", tags=["Auth"])

# === Signup ===
@router.post("/signup", status_code=201)
async def sign_up(user_data: schemas.SignUpSchema, db: AsyncSession = Depends(get_db)):
    if await user_crud.get_user_by_email(db, user_data.email):
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = hash_password(user_data.password)
    user = await user_crud.create_user(db, user_data, hashed_password)

    otp = services.generate_otp()
    await services.save_otp_to_redis(user.email, otp)
    await services.send_otp_email(user.email, otp)

    return {"msg": "User created. OTP sent to email."}

# === Verify Account (OTP) ===
# In auth/routes.py (verify_account route)
@router.post("/verify-account")
async def verify_account(data: schemas.OTPVerifySchema, db: AsyncSession = Depends(get_db)):
    user = await user_crud.get_user_by_email(db, data.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if await services.verify_otp(data.email, data.otp):
        await user_crud.mark_user_verified(db, user.id)
        tokens = await services.create_tokens(user.id, user.email)
        await user_crud.save_tokens(db, user.id, tokens)  # Uses Token table
        return tokens
    raise HTTPException(status_code=400, detail="Invalid OTP")

# === Login ===
@router.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    user = await user_crud.get_user_by_email(db, form_data.email)
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    if not user.otp_confirmed:
        raise HTTPException(status_code=403, detail="Email not confirmed")

    tokens = await services.create_tokens(user.id, user.email)
    await user_crud.save_tokens(db, user.id, tokens)  # Fixed: use user_crud
    return tokens

# === Logout ===
@router.post("/logout")
async def logout(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await user_crud.revoke_tokens(db, current_user.id)  # Fixed: use user_crud
    return {"msg": "Logged out successfully."}

# === Refresh Token ===
@router.post("/refresh-token")
async def refresh_token(data: schemas.RefreshTokenSchema, db: AsyncSession = Depends(get_db)):
    payload = await services.validate_token(data.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    user = await user_crud.get_user_by_email(db, payload["sub"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    tokens = await services.create_tokens(user.id, user.email)
    await user_crud.save_tokens(db, user.id, tokens)  # Fixed: use user_crud
    return tokens

# === Reset Password Request ===
@router.post("/reset-password")
async def reset_password_request(data: schemas.EmailSchema, db: AsyncSession = Depends(get_db)):
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
    if not await services.verify_otp(data.email, data.otp):
        raise HTTPException(status_code=400, detail="Invalid OTP")

    hashed_password = hash_password(data.new_password)  # Fixed: use hash_password
    await user_crud.update_password(db, data.email, hashed_password)
    return {"msg": "Password changed successfully."}