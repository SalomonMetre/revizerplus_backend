from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import delete
from auth.models import User, Token, ProfileImage
from auth.schemas import SignUpSchema
from datetime import datetime, timezone

async def get_user_by_email(db: AsyncSession, email: str) -> User:
    result = await db.execute(select(User).filter_by(email=email))
    return result.scalars().first()

async def create_user(db: AsyncSession, user_data: SignUpSchema, hashed_password: str) -> User:
    user = User(
        prenom=user_data.prenom,
        nom=user_data.nom,
        email=user_data.email,
        password=hashed_password,
        phone_no=user_data.phone_no,
        role=user_data.role.value,  # Use .value for Enum
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user

async def mark_user_verified(db: AsyncSession, user_id: int):
    user = await db.get(User, user_id)
    if user:
        user.otp_confirmed = True
        await db.commit()

async def update_password(db: AsyncSession, email: str, hashed_password: str):
    user = await get_user_by_email(db, email)
    if user:
        user.password = hashed_password
        await db.commit()

async def save_tokens(db: AsyncSession, user_id: int, tokens: dict):
    # Delete existing tokens for the user
    await db.execute(delete(Token).where(Token.user_id == user_id))
    
    # Create new token record
    token = Token(
        user_id=user_id,
        access_token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        access_token_expiry=datetime.fromisoformat(tokens["access_token_expires"]),
        refresh_token_expiry=datetime.fromisoformat(tokens["refresh_token_expires"])
    )
    db.add(token)
    await db.commit()

async def revoke_tokens(db: AsyncSession, user_id: int):
    await db.execute(delete(Token).where(Token.user_id == user_id))
    await db.commit()

async def update_user_profile(db: AsyncSession, user_id: int, update_data: dict) -> User:
    user = await db.get(User, user_id)
    if user:
        # Update only allowed fields
        allowed_fields = {
            "prenom", "nom", "genre", "phone_no", "pays", "ville",
            "etablissement", "profession", "filiere", "annee", "role"
        }
        for key, value in update_data.items():
            if key in allowed_fields:
                setattr(user, key, value if key != "role" else value.value)  # Handle Enum
        await db.commit()
        await db.refresh(user)
    return user

async def link_profile_image(db: AsyncSession, user_id: int, filename: str):
    # Delete existing profile image for the user
    await db.execute(delete(ProfileImage).where(ProfileImage.user_id == user_id))
    
    # Create new profile image record
    profile_image = ProfileImage(
        user_id=user_id,
        path=filename  # Store filename (e.g., uuid4().hex + ext)
    )
    db.add(profile_image)
    await db.commit()