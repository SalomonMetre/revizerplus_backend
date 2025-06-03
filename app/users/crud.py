from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import delete
from auth.models import User, Token, ProfileImage # Ensure Token is imported
from auth.schemas import SignUpSchema
from datetime import datetime, timezone # Ensure datetime and timezone are imported

async def get_user_by_email(db: AsyncSession, email: str) -> User:
    """
    Retrieves a user by their email address.
    """
    result = await db.execute(select(User).filter_by(email=email))
    return result.scalars().first()

async def create_user(db: AsyncSession, user_data: SignUpSchema, hashed_password: str) -> User:
    """
    Creates a new user in the database.
    """
    user = User(
        prenom=user_data.prenom,
        nom=user_data.nom,
        email=user_data.email,
        password=hashed_password,
        phone_no=user_data.phone_no,
        role=user_data.role.value,  # Use .value for Enum
        # Removed 'username' as per previous discussion
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user

async def mark_user_verified(db: AsyncSession, user_id: int):
    """
    Marks a user's email as confirmed (OTP verified).
    """
    user = await db.get(User, user_id)
    if user:
        user.otp_confirmed = True
        await db.commit()
        await db.refresh(user) # Refresh to reflect changes

async def update_password(db: AsyncSession, email: str, hashed_password: str):
    """
    Updates a user's password.
    """
    user = await get_user_by_email(db, email)
    if user:
        user.password = hashed_password
        await db.commit()
        await db.refresh(user) # Refresh to reflect changes

async def save_tokens(db: AsyncSession, user_id: int, tokens: dict):
    """
    Saves or updates access and refresh tokens for a user.
    If tokens already exist, they are updated; otherwise, new ones are created.
    """
    # Try to find an existing token record for the user
    existing_token_record_result = await db.execute(select(Token).filter_by(user_id=user_id))
    token_obj = existing_token_record_result.scalars().first()

    # Convert ISO format strings to datetime objects
    access_token_expiry_dt = datetime.fromisoformat(tokens["access_token_expires"])
    refresh_token_expiry_dt = datetime.fromisoformat(tokens["refresh_token_expires"])

    if token_obj:
        # Update existing token record
        token_obj.access_token = tokens["access_token"]
        token_obj.refresh_token = tokens["refresh_token"]
        token_obj.access_token_expiry = access_token_expiry_dt
        token_obj.refresh_token_expiry = refresh_token_expiry_dt
    else:
        # Create a new token record if none exists
        token_obj = Token(
            user_id=user_id,
            access_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            access_token_expiry=access_token_expiry_dt,
            refresh_token_expiry=refresh_token_expiry_dt
        )
        db.add(token_obj)
    
    await db.commit()
    await db.refresh(token_obj) # Refresh to get any database-generated fields if needed

async def revoke_tokens(db: AsyncSession, user_id: int):
    """
    Revokes (deletes) all tokens for a given user.
    """
    await db.execute(delete(Token).where(Token.user_id == user_id))
    await db.commit()

async def update_user_profile(db: AsyncSession, user_id: int, update_data: dict) -> User:
    """
    Updates specific fields of a user's profile.
    """
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
    """
    Links a profile image to a user, deleting any existing one.
    """
    # Delete existing profile image for the user
    await db.execute(delete(ProfileImage).where(ProfileImage.user_id == user_id))
    
    # Create new profile image record
    profile_image = ProfileImage(
        user_id=user_id,
        path=filename  # Store filename (e.g., uuid4().hex + ext)
    )
    db.add(profile_image)
    await db.commit()