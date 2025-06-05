from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import delete
from auth.models import User, Token, ProfileImage
from auth.schemas import SignUpSchema
from datetime import datetime, timezone


async def get_user_by_email(db: AsyncSession, email: str) -> User:
    """
    Retrieves a user by their email address.
    """
    result = await db.execute(select(User).filter_by(email=email))
    return result.scalars().first()


async def check_user_exists_by_email(db: AsyncSession, email: str) -> bool:
    """
    Checks if a user exists by their email address.
    """
    user = await get_user_by_email(db, email)
    return user is not None


async def validate_access_token(db: AsyncSession, access_token: str) -> User:
    """
    Validates an access token by checking its existence and expiry in the Token table.
    Returns the associated User if valid, None otherwise.
    """
    result = await db.execute(select(Token).filter_by(access_token=access_token))
    token = result.scalars().first()
    if token:
        # Ensure expiry is timezone-aware
        expiry = token.access_token_expiry
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry > datetime.now(timezone.utc):
            user = await db.get(User, token.user_id)
            if user and user.active:
                return user
    return None


async def validate_refresh_token(db: AsyncSession, refresh_token: str, user_id: int) -> User:
    """
    Validates a refresh token by checking its existence and expiry in the Token table.
    Returns the associated User if valid, None otherwise.
    """
    result = await db.execute(select(Token).filter_by(refresh_token=refresh_token, user_id=user_id))
    token = result.scalars().first()
    if token:
        # Ensure expiry is timezone-aware
        expiry = token.refresh_token_expiry
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry > datetime.now(timezone.utc):
            user = await db.get(User, token.user_id)
            if user and user.active:
                return user
    return None


async def create_user(db: AsyncSession, user_data: SignUpSchema, hashed_password: str) -> User:
    """
    Creates a new user with the provided data and hashed password.
    """
    user = User(
        prenom=user_data.prenom,
        nom=user_data.nom,
        email=user_data.email,
        password=hashed_password,
        phone_no=user_data.phone_no,
        role=user_data.role.value,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def mark_user_verified(db: AsyncSession, user_id: int):
    """
    Marks a user as verified by setting otp_confirmed to True.
    """
    user = await db.get(User, user_id)
    if user:
        user.otp_confirmed = True
        await db.commit()
        await db.refresh(user)


async def update_password(db: AsyncSession, email: str, hashed_password: str) -> bool:
    """
    Updates the user's password given their email and a hashed password.
    Returns True if the update was successful, False if the user was not found.
    """
    user = await get_user_by_email(db, email)
    if user:
        user.password = hashed_password
        await db.commit()
        await db.refresh(user)
        return True
    return False


async def save_tokens(db: AsyncSession, user_id: int, tokens: dict):
    """
    Saves or updates access and refresh tokens for a user with timezone-aware datetimes.
    """
    existing_token_record_result = await db.execute(select(Token).filter_by(user_id=user_id))
    token_obj = existing_token_record_result.scalars().first()

    # Parse ISO timestamps and ensure UTC timezone
    access_token_expiry_dt = datetime.fromisoformat(tokens["access_token_expires"]).replace(tzinfo=timezone.utc)
    refresh_token_expiry_dt = datetime.fromisoformat(tokens["refresh_token_expires"]).replace(tzinfo=timezone.utc)

    if token_obj:
        token_obj.access_token = tokens["access_token"]
        token_obj.refresh_token = tokens["refresh_token"]
        token_obj.access_token_expiry = access_token_expiry_dt
        token_obj.refresh_token_expiry = refresh_token_expiry_dt
    else:
        token_obj = Token(
            user_id=user_id,
            access_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            access_token_expiry=access_token_expiry_dt,
            refresh_token_expiry=refresh_token_expiry_dt
        )
        db.add(token_obj)
    
    await db.commit()
    await db.refresh(token_obj)


async def revoke_tokens(db: AsyncSession, user_id: int):
    """
    Revokes all tokens for a user by deleting them from the database.
    """
    await db.execute(delete(Token).where(Token.user_id == user_id))
    await db.commit()


async def update_user_profile(db: AsyncSession, user_id: int, update_data: dict) -> User:
    """
    Updates a user's profile with the provided data.
    """
    user = await db.get(User, user_id)
    if user:
        allowed_fields = {
            "prenom", "nom", "genre", "phone_no", "pays", "ville",
            "etablissement", "profession", "filiere", "annee", "role"
        }
        for key, value in update_data.items():
            if key in allowed_fields:
                if key == "role":
                    if value is not None:
                        setattr(user, key, value.value)
                else:
                    setattr(user, key, value)
        await db.commit()
        await db.refresh(user)
    return user


async def link_profile_image(db: AsyncSession, user_id: int, filename: str):
    """
    Links a profile image to a user, replacing any existing image.
    """
    await db.execute(delete(ProfileImage).where(ProfileImage.user_id == user_id))
    
    profile_image = ProfileImage(
        user_id=user_id,
        path=filename
    )
    db.add(profile_image)
    await db.commit()


async def get_profile_image_by_user_id(db: AsyncSession, user_id: int) -> ProfileImage:
    """
    Retrieves the ProfileImage record for a given user ID.
    """
    result = await db.execute(select(ProfileImage).filter_by(user_id=user_id))
    return result.scalars().first()