from typing import List, Optional
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from app.models.user_token import UserToken  # Adjust import as needed

async def get_valid_tokens_by_user_id(
    *, 
    db: AsyncSession, 
    user_id: int, 
    current_time: datetime
) -> List[UserToken]:
    result = await db.execute(
        select(UserToken).where(
            UserToken.user_id == user_id,
            UserToken.access_token_expiry > current_time,
            UserToken.refresh_token_expiry > current_time
        ).order_by(UserToken.created_at.desc())
    )
    return result.scalars().all()  # Return a list of valid tokens

async def get_latest_token_for_user(
    db: AsyncSession, 
    user_id: int
) -> Optional[UserToken]:
    result = await db.execute(
        select(UserToken).where(UserToken.user_id == user_id).order_by(UserToken.created_at.desc())
    )
    return result.scalars().first()

async def create_user_tokens(
    *,
    db: AsyncSession,
    user_id: int,
    access_token: str,
    refresh_token: str,
    access_token_expiry: datetime,
    refresh_token_expiry: datetime,
) -> UserToken:
    # Validate inputs
    if user_id <= 0:
        raise ValueError("Invalid user ID")
    if not access_token or not refresh_token:
        raise ValueError("Tokens cannot be empty")
    
    current_time = datetime.now(timezone.utc)
    if access_token_expiry <= current_time:
        raise ValueError("Access token expiry must be in the future")
    if refresh_token_expiry <= current_time:
        raise ValueError("Refresh token expiry must be in the future")

    # Delete any existing valid tokens
    existing_tokens = await get_valid_tokens_by_user_id(
        db=db,
        user_id=user_id,
        current_time=current_time
    )
    
    for token in existing_tokens:
        await db.delete(token)
    if existing_tokens:
        await db.commit()

    # Create new token
    user_token = UserToken(
        user_id=user_id,
        access_token=access_token,
        refresh_token=refresh_token,
        access_token_expiry=access_token_expiry,
        refresh_token_expiry=refresh_token_expiry,
    )

    try:
        db.add(user_token)
        await db.commit()
        await db.refresh(user_token)
        return user_token
    except IntegrityError as e:
        await db.rollback()