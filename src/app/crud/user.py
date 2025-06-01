from datetime import datetime, timezone
from typing import Any, Dict, Optional
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import IntegrityError
import bcrypt
from app.models.user import User, UserRole
from app.schemas.user import UserCreate

def get_password_hash(password: str) -> str:
    """Hash a password using bcrypt.

    Args:
        password: The plaintext password to hash.

    Returns:
        The hashed password as a string.

    Raises:
        RuntimeError: If bcrypt hashing fails.
    """
    try:
        # Encode password to bytes and generate a salt
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    except Exception as e:
        raise RuntimeError(f"Password hashing failed: {str(e)}")

async def create_user(db: AsyncSession, user: UserCreate) -> User:
    """Create a new user in the database.

    Args:
        db: Async SQLAlchemy session.
        user: User creation schema with user details.

    Returns:
        The created User object.

    Raises:
        ValueError: If the email is already registered.
        IntegrityError: If a database integrity error occurs (e.g., unique constraint violation).
    """
    # Check if email already exists
    existing_user = await get_user_by_email(db, user.email)
    if existing_user:
        raise ValueError("Email already registered")

    db_user = User(
        name=user.name,
        email=user.email,
        password=get_password_hash(user.password),
        gender=user.gender,
        phone_no=user.phone_no,
        filiere=user.filiere,
        profession=user.profession,
        country=user.country,
        town=user.town,
        academic_year=user.academic_year,
        dob=user.dob,
        role=UserRole.student,
        is_active=False,
        otp_confirmed=False,
    )
    try:
        db.add(db_user)
        await db.commit()
        await db.refresh(db_user)
        return db_user
    except IntegrityError as e:
        await db.rollback()
        raise ValueError(f"Failed to create user: {str(e)}")

async def confirm_user_otp(db: AsyncSession, email: str) -> Optional[User]:
    """
    Confirm a user's OTP and activate their account.

    Args:
        db: Async SQLAlchemy session.
        email: The email address of the user to confirm.

    Returns:
        The confirmed User object or None if no user is found or already confirmed.
    """
    result = await db.execute(select(User).filter(User.email == email))
    user = result.scalars().first()

    if not user:
        return None

    if not user.otp_confirmed:
        user.otp_confirmed = True
        user.is_active = True
        user.updated_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(user)

    return user


async def get_user_by_email(db: AsyncSession, email: str) -> Optional[User]:
    """Retrieve a user by their email address.

    Args:
        db: Async SQLAlchemy session.
        email: The email address to search for.

    Returns:
        The User object if found, else None.
    """
    result = await db.execute(select(User).filter(User.email == email))
    return result.scalars().first()

async def update_user_profile(db: AsyncSession, user_id: int, update_data: Dict[str, Any]) -> User:
    """
    Update user profile with the provided data.
    
    Args:
        db: Database session
        user_id: ID of the user to update
        update_data: Dictionary containing fields to update
        
    Returns:
        Updated User object
        
    Raises:
        Exception: If user not found or update fails
    """
    # Create update statement
    stmt = update(User).where(User.id == user_id).values(**update_data)
    
    # Execute the update
    result = await db.execute(stmt)
    
    # Check if any rows were affected
    if result.rowcount == 0:
        raise Exception(f"User with id {user_id} not found")
    
    # Fetch and return the updated user
    updated_user_stmt = select(User).where(User.id == user_id)
    result = await db.execute(updated_user_stmt)
    updated_user = result.scalars().first()
    
    if not updated_user:
        raise Exception(f"Failed to fetch updated user with id {user_id}")
    
    return updated_user