from typing import Optional
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
    """Confirm a user's OTP and activate their account.

    Args:
        db: Async SQLAlchemy session.
        email: The email address of the user to confirm.

    Returns:
        The confirmed User object or None if no user is found.
    """
    result = await db.execute(select(User).filter(User.email == email))
    user = result.scalars().first()
    if user and not user.otp_confirmed:
        user.otp_confirmed = True
        user.is_active = True
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