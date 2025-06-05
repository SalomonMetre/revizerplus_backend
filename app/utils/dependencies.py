from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession
from db.session import get_db
from core.config import settings
from auth.models import User
from users import crud as user_crud

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Retrieves the current user based on the provided JWT access token.
    Validates the token against the Token table, checks its expiry, and verifies user activity.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Decode JWT to extract email
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        
        # Validate token against Token table
        user = await user_crud.validate_access_token(db, token)
        if not user:
            raise credentials_exception
            
        # Verify user matches email and is active
        if user.email != email or not user.active:
            raise credentials_exception
            
        return user
        
    except JWTError:
        raise credentials_exception