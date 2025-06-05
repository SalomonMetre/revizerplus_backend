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
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="JWT token missing 'sub' claim",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        print(f"DEBUG: JWT decoded successfully, email: {email}")
        
        # Validate token against Token table
        user = await user_crud.validate_access_token(db, token)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Access token not found or expired in database",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        print(f"DEBUG: Token validated in database, user ID: {user.id}, email: {user.email}")
        
        # Verify user matches email and is active
        if user.email != email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="JWT email does not match user email",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        if not user.active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is inactive",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        print(f"DEBUG: User verified, active: {user.active}")
        
        return user
        
    except JWTError as e:
        print(f"DEBUG: JWT decoding failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid JWT token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )