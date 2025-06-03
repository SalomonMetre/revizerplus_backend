from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError # Import for database errors

from db.session import get_db
from auth import schemas
from users import crud as user_crud
from utils.dependencies import get_current_user
from auth.models import User # Ensure User model is imported
from utils.image_upload import save_profile_image # Ensure this is imported

router = APIRouter(prefix="/users", tags=["User"])

# === Get Profile ===
@router.get("/me", response_model=schemas.UserProfile)
async def get_me(current_user: User = Depends(get_current_user)):
    """
    Retrieves the profile information of the current authenticated user.
    """
    return current_user

# === Update Profile ===
@router.put("/me", response_model=schemas.UserProfile)
async def update_me(
    # Use the as_form class method to parse data from form fields
    update_data: schemas.UpdateUserProfile = Depends(schemas.UpdateUserProfile.as_form),
    image: UploadFile = File(None, description="Optional profile image to upload"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Updates the profile information of the current authenticated user.
    - Accepts profile fields as form data.
    - Optionally accepts a profile image file.
    - Returns the updated user profile.
    """
    update_dict = update_data.model_dump(exclude_unset=True) # Exclude fields not provided by client

    # Handle image upload if provided
    if image and image.filename:
        try:
            contents = await image.read()
            # Basic validation for image size (e.g., max 5MB)
            if len(contents) > 5 * 1024 * 1024:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Image file too large (max 5MB)")
            
            path = await save_profile_image(contents, current_user.id)
            await user_crud.link_profile_image(db, current_user.id, path)
        except Exception as e:
            # Catch specific image processing errors if possible, e.g., PIL errors
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to upload profile image: {e}"
            )

    # Handle profile data update
    if update_dict: # Only proceed if there's data to update
        try:
            updated_user = await user_crud.update_user_profile(db, current_user.id, update_dict)
            if not updated_user:
                # This case should ideally not happen if current_user is valid, but good for safety
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found for update")
            return updated_user
        except SQLAlchemyError as e:
            # Catch database-related errors
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Database error during profile update: {e}"
            )
        except Exception as e:
            # Catch any other unexpected errors during profile update
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred during profile update: {e}"
            )
    
    # If no update_data and no image, return the current user profile (no change)
    return current_user # Or return a success message if no update was performed