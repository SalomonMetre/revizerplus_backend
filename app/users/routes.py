from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError # Import for database errors

from db.session import get_db
from auth import schemas
from users import crud as user_crud
from utils.dependencies import get_current_user
from auth.models import User # Ensure User model is imported
from utils.image_upload import save_profile_image, UPLOAD_DIR # Ensure this is imported

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
    # Debug print: See what Pydantic model received from form
    print(f"DEBUG: update_data Pydantic model: {update_data}")

    update_dict = update_data.model_dump(exclude_unset=True) # Exclude fields not provided by client

    # Debug print: See what dictionary is passed to CRUD
    print(f"DEBUG: update_dict for CRUD: {update_dict}")

    # Handle image upload if provided
    if image and image.filename:
        print(f"DEBUG: Image file received: {image.filename}")
        try:
            contents = await image.read()
            # Basic validation for image size (e.g., max 5MB)
            if len(contents) > 5 * 1024 * 1024:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Image file too large (max 5MB)")
            
            path = await save_profile_image(contents, current_user.id)
            await user_crud.link_profile_image(db, current_user.id, path)
            print(f"DEBUG: Profile image linked: {path}")
        except Exception as e:
            # Catch specific image processing errors if possible, e.g., PIL errors
            print(f"ERROR: Failed to upload profile image: {e}") # Debug print
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to upload profile image: {e}"
            )

    # Handle profile data update
    if update_dict: # Only proceed if there's data to update
        print(f"DEBUG: Attempting to update user profile with: {update_dict}")
        try:
            updated_user = await user_crud.update_user_profile(db, current_user.id, update_dict)
            if not updated_user:
                # This case should ideally not happen if current_user is valid, but good for safety
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found for update")
            print(f"DEBUG: User profile updated successfully for user ID: {current_user.id}")
            return updated_user
        except SQLAlchemyError as e:
            # Catch database-related errors
            print(f"ERROR: Database error during profile update: {e}") # Debug print
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Database error during profile update: {e}"
            )
        except Exception as e:
            # Catch any other unexpected errors during profile update
            print(f"ERROR: An unexpected error occurred during profile update: {e}") # Debug print
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred during profile update: {e}"
            )
    else:
        print("DEBUG: No profile data or image provided for update. Returning current user.")
    
    # If no update_data and no image, return the current user profile (no change)
    return current_user # Or return a success message if no update was performed


# === Get My Profile Image ===
@router.get("/me/profile-image")
async def get_my_profile_image(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieves the profile image of the current authenticated user.
    Requires a valid access token.
    """
    # 1. Get the ProfileImage record from the database
    profile_image_record = await user_crud.get_profile_image_by_user_id(db, current_user.id)

    if not profile_image_record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile image not found for this user.")

    # 2. Construct the full absolute path to the image file
    # UPLOAD_DIR is imported from utils.image_upload
    full_image_path = UPLOAD_DIR / profile_image_record.path

    # 3. Check if the file actually exists on the file system
    if not full_image_path.is_file():
        # Log this discrepancy for debugging, as the DB record exists but file doesn't
        print(f"WARNING: Profile image record exists for user {current_user.id} "
              f"at path '{profile_image_record.path}' but file '{full_image_path}' not found on disk.")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile image file not found on server.")

    # 4. Determine media type for FileResponse (optional but good practice)
    # You might want a more robust way to determine content_type based on file extension
    # For now, a simple guess:
    content_type = "image/jpeg" # Default
    if full_image_path.suffix.lower() == ".png":
        content_type = "image/png"
    elif full_image_path.suffix.lower() == ".gif":
        content_type = "image/gif"
    elif full_image_path.suffix.lower() == ".webp":
        content_type = "image/webp"
    # Add more as needed

    # 5. Return the image file using FileResponse
    return FileResponse(full_image_path, media_type=content_type)
