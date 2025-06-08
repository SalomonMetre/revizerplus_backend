from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError
from db.session import get_db
from auth import schemas
from users import crud as user_crud
from utils.dependencies import get_current_user
from auth.models import User
from utils.image_upload import save_profile_image, UPLOAD_DIR
import base64
from pathlib import Path
from PIL import Image
from io import BytesIO

router = APIRouter(prefix="/users", tags=["User"])

@router.get("/me", response_model=schemas.UserProfile)
async def get_user_profile(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieves the authenticated user's profile information,
    including a compressed profile image as base64 if available.
    """
    print(f"DEBUG: Handling GET request for user ID: {current_user.id}")
    user_profile = current_user
    profile_image_record = await user_crud.get_profile_image_by_user_id(db, current_user.id)

    if profile_image_record:
        full_image_path = UPLOAD_DIR / profile_image_record.path
        if full_image_path.is_file():
            try:
                with Image.open(full_image_path) as img:
                    # Determine appropriate resample method
                    try:
                        resample = Image.Resampling.LANCZOS
                    except AttributeError:
                        resample = Image.ANTIALIAS  # Backward compatibility

                    # Resize if width exceeds max width
                    max_width = 256
                    if img.width > max_width:
                        w_percent = max_width / float(img.width)
                        h_size = int((float(img.height) * w_percent))
                        img = img.resize((max_width, h_size), resample)

                    # Convert to RGB to avoid format issues (especially with JPEG)
                    img = img.convert("RGB")

                    # Compress and encode image
                    buffer = BytesIO()
                    img.save(buffer, format="JPEG", optimize=True, quality=70)
                    buffer.seek(0)
                    encoded_image = base64.b64encode(buffer.read()).decode("utf-8")
                    mime_type = "image/jpeg"

                    user_profile.profile_picture = f"data:{mime_type};base64,{encoded_image}"

            except Exception as e:
                print(f"WARNING: Failed to read or compress profile image at '{full_image_path}': {e}")
                user_profile.profile_picture = None
        else:
            print(f"WARNING: Profile image file not found at: {full_image_path}")
            user_profile.profile_picture = None
    else:
        user_profile.profile_picture = None

    return user_profile

@router.put("/me", response_model=schemas.UserProfile)
async def update_user_profile(
    update_data: schemas.UpdateUserProfile = Depends(schemas.UpdateUserProfile.as_form),
    image: UploadFile = File(None, description="Optional profile image to upload"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Updates the authenticated user's profile information and optionally uploads a new profile picture.
    Accepts multipart/form-data input and responds with application/json.
    Only updates fields explicitly provided in the request.
    """
    print(f"DEBUG: Handling PUT request for user ID: {current_user.id}")
    print(f"DEBUG: Current user before update: {current_user.__dict__}")

    # Handle profile data update
    update_dict = update_data.model_dump(exclude_unset=True) if update_data else {}
    print(f"DEBUG: Update data provided: {update_dict}")
    if not update_dict:
        print(f"WARNING: No valid update data provided; all fields are None or unset.")
    
    if update_dict:
        try:
            updated_user = await user_crud.update_user_profile(db, current_user.id, update_dict)
            if not updated_user:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found for update")
            print(f"DEBUG: Updated user: {updated_user.__dict__}")
        except SQLAlchemyError as e:
            print(f"ERROR: Database error during profile update: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Database error during profile update: {e}"
            )
        except Exception as e:
            print(f"ERROR: Unexpected error during profile update: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Unexpected error during profile update: {e}"
            )
    else:
        updated_user = current_user
        print(f"DEBUG: No update data provided, using current user: {updated_user.__dict__}")

    # Handle image upload if provided
    if image and image.filename:
        print(f"DEBUG: Image file received: {image.filename}")
        try:
            contents = await image.read()
            if len(contents) > 5 * 1024 * 1024:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Image file too large (max 5MB)")
            path = await save_profile_image(contents, current_user.id)
            await user_crud.link_profile_image(db, current_user.id, path)
            print(f"DEBUG: Profile image linked: {path}")
        except Exception as e:
            print(f"ERROR: Failed to upload profile image: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to upload profile image: {e}"
            )

    # Prepare the response
    profile_image_record = await user_crud.get_profile_image_by_user_id(db, updated_user.id)
    user_profile = updated_user
    print(f"DEBUG: User profile before response: {user_profile.__dict__}")

    # Add profile picture as base64 with MIME type if it exists
    if profile_image_record:
        full_image_path = UPLOAD_DIR / profile_image_record.path
        if full_image_path.is_file():
            try:
                with open(full_image_path, "rb") as image_file:
                    image_data = image_file.read()
                    encoded_image = base64.b64encode(image_data).decode("utf-8")
                
                # Determine MIME type based on file extension
                mime_type = "image/jpeg"  # Default
                if full_image_path.suffix.lower() == ".png":
                    mime_type = "image/png"
                elif full_image_path.suffix.lower() == ".gif":
                    mime_type = "image/gif"
                elif full_image_path.suffix.lower() == ".webp":
                    mime_type = "image/webp"
                
                user_profile.profile_picture = f"data:{mime_type};base64,{encoded_image}"
            except Exception as e:
                print(f"WARNING: Failed to read or encode profile image at '{full_image_path}': {e}")
                user_profile.profile_picture = None
        else:
            print(f"WARNING: Profile image record exists for user {updated_user.id} "
                  f"at path '{profile_image_record.path}' but file '{full_image_path}' not found on disk.")
            user_profile.profile_picture = None
    else:
        user_profile.profile_picture = None

    print(f"DEBUG: Final response: {user_profile.__dict__}")
    return user_profile
   