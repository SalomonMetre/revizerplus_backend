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