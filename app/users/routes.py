from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession

from db.session import get_db
from auth import schemas
from users import crud as user_crud
from utils.dependencies import get_current_user
from auth.models import User
from utils.image_upload import save_profile_image

router = APIRouter(prefix="/users", tags=["User"])

# === Get Profile ===
@router.get("/me", response_model=schemas.UserProfile)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user

# === Update Profile ===
@router.put("/me", response_model=schemas.UserProfile)
async def update_me(
    update_data: schemas.UpdateUserProfile = Depends(),
    image: UploadFile = File(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Convert update_data to dict and remove unset values
    update_dict = update_data.model_dump(exclude_unset=True)

    if image:
        contents = await image.read()
        path = await save_profile_image(contents, current_user.id)
        await user_crud.link_profile_image(db, current_user.id, path)

    updated_user = await user_crud.update_user_profile(db, current_user.id, update_dict)
    return updated_user