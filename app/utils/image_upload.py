import os
import uuid
from pathlib import Path
from PIL import Image
from io import BytesIO
# No need for UploadFile import here, as we're directly receiving bytes

# Your custom directory for profile images
# Ensure this path is correct for your server environment
UPLOAD_DIR = Path("/home/revizerplus/uploads/profile_images")

# Make sure the directory exists
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

async def save_profile_image(contents: bytes, user_id: int, filename: str) -> str:
    """
    Saves a profile image to disk with a consistent filename based on user_id.
    Returns the relative path to the saved image.
    """
    try:
        # Determine file extension from original filename
        suffix = Path(filename).suffix.lower()
        if suffix not in {".jpg", ".jpeg", ".png", ".gif", ".webp"}:
            raise ValueError(f"Unsupported image format: {suffix}")
        
        # Use consistent filename: user_<user_id><suffix>
        file_name = f"user_{user_id}{suffix}"
        file_path = UPLOAD_DIR / file_name
        
        # Validate and save image
        image = Image.open(BytesIO(contents))
        image.verify()  # Verify image integrity
        image = Image.open(BytesIO(contents))  # Reopen for saving
        image.save(file_path, format=image.format)
        
        print(f"DEBUG: Image saved for user {user_id} at {file_path}")
        return str(file_name)  # Return relative path
    except Exception as e:
        print(f"ERROR: Failed to save profile image for user {user_id}: {e}")
        raise