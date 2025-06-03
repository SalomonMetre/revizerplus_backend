import os
import uuid
from fastapi import UploadFile
from pathlib import Path

# Your custom directory for profile images
UPLOAD_DIR = Path("/home/revizerplus/uploads/profile_images")

# Make sure the directory exists
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

async def save_profile_image(file: UploadFile) -> str:
    """
    Save the uploaded profile image to the custom directory,
    generate a unique filename to avoid conflicts,
    and return the relative path to be stored in the DB.
    """
    # Get the file extension
    ext = os.path.splitext(file.filename)[1]
    # Generate a unique filename
    unique_filename = f"{uuid.uuid4().hex}{ext}"
    file_path = UPLOAD_DIR / unique_filename

    # Save the file asynchronously
    contents = await file.read()
    with open(file_path, "wb") as f:
        f.write(contents)

    # Return just the filename or relative path to store in DB
    return str(unique_filename)
