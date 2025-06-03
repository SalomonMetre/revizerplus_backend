import os
import uuid
from pathlib import Path
# No need for UploadFile import here, as we're directly receiving bytes

# Your custom directory for profile images
# Ensure this path is correct for your server environment
UPLOAD_DIR = Path("/home/revizerplus/uploads/profile_images")

# Make sure the directory exists
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

async def save_profile_image(image_bytes: bytes, user_id: int) -> str:
    """
    Saves a profile image to the custom directory.
    Generates a unique filename using user_id and a UUID to avoid conflicts.

    Args:
        image_bytes (bytes): The raw bytes content of the image file.
        user_id (int): The ID of the user for whom the image is being saved.

    Returns:
        str: The unique filename (e.g., 'user_id_uuid.ext') that should be
             stored in the database.
    """
    # --- IMPORTANT: Robustly determine file extension ---
    # The simplest way is to guess from magic bytes, but this is not foolproof.
    # For production, consider a more robust library like 'python-magic'
    # or ensure the client sends the correct content-type header for the image.
    
    # Basic magic number check (for common image types)
    ext = ".jpg" # Default fallback
    if image_bytes.startswith(b'\xFF\xD8\xFF'):
        ext = ".jpg"
    elif image_bytes.startswith(b'\x89PNG\r\n\x1a\n'):
        ext = ".png"
    elif image_bytes.startswith(b'GIF87a') or image_bytes.startswith(b'GIF89a'):
        ext = ".gif"
    elif image_bytes.startswith(b'\x00\x00\x00\x18ftypheic'): # HEIC/HEIF (more complex)
        ext = ".heic"
    elif image_bytes.startswith(b'\x00\x00\x00 ftypmp42') or image_bytes.startswith(b'\x00\x00\x00\x14ftypqt  '): # Basic check for MP4/MOV if you allow videos
        ext = ".mp4" # Or .mov, etc.
    # Add more checks for other formats like WebP if needed

    # Generate a unique filename using user_id for better organization/uniqueness
    unique_filename = f"{user_id}_{uuid.uuid4().hex}{ext}"
    file_path = UPLOAD_DIR / unique_filename

    try:
        # Save the file asynchronously
        # Since we already have contents (image_bytes), we just write them
        with open(file_path, "wb") as f:
            f.write(image_bytes)

        # Return just the filename. The full path can be reconstructed later
        # when serving static files or displaying the image.
        return unique_filename
    except Exception as e:
        # Log the error for debugging purposes
        print(f"Error saving profile image for user {user_id} to {file_path}: {e}")
        # Re-raise as a more specific HTTPException in the FastAPI context
        # if you want the API to return a 500 error directly from here.
        # For now, just re-raising the original exception is fine, as users/routes.py handles it.
        raise