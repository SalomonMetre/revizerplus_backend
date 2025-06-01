from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import date
from enum import Enum

class UserRole(str, Enum):
    admin = "admin"
    student = "student"

# Input model for registration
class UserCreate(BaseModel):
    name: Optional[str] = Field(None, example="John Doe")
    email: EmailStr
    password: str
    gender: Optional[str] = None
    phone_no: Optional[str] = None
    filiere: Optional[str] = None
    profession: Optional[str] = None
    country: Optional[str] = None
    town: Optional[str] = None
    academic_year: Optional[str] = None
    dob: Optional[date] = None

# Output model for response
class UserOut(BaseModel):
    id: int
    name: Optional[str] = None
    email: EmailStr
    gender: Optional[str] = None
    phone_no: Optional[str] = None
    filiere: Optional[str] = None
    profession: Optional[str] = None
    country: Optional[str] = None
    town: Optional[str] = None
    academic_year: Optional[str] = None
    dob: Optional[date] = None
    role: UserRole
    is_active: bool
    otp_confirmed: bool

    class Config:
        from_attributes = True

class UpdateProfileSchema(BaseModel):
    """Schema for updating user profile information."""
    name: Optional[str] = Field(None, min_length=1, max_length=100, description="User's full name")
    gender: Optional[str] = Field(None, min_length=1, max_length=20, description="User's gender")
    phone_no: Optional[str] = Field(None, min_length=10, max_length=15, description="User's phone number")
    filiere: Optional[str] = Field(None, max_length=100, description="User's field of study")
    profession: Optional[str] = Field(None, max_length=100, description="User's profession")
    country: Optional[str] = Field(None, max_length=50, description="User's country")
    town: Optional[str] = Field(None, max_length=50, description="User's town/city")
    academic_year: Optional[str] = Field(None, max_length=20, description="User's academic year")
    dob: Optional[str] = Field(None, description="User's date of birth (YYYY-MM-DD)")
    current_password: Optional[str] = Field(None, min_length=8, description="Current password (required if changing password)")
    new_password: Optional[str] = Field(None, min_length=8, description="New password")
    
    class Config:
        json_schema_extra = {
            "example": {
                "name": "John Doe",
                "gender": "Male",
                "phone_no": "+1234567890",
                "filiere": "Computer Science",
                "profession": "Software Developer",
                "country": "Kenya",
                "town": "Nairobi",
                "academic_year": "2024",
                "dob": "1995-05-15",
                "current_password": "current_password123",
                "new_password": "new_password123"
            }
        }

class ProfileUpdateResponse(BaseModel):
    """Response schema for profile update."""
    message: str
    updated_fields: list[str]
