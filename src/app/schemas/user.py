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
