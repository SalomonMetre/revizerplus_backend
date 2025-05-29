from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import date
from enum import Enum

class UserRole(str, Enum):
    admin = "admin"
    student = "student"

class UserCreate(BaseModel):
    name: Optional[str]
    email: EmailStr
    password: str
    gender: Optional[str]
    phone_no: Optional[str]
    filiere: Optional[str]
    profession: Optional[str]
    country: Optional[str]
    town: Optional[str]
    academic_year: Optional[str]
    dob: Optional[date]

class UserOut(BaseModel):
    id: int
    name: Optional[str]
    email: EmailStr
    gender: Optional[str]
    phone_no: Optional[str]
    filiere: Optional[str]
    profession: Optional[str]
    country: Optional[str]
    town: Optional[str]
    academic_year: Optional[str]
    dob: Optional[date]
    role: UserRole
    is_active: bool
    otp_confirmed: bool

    class Config:
        from_attributes = True
