from typing import Optional, Annotated
from annotated_types import Len
from pydantic import BaseModel, EmailStr, Field, ValidationError # Added ValidationError
from datetime import datetime
from enum import Enum
from fastapi import Form # Import Form for the as_form method


class UserRole(str, Enum):
    admin = "admin"
    student = "student"


class SignUpSchema(BaseModel):
    prenom: Optional[str] = Field(None, example="John")
    nom: Optional[str] = Field(None, example="Doe")
    email: EmailStr = Field(..., example="user@example.com")
    password: Annotated[str, Len(min_length=6)] = Field(..., example="strongpassword")
    phone_no: Optional[str] = Field(None, example="+123456789")
    role: UserRole = Field(default=UserRole.student, example="student")

    class Config:
        from_attributes = True


class LoginSchema(BaseModel):
    email: EmailStr = Field(..., example="user@example.com")
    password: Annotated[str, Len(min_length=6)] = Field(..., example="strongpassword")

    class Config:
        from_attributes = True


class OTPVerifySchema(BaseModel):
    email: EmailStr = Field(..., example="user@example.com")
    otp: Annotated[str, Len(min_length=6, max_length=6)] = Field(..., example="123456")

    class Config:
        from_attributes = True


class EmailSchema(BaseModel):
    email: EmailStr = Field(..., example="user@example.com")

    class Config:
        from_attributes = True


class ChangePasswordSchema(BaseModel):
    email: EmailStr = Field(..., example="user@example.com")
    otp: Annotated[str, Len(min_length=6, max_length=6)] = Field(..., example="123456")
    new_password: Annotated[str, Len(min_length=6)] = Field(..., example="newstrongpassword")

    class Config:
        from_attributes = True


class RefreshTokenSchema(BaseModel):
    refresh_token: str = Field(..., example="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")

    class Config:
        from_attributes = True


class TokenPayload(BaseModel):
    sub: str
    user_id: int
    type: str
    exp: int

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    access_token_expires: str
    refresh_token_expires: str
    token_type: str = "bearer"

    class Config:
        from_attributes = True


class UserProfile(BaseModel):
    id: int
    prenom: Optional[str]
    nom: Optional[str]
    email: EmailStr
    genre: Optional[str]
    phone_no: Optional[str]
    pays: Optional[str]
    ville: Optional[str]
    etablissement: Optional[str]
    profession: Optional[str]
    filiere: Optional[str]
    annee: Optional[str]
    otp_confirmed: bool
    active: bool
    role: UserRole
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class UpdateUserProfile(BaseModel):
    prenom: Optional[str] = None
    nom: Optional[str] = None
    genre: Optional[str] = None
    phone_no: Optional[str] = None
    pays: Optional[str] = None
    ville: Optional[str] = None
    etablissement: Optional[str] = None
    profession: Optional[str] = None
    filiere: Optional[str] = None
    annee: Optional[str] = None
    role: Optional[UserRole] = None # Still Optional, but will be converted if provided

    class Config:
        from_attributes = True

    @classmethod
    def as_form(
        cls,
        prenom: Optional[str] = Form(None),
        nom: Optional[str] = Form(None),
        genre: Optional[str] = Form(None),
        phone_no: Optional[str] = Form(None),
        pays: Optional[str] = Form(None),
        ville: Optional[str] = Form(None),
        etablissement: Optional[str] = Form(None),
        profession: Optional[str] = Form(None),
        filiere: Optional[str] = Form(None),
        annee: Optional[str] = Form(None),
        # Explicitly handle role conversion from string to UserRole Enum
        role: Optional[str] = Form(None), 
    ) -> "UpdateUserProfile":
        # Convert role string to UserRole Enum if not None
        user_role_enum = None
        if role is not None:
            try:
                user_role_enum = UserRole(role) # Attempt to convert string to Enum
            except ValueError:
                # Handle invalid role string gracefully, e.g., raise an error or log
                # For now, we'll let Pydantic's validation handle it later,
                # or you could raise HTTPException here for immediate feedback.
                print(f"Warning: Invalid role '{role}' provided in form data.")
                user_role_enum = None # Or raise HTTPException(400, "Invalid role")

        return cls(
            prenom=prenom,
            nom=nom,
            genre=genre,
            phone_no=phone_no,
            pays=pays,
            ville=ville,
            etablissement=etablissement,
            profession=profession,
            filiere=filiere,
            annee=annee,
            role=user_role_enum, # Pass the converted Enum or None
        )