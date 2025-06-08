from typing import Optional, Annotated
from annotated_types import Len
from pydantic import BaseModel, EmailStr, Field, field_validator
from datetime import datetime
from enum import Enum
from fastapi import Form


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
    email: Optional[EmailStr] = Field(None, example="user@example.com")
    otp: Annotated[str, Len(min_length=6, max_length=6)] = Field(..., example="123456")

    class Config:
        from_attributes = True


class EmailSchema(BaseModel):
    email: EmailStr = Field(..., example="user@example.com")

    class Config:
        from_attributes = True


class ChangePasswordSchema(BaseModel):
    email: Optional[EmailStr] = Field(None, example="user@example.com")
    otp: Annotated[str, Len(min_length=6, max_length=6)] = Field(..., example="123456")
    new_password: Annotated[str, Len(min_length=6)] = Field(..., example="newstrongpassword")
    confirm_password: Annotated[str, Len(min_length=6)] = Field(..., example="newstrongpassword")

    @field_validator("confirm_password")
    @classmethod
    def passwords_match(cls, v, values):
        if "new_password" in values.data and v != values.data["new_password"]:
            raise ValueError("confirm_password must match new_password")
        return v

    class Config:
        from_attributes = True


class ChangePasswordAuthenticatedSchema(BaseModel):
    current_password: Annotated[str, Len(min_length=6)] = Field(..., example="currentpassword")
    new_password: Annotated[str, Len(min_length=6)] = Field(..., example="newstrongpassword")
    confirm_password: Annotated[str, Len(min_length=6)] = Field(..., example="newstrongpassword")

    @field_validator("confirm_password")
    @classmethod
    def passwords_match(cls, v, values):
        if "new_password" in values.data and v != values.data["new_password"]:
            raise ValueError("confirm_password must match new_password")
        return v

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
    profile_picture: Optional[str] = Field(None, description="Base64-encoded profile image")

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
    annee: Optional[int] = None  # Changed to int to match User model
    role: Optional[UserRole] = None

    class Config:
        from_attributes = True
        use_enum_values = True  # Serialize enums as their values

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
        annee: Optional[int] = Form(None),  # Changed to int
        role: Optional[str] = Form(None),
    ) -> "UpdateUserProfile":
        user_role_enum = None
        if role is not None:
            try:
                user_role_enum = UserRole(role)
            except ValueError:
                print(f"WARNING: Invalid role '{role}' provided in form data, setting role to None.")
        
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
            role=user_role_enum,
        )