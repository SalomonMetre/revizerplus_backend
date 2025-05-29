from sqlalchemy import Column, DateTime, Integer, String, Boolean, Date, Enum
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from enum import Enum as PyEnum
from app.models.base import Base

class UserRole(PyEnum):
    student = "student"
    admin = "admin"

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    name = Column(String)
    email = Column(String, unique=True)
    password = Column(String)
    gender = Column(String, nullable=True)
    phone_no = Column(String, nullable=True)
    filiere = Column(String, nullable=True)
    profession = Column(String, nullable=True)
    country = Column(String, nullable=True)
    town = Column(String, nullable=True)
    profile_image_id = Column(Integer, nullable=True)
    academic_year = Column(String, nullable=True)
    dob = Column(Date, nullable=True)
    role = Column(Enum(UserRole), default=UserRole.student)
    is_active = Column(Boolean, default=False)
    otp_confirmed = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    tokens = relationship("UserToken", back_populates="user")