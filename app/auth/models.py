from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, Text, TIMESTAMP
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from db.base import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    prenom = Column(String(100), nullable=True)
    nom = Column(String(100), nullable=True)
    genre = Column(String(20), nullable=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    phone_no = Column(String(20), nullable=True)
    pays = Column(String(100), nullable=True)
    ville = Column(String(100), nullable=True)
    etablissement = Column(String(255), nullable=True)
    profession = Column(String(100), nullable=True)
    filiere = Column(String(100), nullable=True)
    annee = Column(String(50), nullable=True)
    password = Column(String(255), nullable=False)
    otp_confirmed = Column(Boolean, default=False)
    active = Column(Boolean, default=True)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now())

    tokens = relationship("Token", back_populates="user", cascade="all, delete")
    profile_image = relationship("ProfileImage", back_populates="user", uselist=False, cascade="all, delete")


class Token(Base):
    __tablename__ = "tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    access_token = Column(Text, nullable=False)
    refresh_token = Column(Text, nullable=False)
    access_token_expiry = Column(TIMESTAMP(timezone=True), nullable=False)
    refresh_token_expiry = Column(TIMESTAMP(timezone=True), nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now())

    user = relationship("User", back_populates="tokens")


class ProfileImage(Base):
    __tablename__ = "profile_images"

    id = Column(Integer, primary_key=True, index=True)
    path = Column(String(255), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now())

    user = relationship("User", back_populates="profile_image")
