from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.models.base import Base

class UserToken(Base):
    __tablename__ = "user_tokens"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    access_token = Column(String, nullable=False)
    refresh_token = Column(String, nullable=False)
    access_token_expiry = Column(DateTime(timezone=True), nullable=False)  # Added timezone=True
    refresh_token_expiry = Column(DateTime(timezone=True), nullable=False)  # Added timezone=True
    user = relationship("User", back_populates="tokens")