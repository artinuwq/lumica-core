from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from .db import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    telegram_id = Column(String, unique=True, nullable=False)
    username = Column(String, nullable=True)
    name = Column(String, nullable=True)
    profile_data = Column(JSON, nullable=True)

    auth_sessions = relationship(
        "AuthSession",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    mini_app_launches = relationship(
        "MiniAppLaunch",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

class TimestampMixin:
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AuthSession(Base, TimestampMixin):
    __tablename__ = "auth_sessions"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    init_data = Column(JSON, nullable=True)
    session_token = Column(String, nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)

    user = relationship("User", back_populates="auth_sessions")


class MiniAppLaunch(Base, TimestampMixin):
    __tablename__ = "mini_app_launches"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    url = Column(String, nullable=False)
    payload = Column(JSON, nullable=True)
    status = Column(String, nullable=True)

    user = relationship("User", back_populates="mini_app_launches")

