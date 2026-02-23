from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, Numeric, String
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
    role = Column(String, nullable=False, default="user", server_default="user")

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
    subscriptions = relationship(
        "Subscription",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    vpn_accounts = relationship(
        "VpnAccount",
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
    session_token = Column(String, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)

    user = relationship("User", back_populates="auth_sessions")


class MiniAppLaunch(Base, TimestampMixin):
    __tablename__ = "mini_app_launches"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    url = Column(String, nullable=False)
    payload = Column(JSON, nullable=True)
    status = Column(String, nullable=True)

    user = relationship("User", back_populates="mini_app_launches")


class Subscription(Base, TimestampMixin):
    __tablename__ = "subscriptions"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    status = Column(String, nullable=False, default="active", server_default="active")
    access_until = Column(DateTime(timezone=True), nullable=True)
    price_amount = Column(Numeric(10, 2), nullable=True)
    notes = Column(String, nullable=True)

    user = relationship("User", back_populates="subscriptions")


class VpnAccount(Base, TimestampMixin):
    __tablename__ = "vpn_accounts"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    protocol = Column(String, nullable=False)
    panel_inbound_id = Column(Integer, nullable=True)
    identifier = Column(String, nullable=True)
    label = Column(String, nullable=True)
    secret = Column(String, nullable=True)
    meta_json = Column("meta", JSON, nullable=True)
    status = Column(String, nullable=False, default="active", server_default="active")
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    user = relationship("User", back_populates="vpn_accounts")


class PendingBinding(Base, TimestampMixin):
    __tablename__ = "pending_bindings"

    id = Column(Integer, primary_key=True)
    telegram_id = Column(String, nullable=False)
    protocol = Column(String, nullable=False)
    panel_inbound_id = Column(Integer, nullable=False)
    identifier = Column(String, nullable=False)
    label = Column(String, nullable=True)
    secret = Column(String, nullable=True)
    meta_json = Column("meta", JSON, nullable=True)
    status = Column(String, nullable=False, default="pending", server_default="pending")
    applied_user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    applied_at = Column(DateTime(timezone=True), nullable=True)


class Inbound(Base):
    __tablename__ = "inbounds"

    id = Column(Integer, primary_key=True)
    panel_inbound_id = Column(Integer, nullable=False, unique=True)
    protocol = Column(String, nullable=True)
    port = Column(Integer, nullable=True)
    remark = Column(String, nullable=True)
    listen = Column(String, nullable=True)
    enable = Column(Integer, nullable=False, default=1, server_default="1")
    show_in_app = Column(Integer, nullable=False, default=1, server_default="1")
    stream_settings = Column(JSON, nullable=True)
    settings = Column(JSON, nullable=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
