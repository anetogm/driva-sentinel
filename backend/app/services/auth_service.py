from datetime import timedelta

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.core.security import (
    create_access_token,
    decode_access_token,
    get_password_hash,
    verify_password,
)
from app.models.user import User
from app.repositories.user import user_repo
from app.schemas.user import LoginRequest, UserCreate

logger = get_logger("auth")


class AuthService:
    @staticmethod
    async def register(db: AsyncSession, user_in: UserCreate) -> User:
        existing = await user_repo.get_by_email(db, user_in.email)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already registered",
            )
        user_data = {
            "email": user_in.email,
            "hashed_password": get_password_hash(user_in.password),
        }
        user = await user_repo.create(db, obj_in=user_data)
        logger.info("user_registered", user_id=user.id, email=user.email)
        return user

    @staticmethod
    async def authenticate(db: AsyncSession, login: LoginRequest) -> User:
        user = await user_repo.get_by_email(db, login.email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User is inactive",
            )
        if not verify_password(login.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )
        return user

    @staticmethod
    async def login(db: AsyncSession, login: LoginRequest) -> dict:
        user = await AuthService.authenticate(db, login)
        token = create_access_token(subject=user.id)
        logger.info("user_login", user_id=user.id)
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": 60 * 60 * 24 * 7,
        }

    @staticmethod
    async def get_current_user(db: AsyncSession, token: str) -> User:
        user_id = decode_access_token(token)
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )
        user = await user_repo.get(db, user_id)
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive",
            )
        return user
