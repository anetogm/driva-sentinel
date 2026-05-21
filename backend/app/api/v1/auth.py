from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db_session, get_current_user, require_user
from app.core.logging import get_logger
from app.models.user import User
from app.schemas.user import LoginRequest, Token, UserCreate, UserRead
from app.services.auth_service import AuthService

logger = get_logger("auth_router")

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def register(
    user_in: UserCreate,
    db: AsyncSession = Depends(get_db_session),
) -> User:
    user = await AuthService.register(db, user_in)
    return user


@router.post("/login", response_model=Token)
async def login(
    login: LoginRequest,
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    return await AuthService.login(db, login)


@router.get("/me", response_model=UserRead)
async def get_me(
    current_user: User = Depends(require_user),
) -> User:
    return current_user
