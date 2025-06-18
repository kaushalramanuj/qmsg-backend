from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List
import uuid

from app.core.database import get_db
from app.models.models import User
from app.schemas.schemas import UserResponse, UserPublicKey
from app.api.v1.endpoints.auth import get_current_user

router = APIRouter()

@router.get("/me", response_model=UserResponse)
async def read_user_me(current_user: User = Depends(get_current_user)):
    return current_user

@router.get("/search", response_model=List[UserResponse])
async def search_users(
    query: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    search = f"%{query}%"
    stmt = select(User).where(
        (User.username.ilike(search)) | (User.email.ilike(search))
    ).where(User.id != current_user.id)
    
    result = await db.execute(stmt)
    users = result.scalars().all()
    return users

@router.get("/{user_id}/public-key", response_model=UserPublicKey)
async def get_user_public_key(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = select(User).where(User.id == user_id)
    result = await db.execute(query)
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return {"user_id": user.id, "public_key": user.kyber_public_key} 