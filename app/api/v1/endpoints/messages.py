from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_
from datetime import datetime
from typing import List
import uuid

from app.core.database import get_db
from app.core.security import KyberKEM, AESCipher
from app.models.models import Message, User
from app.schemas.schemas import MessageCreate, MessageResponse, MessageList
from app.api.v1.endpoints.auth import get_current_user
from Crypto.Random import get_random_bytes

router = APIRouter()

@router.post("/send", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
async def send_message(
    message_data: MessageCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Get recipient's public key
    query = select(User).where(User.id == message_data.recipient_id)
    result = await db.execute(query)
    recipient = result.scalar_one_or_none()
    
    if not recipient:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recipient not found"
        )
    
    # Generate AES key for message encryption
    aes_key = get_random_bytes(32)
    cipher = AESCipher(aes_key)
    
    # Encrypt message content
    encrypted_content = cipher.encrypt(message_data.content.encode())
    
    # Encrypt AES key with recipient's Kyber public key
    encrypted_key, _ = KyberKEM.encapsulate(recipient.kyber_public_key)
    
    # Create message
    db_message = Message(
        sender_id=current_user.id,
        recipient_id=recipient.id,
        subject=message_data.subject,
        encrypted_content=encrypted_content,
        encrypted_symmetric_key=encrypted_key
    )
    
    db.add(db_message)
    await db.commit()
    await db.refresh(db_message)
    
    return db_message

@router.get("/inbox", response_model=MessageList)
async def get_inbox(
    skip: int = 0,
    limit: int = 10,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Get total count
    count_query = select(Message).where(
        and_(
            Message.recipient_id == current_user.id,
            Message.is_deleted == False
        )
    )
    result = await db.execute(count_query)
    total = len(result.scalars().all())
    
    # Get messages with pagination
    query = select(Message).where(
        and_(
            Message.recipient_id == current_user.id,
            Message.is_deleted == False
        )
    ).order_by(Message.created_at.desc()).offset(skip).limit(limit)
    
    result = await db.execute(query)
    messages = result.scalars().all()
    
    return MessageList(messages=messages, total=total)

@router.get("/sent", response_model=MessageList)
async def get_sent_messages(
    skip: int = 0,
    limit: int = 10,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Get total count
    count_query = select(Message).where(
        and_(
            Message.sender_id == current_user.id,
            Message.is_deleted == False
        )
    )
    result = await db.execute(count_query)
    total = len(result.scalars().all())
    
    # Get messages with pagination
    query = select(Message).where(
        and_(
            Message.sender_id == current_user.id,
            Message.is_deleted == False
        )
    ).order_by(Message.created_at.desc()).offset(skip).limit(limit)
    
    result = await db.execute(query)
    messages = result.scalars().all()
    
    return MessageList(messages=messages, total=total)

@router.get("/{message_id}", response_model=MessageResponse)
async def get_message(
    message_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = select(Message).where(
        and_(
            Message.id == message_id,
            or_(
                Message.sender_id == current_user.id,
                Message.recipient_id == current_user.id
            ),
            Message.is_deleted == False
        )
    )
    result = await db.execute(query)
    message = result.scalar_one_or_none()
    
    if not message:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found"
        )
    
    # Mark as read if recipient is accessing
    if message.recipient_id == current_user.id and not message.read_at:
        message.read_at = datetime.utcnow()
        await db.commit()
    
    return message

@router.delete("/{message_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_message(
    message_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = select(Message).where(
        and_(
            Message.id == message_id,
            or_(
                Message.sender_id == current_user.id,
                Message.recipient_id == current_user.id
            ),
            Message.is_deleted == False
        )
    )
    result = await db.execute(query)
    message = result.scalar_one_or_none()
    
    if not message:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found"
        )
    
    message.is_deleted = True
    await db.commit()
    return None 