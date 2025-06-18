from pydantic import BaseModel, EmailStr, UUID4, validator
from typing import Optional, List
from datetime import datetime
import base64
import uuid

class UserBase(BaseModel):
    username: str
    email: EmailStr

class UserCreate(UserBase):
    password: str

    @validator('password')
    def password_strength(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        return v

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(UserBase):
    id: UUID4
    created_at: datetime

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    user_id: Optional[UUID4] = None

class MessageBase(BaseModel):
    recipient_id: UUID4
    subject: str
    content: str  # Plain text content to be encrypted

class MessageCreate(MessageBase):
    pass

class MessageResponse(BaseModel):
    id: UUID4
    sender_id: UUID4
    recipient_id: UUID4
    subject: str
    encrypted_content: bytes  # Will be base64 encoded in response
    encrypted_symmetric_key: bytes  # Will be base64 encoded in response
    created_at: datetime
    read_at: Optional[datetime]
    is_deleted: bool = False

    class Config:
        from_attributes = True

    @validator('encrypted_content', 'encrypted_symmetric_key')
    def encode_bytes(cls, v):
        return base64.b64encode(v).decode()

class UserPublicKey(BaseModel):
    user_id: UUID4
    public_key: bytes  # Will be base64 encoded in response

    class Config:
        from_attributes = True

    @validator('public_key')
    def encode_public_key(cls, v):
        return base64.b64encode(v).decode()

class MessageList(BaseModel):
    messages: List[MessageResponse]
    total: int

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class VerifyOTPRequest(BaseModel):
    email: EmailStr
    otp: str

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    otp: str
    new_password: str

class OTPResponse(BaseModel):
    message: str
    expires_in: int  # seconds until OTP expires 

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str