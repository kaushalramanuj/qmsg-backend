from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import timedelta, datetime
import uuid
import random
import string

from app.core.database import get_db
from app.core.security import (
    verify_password, get_password_hash, create_access_token,
    KyberKEM, encrypt_private_key, ACCESS_TOKEN_EXPIRE_MINUTES
)
from app.models.models import User
from app.schemas.schemas import (
    UserCreate, UserResponse, Token, ForgotPasswordRequest,
    VerifyOTPRequest, ResetPasswordRequest, OTPResponse,ChangePasswordRequest
)
from sqlalchemy import select
from app.core.email import send_otp_email

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate, db: AsyncSession = Depends(get_db)):
    # Check if user exists
    query = select(User).where(
        (User.email == user_data.email) | (User.username == user_data.username)
    )
    result = await db.execute(query)
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered"
        )

    # Generate Kyber keypair
    public_key, private_key = KyberKEM.generate_keypair()
    
    # Create new user
    db_user = User(
        username=user_data.username,
        email=user_data.email,
        password_hash=get_password_hash(user_data.password),
        kyber_public_key=public_key,
        kyber_private_key=encrypt_private_key(private_key, user_data.password)
    )
    
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    
    return db_user

@router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    # Find user
    query = select(User).where(User.email == form_data.username)
    result = await db.execute(query)
    user = result.scalar_one_or_none()
    
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id)},
        expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        from jose import jwt
        from app.core.security import SECRET_KEY, ALGORITHM
        
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except Exception:
        raise credentials_exception
    
    query = select(User).where(User.id == uuid.UUID(user_id))
    result = await db.execute(query)
    user = result.scalar_one_or_none()
    
    if user is None:
        raise credentials_exception
    return user 

@router.post("/forgot-password", response_model=OTPResponse)
async def forgot_password(
    request: ForgotPasswordRequest,
    db: AsyncSession = Depends(get_db)
):
    # Find user by email
    query = select(User).where(User.email == request.email)
    result = await db.execute(query)
    user = result.scalar_one_or_none()
    
    if not user:
        # Don't reveal if email exists or not
        return {"message": "If your email is registered, you will receive an OTP", "expires_in": 600}
    
    # Check rate limiting
    if user.last_otp_request and (datetime.utcnow() - user.last_otp_request) < timedelta(minutes=1):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Please wait 1 minute before requesting another OTP"
        )
    
    # Generate 6-digit OTP
    otp = ''.join(random.choices(string.digits, k=6))
    
    # Store OTP and update user
    user.reset_otp = otp
    user.reset_otp_expires = datetime.utcnow() + timedelta(minutes=10)
    user.otp_attempts = 0
    user.last_otp_request = datetime.utcnow()
    await db.commit()
    
    # Send OTP email
    await send_otp_email(user.email, otp)
    
    return {"message": "If your email is registered, you will receive an OTP", "expires_in": 600}

@router.post("/verify-otp", response_model=dict)
async def verify_otp(
    request: VerifyOTPRequest,
    db: AsyncSession = Depends(get_db)
):
    # Find user by email
    query = select(User).where(User.email == request.email)
    result = await db.execute(query)
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid request"
        )
    
    # Check if OTP exists and is not expired
    if not user.reset_otp or not user.reset_otp_expires or user.reset_otp_expires < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP has expired. Please request a new one"
        )
    
    # Check OTP attempts
    if user.otp_attempts >= 3:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Too many failed attempts. Please request a new OTP"
        )
    
    # Verify OTP
    if user.reset_otp != request.otp:
        user.otp_attempts += 1
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OTP"
        )
    
    return {"message": "OTP verified successfully"}

@router.post("/change-password")
async def change_password(
    request: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    # Verify old password
    if not verify_password(request.old_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect old password"
        )
    
    # Update password
    current_user.password_hash = get_password_hash(request.new_password)
    await db.commit()
    
    return {"message": "Password updated successfully"}

@router.post("/reset-password", response_model=dict)
async def reset_password(
    request: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db)
):
    # Find user by email
    query = select(User).where(User.email == request.email)
    result = await db.execute(query)
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid request"
        )
    
    # Verify OTP
    if not user.reset_otp or not user.reset_otp_expires or user.reset_otp_expires < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP has expired. Please request a new one"
        )
    
    if user.reset_otp != request.otp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OTP"
        )
    
    # Update password
    user.password_hash = get_password_hash(request.new_password)
    user.reset_otp = None
    user.reset_otp_expires = None
    user.otp_attempts = 0
    await db.commit()
    
    return {"message": "Password has been reset successfully"} 