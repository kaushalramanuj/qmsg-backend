from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, Tuple
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
from base64 import b64encode, b64decode
from .kyber.kyber import KyberKEM

# Password hashing configuration
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Generate password hash"""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

class AESCipher:
    def __init__(self, key: bytes):
        self.key = key
        self.block_size = AES.block_size

    def encrypt(self, data: bytes) -> bytes:
        iv = get_random_bytes(self.block_size)
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return iv + tag + ciphertext

    def decrypt(self, encrypted_data: bytes) -> bytes:
        iv = encrypted_data[:self.block_size]
        tag = encrypted_data[self.block_size:self.block_size + 16]
        ciphertext = encrypted_data[self.block_size + 16:]
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
        return cipher.decrypt_and_verify(ciphertext, tag)

def generate_keypair() -> Tuple[bytes, bytes]:
    """Generate a Kyber key pair"""
    return KyberKEM.generate_keypair()

def encapsulate_key(public_key: bytes) -> Tuple[bytes, bytes]:
    """
    Encapsulate a shared secret using recipient's public key
    Returns (ciphertext, shared_secret)
    """
    return KyberKEM.encapsulate(public_key)

def decapsulate_key(ciphertext: bytes, private_key: bytes) -> bytes:
    """
    Decapsulate a shared secret using recipient's private key
    """
    return KyberKEM.decapsulate(ciphertext, private_key)

def encode_key(key: bytes) -> str:
    """Encode a key as base64"""
    return b64encode(key).decode('utf-8')

def decode_key(key_str: str) -> bytes:
    """Decode a base64 key to bytes"""
    return b64decode(key_str.encode('utf-8'))

def encrypt_private_key(private_key: bytes, password: str) -> bytes:
    """
    Encrypt a user's Kyber private key with their password
    Uses AES-GCM for authenticated encryption
    """
    key = pwd_context.hash(password)[:32].encode()
    cipher = AESCipher(key)
    return cipher.encrypt(private_key)

def decrypt_private_key(encrypted_private_key: bytes, password: str) -> bytes:
    """
    Decrypt a user's Kyber private key with their password
    Uses AES-GCM for authenticated encryption
    """
    key = pwd_context.hash(password)[:32].encode()
    cipher = AESCipher(key)
    return cipher.decrypt(encrypted_private_key) 