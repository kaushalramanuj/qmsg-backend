from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
from base64 import b64encode, b64decode
from .kyber.kyber import KyberKEM, KyberKEMManager

# Password hashing configuration
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Global KEM manager for handling decryption
_kem_manager = KyberKEMManager()

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

def verify_access_token(token: str) -> Dict[str, Any]:
    """Verify and decode JWT access token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise Exception("Invalid token")

class AESCipher:
    """
    Fixed AES-GCM cipher implementation with proper error handling
    """
    def __init__(self, key: bytes):
        if len(key) != 32:  # AES-256 requires 32-byte key
            raise ValueError(f"AES key must be 32 bytes, got {len(key)}")
        self.key = key

    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt data using AES-GCM
        Returns: IV (12 bytes) + Tag (16 bytes) + Ciphertext
        """
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes")
            
        # Generate random IV (12 bytes recommended for GCM)
        iv = get_random_bytes(12)
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        
        # Format: IV (12) + Tag (16) + Ciphertext
        result = iv + tag + ciphertext
        print(f"🔐 AES Encryption: {len(data)} bytes -> {len(result)} bytes (IV:{len(iv)} + Tag:{len(tag)} + CT:{len(ciphertext)})")
        return result

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt AES-GCM encrypted data
        Expected format: IV (12 bytes) + Tag (16 bytes) + Ciphertext
        """
        if not isinstance(encrypted_data, bytes):
            raise TypeError("Encrypted data must be bytes")
            
        # Check minimum length
        if len(encrypted_data) < 28:  # 12 (IV) + 16 (tag) = 28 minimum
            raise ValueError(f"Encrypted data too short: {len(encrypted_data)} bytes (need at least 28)")
        
        # Extract components
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]
        
        print(f"🔓 AES Decryption: {len(encrypted_data)} bytes -> IV:{len(iv)} + Tag:{len(tag)} + CT:{len(ciphertext)}")
        
        try:
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            print(f"✅ AES Decryption successful: {len(plaintext)} bytes")
            return plaintext
        except ValueError as e:
            raise ValueError(f"AES decryption/verification failed: {str(e)}")

def generate_keypair(algorithm="Kyber512") -> Tuple[bytes, bytes]:
    """Generate a Kyber key pair"""
    return KyberKEM.generate_keypair_static(algorithm)

def encapsulate_key(public_key: bytes, algorithm="Kyber512") -> Tuple[bytes, bytes]:
    """
    Encapsulate a shared secret using recipient's public key
    Returns (ciphertext, shared_secret)
    """
    return KyberKEM.encapsulate(public_key, algorithm)

def decapsulate_key(ciphertext: bytes, private_key: bytes, algorithm="Kyber512") -> bytes:
    """
    Decapsulate a shared secret using recipient's private key
    
    IMPORTANT: This function now handles the liboqs-python limitations properly
    """
    print(f"🔑 Attempting to decapsulate key...")
    print(f"📊 Ciphertext length: {len(ciphertext)} bytes")
    print(f"📊 Private key length: {len(private_key)} bytes")
    print(f"📊 Algorithm: {algorithm}")
    
    try:
        # Try the corrected decapsulation approach
        shared_secret = _decapsulate_with_workaround(ciphertext, private_key, algorithm)
        print(f"✅ Decapsulation successful! Shared secret length: {len(shared_secret)} bytes")
        return shared_secret
        
    except Exception as e:
        print(f"❌ Decapsulation failed: {str(e)}")
        raise Exception(f"Key decapsulation failed: {str(e)}")

def _decapsulate_with_workaround(ciphertext: bytes, private_key: bytes, algorithm: str) -> bytes:
    """
    Workaround for liboqs-python decapsulation limitations
    """
    import oqs
    
    try:
        # Method 1: Try creating a new KEM instance and inject the secret key
        kem = oqs.KeyEncapsulation(algorithm)
        
        # Generate a dummy keypair to initialize the instance
        _ = kem.generate_keypair()
        
        # Try to inject our secret key into the instance
        # This is a workaround that exploits internal implementation details
        injected = False
        
        # Try different possible internal attribute names
        for attr_name in ['_secret_key', 'secret_key', '_sk', 'sk']:
            if hasattr(kem, attr_name):
                try:
                    setattr(kem, attr_name, private_key)
                    injected = True
                    print(f"✅ Successfully injected secret key via {attr_name}")
                    break
                except Exception as e:
                    print(f"⚠️  Failed to inject via {attr_name}: {e}")
                    continue
        
        if not injected:
            raise Exception("Could not inject secret key into KEM instance")
            
        # Now try decapsulation with the injected key
        shared_secret = kem.decap_secret(ciphertext)
        return shared_secret
        
    except Exception as e1:
        print(f"❌ Workaround method failed: {e1}")
        
        # Method 2: Try to use the KEM instance directly (if possible)
        try:
            # This is a fallback that might work in some versions
            kem = oqs.KeyEncapsulation(algorithm)
            
            # Some versions might support direct decapsulation
            # Try calling with both parameters (even though it should fail)
            try:
                shared_secret = kem.decap_secret(ciphertext, private_key)
                return shared_secret
            except TypeError:
                # Expected - this version doesn't support two parameters
                pass
            
            # If we get here, we need to provide a helpful error
            raise Exception(
                "Cannot decapsulate with stored secret key. "
                "This version of liboqs-python requires maintaining the original KEM instance. "
                f"Consider using KyberKEMManager for persistent key management."
            )
            
        except Exception as e2:
            raise Exception(f"All decapsulation methods failed: {e1}, {e2}")

def register_kem_instance(user_id: str, algorithm="Kyber512") -> Tuple[bytes, bytes]:
    """
    Register a new KEM instance for a user
    This allows proper decapsulation later
    """
    try:
        public_key, private_key = _kem_manager.create_keypair(user_id)
        print(f"✅ Registered KEM instance for user {user_id}")
        return public_key, private_key
    except Exception as e:
        print(f"❌ Failed to register KEM instance for user {user_id}: {e}")
        raise

def decapsulate_with_manager(user_id: str, ciphertext: bytes) -> bytes:
    """
    Decapsulate using the KEM manager (preferred method)
    """
    try:
        return _kem_manager.decapsulate(user_id, ciphertext)
    except Exception as e:
        print(f"❌ Manager decapsulation failed for user {user_id}: {e}")
        raise

def load_user_secret_key(user_id: str, private_key: bytes, algorithm="Kyber512") -> bool:
    """
    Load a user's secret key into the KEM manager
    """
    return _kem_manager.load_secret_key(user_id, private_key)

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
    
    IMPORTANT: This uses a proper key derivation function
    """
    print(f"🔐 Encrypting private key ({len(private_key)} bytes) with password...")
    
    try:
        # Use a proper key derivation from password
        # In production, use PBKDF2, scrypt, or Argon2
        from hashlib import pbkdf2_hmac
        import os
        
        # Generate a random salt
        salt = os.urandom(16)
        
        # Derive key from password using PBKDF2
        key = pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, 32)
        
        cipher = AESCipher(key)
        encrypted_key = cipher.encrypt(private_key)
        
        # Prepend salt to encrypted key
        result = salt + encrypted_key
        
        print(f"✅ Private key encrypted successfully ({len(result)} bytes)")
        return result
        
    except Exception as e:
        print(f"❌ Private key encryption failed: {e}")
        raise Exception(f"Private key encryption failed: {str(e)}")

def decrypt_private_key(encrypted_private_key: bytes, password: str) -> bytes:
    """
    Decrypt a user's Kyber private key with their password
    Uses AES-GCM for authenticated encryption
    """
    print(f"🔓 Decrypting private key ({len(encrypted_private_key)} bytes) with password...")
    
    try:
        # Check minimum length (16 bytes salt + 28 bytes minimum encrypted data)
        if len(encrypted_private_key) < 44:
            raise ValueError(f"Encrypted private key too short: {len(encrypted_private_key)} bytes")
        
        # Extract salt and encrypted data
        salt = encrypted_private_key[:16]
        encrypted_data = encrypted_private_key[16:]
        
        # Derive the same key from password
        from hashlib import pbkdf2_hmac
        key = pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, 32)
        
        cipher = AESCipher(key)
        private_key = cipher.decrypt(encrypted_data)
        
        print(f"✅ Private key decrypted successfully ({len(private_key)} bytes)")
        return private_key
        
    except Exception as e:
        print(f"❌ Private key decryption failed: {str(e)}")
        print("💡 This usually means the password is incorrect or the encrypted key is corrupted")
        raise Exception(f"Private key decryption failed: {str(e)}")

def validate_kyber_keys(public_key: bytes, private_key: bytes, algorithm="Kyber512") -> bool:
    """
    Validate that a Kyber keypair is valid by testing encryption/decryption
    """
    print(f"🧪 Validating Kyber keypair for {algorithm}...")
    
    try:
        # Test encapsulation/decapsulation cycle
        ciphertext, shared_secret1 = encapsulate_key(public_key, algorithm)
        shared_secret2 = decapsulate_key(ciphertext, private_key, algorithm)
        
        is_valid = shared_secret1 == shared_secret2
        
        if is_valid:
            print("✅ Keypair validation successful!")
        else:
            print("❌ Keypair validation failed - shared secrets don't match")
            
        return is_valid
        
    except Exception as e:
        print(f"❌ Keypair validation failed with error: {str(e)}")
        return False

def get_algorithm_info(algorithm="Kyber512") -> Dict[str, Any]:
    """Get information about a Kyber algorithm variant"""
    
    # Typical sizes for different Kyber variants
    sizes = {
        "Kyber512": {
            "public_key_size": 800,
            "private_key_size": 1632,
            "ciphertext_size": 768,
            "shared_secret_size": 32,
            "security_level": "NIST Level 1",
            "equivalent_aes": "AES-128",
            "description": "Fastest variant, good for IoT and embedded systems"
        },
        "Kyber768": {
            "public_key_size": 1184,
            "private_key_size": 2400,
            "ciphertext_size": 1088,
            "shared_secret_size": 32,
            "security_level": "NIST Level 3",
            "equivalent_aes": "AES-192",
            "description": "Balanced security and performance"
        },
        "Kyber1024": {
            "public_key_size": 1568,
            "private_key_size": 3168,
            "ciphertext_size": 1568,
            "shared_secret_size": 32,
            "security_level": "NIST Level 5",
            "equivalent_aes": "AES-256",
            "description": "Highest security level, recommended for long-term protection"
        }
    }
    
    if algorithm not in sizes:
        available = list(sizes.keys())
        raise ValueError(f"Unknown algorithm '{algorithm}'. Available: {available}")
    
    return sizes[algorithm]

def generate_shared_secret_from_password(password: str, salt: bytes = None) -> bytes:
    """
    Generate a 32-byte shared secret from a password using PBKDF2
    This can be used as an AES-256 key
    """
    from hashlib import pbkdf2_hmac
    
    if salt is None:
        salt = get_random_bytes(16)
    
    # Generate 32-byte key suitable for AES-256
    key = pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, 32)
    return key

def create_secure_message_envelope(message: bytes, recipient_public_key: bytes, 
                                 sender_private_key: bytes = None, algorithm="Kyber512") -> Dict[str, str]:
    """
    Create a secure message envelope using hybrid encryption:
    1. Generate ephemeral Kyber keypair
    2. Encapsulate shared secret with recipient's public key
    3. Encrypt message with AES-GCM using shared secret
    4. Return envelope with all necessary components
    """
    print(f"📨 Creating secure message envelope for {len(message)} byte message...")
    
    try:
        # Step 1: Encapsulate a shared secret using recipient's public key
        ciphertext, shared_secret = encapsulate_key(recipient_public_key, algorithm)
        print(f"🔑 Kyber encapsulation: {len(shared_secret)} byte shared secret")
        
        # Step 2: Encrypt the message using the shared secret
        cipher = AESCipher(shared_secret)
        encrypted_message = cipher.encrypt(message)
        print(f"🔐 AES encryption: {len(message)} -> {len(encrypted_message)} bytes")
        
        # Step 3: Create the envelope
        envelope = {
            "algorithm": algorithm,
            "kyber_ciphertext": encode_key(ciphertext),
            "encrypted_message": encode_key(encrypted_message),
            "timestamp": datetime.utcnow().isoformat(),
            "message_size": len(message)
        }
        
        print(f"✅ Secure envelope created successfully")
        return envelope
        
    except Exception as e:
        print(f"❌ Failed to create secure envelope: {e}")
        raise Exception(f"Envelope creation failed: {str(e)}")

def open_secure_message_envelope(envelope: Dict[str, str], recipient_private_key: bytes) -> bytes:
    """
    Open a secure message envelope:
    1. Extract Kyber ciphertext and encrypted message
    2. Decapsulate shared secret using recipient's private key
    3. Decrypt message using shared secret
    4. Return original message
    """
    print(f"📬 Opening secure message envelope...")
    
    try:
        # Extract components from envelope
        algorithm = envelope.get("algorithm", "Kyber512")
        kyber_ciphertext = decode_key(envelope["kyber_ciphertext"])
        encrypted_message = decode_key(envelope["encrypted_message"])
        
        print(f"📊 Envelope info: {algorithm}, CT: {len(kyber_ciphertext)} bytes, MSG: {len(encrypted_message)} bytes")
        
        # Step 1: Decapsulate the shared secret
        shared_secret = decapsulate_key(kyber_ciphertext, recipient_private_key, algorithm)
        print(f"🔑 Kyber decapsulation: {len(shared_secret)} byte shared secret recovered")
        
        # Step 2: Decrypt the message
        cipher = AESCipher(shared_secret)
        message = cipher.decrypt(encrypted_message)
        print(f"🔓 AES decryption: {len(encrypted_message)} -> {len(message)} bytes")
        
        # Verify expected size if provided
        if "message_size" in envelope:
            expected_size = envelope["message_size"]
            if len(message) != expected_size:
                print(f"⚠️  Warning: Message size mismatch. Expected {expected_size}, got {len(message)}")
        
        print(f"✅ Message envelope opened successfully")
        return message
        
    except Exception as e:
        print(f"❌ Failed to open envelope: {e}")
        raise Exception(f"Envelope opening failed: {str(e)}")

def create_user_keypair_with_backup(user_id: str, password: str, algorithm="Kyber512") -> Dict[str, str]:
    """
    Create a user keypair with encrypted backup:
    1. Generate Kyber keypair
    2. Encrypt private key with user password
    3. Register KEM instance for immediate use
    4. Return public key and encrypted private key for storage
    """
    print(f"👤 Creating keypair with backup for user {user_id}...")
    
    try:
        # Generate fresh keypair
        public_key, private_key = generate_keypair(algorithm)
        print(f"🔑 Generated {algorithm} keypair: PK={len(public_key)}, SK={len(private_key)} bytes")
        
        # Encrypt private key with password
        encrypted_private_key = encrypt_private_key(private_key, password)
        print(f"🔐 Encrypted private key: {len(encrypted_private_key)} bytes")
        
        # Register KEM instance for immediate use
        try:
            # Load the private key into KEM manager
            success = load_user_secret_key(user_id, private_key, algorithm)
            if success:
                print(f"✅ KEM instance registered for user {user_id}")
            else:
                print(f"⚠️  Warning: Could not register KEM instance, fallback methods will be used")
        except Exception as e:
            print(f"⚠️  Warning: KEM registration failed: {e}")
        
        # Return components for storage
        result = {
            "user_id": user_id,
            "algorithm": algorithm,
            "public_key": encode_key(public_key),
            "encrypted_private_key": encode_key(encrypted_private_key),
            "created_at": datetime.utcnow().isoformat(),
            "key_info": get_algorithm_info(algorithm)
        }
        
        print(f"✅ User keypair with backup created successfully")
        return result
        
    except Exception as e:
        print(f"❌ Failed to create user keypair: {e}")
        raise Exception(f"User keypair creation failed: {str(e)}")

def restore_user_keypair(user_data: Dict[str, str], password: str) -> bool:
    """
    Restore a user's keypair from encrypted backup:
    1. Decrypt private key using password
    2. Register KEM instance
    3. Validate keypair
    """
    print(f"🔄 Restoring keypair for user {user_data['user_id']}...")
    
    try:
        user_id = user_data["user_id"]
        algorithm = user_data.get("algorithm", "Kyber512")
        public_key = decode_key(user_data["public_key"])
        encrypted_private_key = decode_key(user_data["encrypted_private_key"])
        
        # Decrypt private key
        private_key = decrypt_private_key(encrypted_private_key, password)
        print(f"🔓 Private key decrypted: {len(private_key)} bytes")
        
        # Validate keypair
        if not validate_kyber_keys(public_key, private_key, algorithm):
            raise Exception("Keypair validation failed - keys don't match")
        
        # Register KEM instance
        success = load_user_secret_key(user_id, private_key, algorithm)
        if success:
            print(f"✅ KEM instance restored for user {user_id}")
        else:
            print(f"⚠️  Warning: Could not restore KEM instance")
        
        print(f"✅ User keypair restored successfully")
        return True
        
    except Exception as e:
        print(f"❌ Failed to restore user keypair: {e}")
        return False

def test_security_module():
    """Test the complete security module functionality"""
    print("🧪 Testing Security Module...")
    
    try:
        # Test 1: Basic keypair generation and validation
        print("\n1. Testing keypair generation...")
        public_key, private_key = generate_keypair("Kyber512")
        if validate_kyber_keys(public_key, private_key):
            print("✅ Keypair generation test passed")
        else:
            print("❌ Keypair generation test failed")
            return False
        
        # Test 2: Message envelope
        print("\n2. Testing secure message envelope...")
        test_message = b"Hello, this is a test message for quantum-safe encryption!"
        envelope = create_secure_message_envelope(test_message, public_key)
        decrypted_message = open_secure_message_envelope(envelope, private_key)
        
        if test_message == decrypted_message:
            print("✅ Message envelope test passed")
        else:
            print("❌ Message envelope test failed")
            return False
        
        # Test 3: User keypair with backup
        print("\n3. Testing user keypair with backup...")
        user_data = create_user_keypair_with_backup("test_user", "test_password123")
        restored = restore_user_keypair(user_data, "test_password123")
        
        if restored:
            print("✅ User backup test passed")
        else:
            print("❌ User backup test failed")
            return False
        
        print("\n✅ All security module tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Security module test failed: {e}")
        return False

if __name__ == "__main__":
    test_security_module()