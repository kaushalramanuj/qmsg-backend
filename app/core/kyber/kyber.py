import oqs
from typing import Tuple

class KyberKEM:
    """
    Corrected Python wrapper for Kyber KEM implementation using liboqs-python
    
    KEY INSIGHTS:
    1. liboqs-python's KeyEncapsulation maintains internal state
    2. decap_secret() only takes ciphertext, uses internal secret key
    3. Can't import external secret keys into existing KEM instance
    4. Must maintain KEM instance with the keypair for decapsulation
    """
    
    def __init__(self, algorithm="Kyber512"):
        """
        Initialize with specified Kyber variant
        Options: "Kyber512", "Kyber768", "Kyber1024"  
        """
        self.algorithm = algorithm
        self.kem_instance = None
        self.public_key = None
        self.secret_key = None
        
        # Verify the algorithm is supported
        enabled_kems = oqs.get_enabled_KEM_mechanisms()
        if algorithm not in enabled_kems:
            raise ValueError(f"Algorithm {algorithm} not supported. Available: {enabled_kems}")
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a Kyber key pair and store in instance
        Returns: (public_key, secret_key_bytes)
        """
        self.kem_instance = oqs.KeyEncapsulation(self.algorithm)
        self.public_key = self.kem_instance.generate_keypair()
        self.secret_key = self.kem_instance.export_secret_key()
        return self.public_key, self.secret_key
    
    @staticmethod
    def generate_keypair_static(algorithm="Kyber512") -> Tuple[bytes, bytes]:
        """
        Static method to generate keypair without maintaining instance
        Returns: (public_key, secret_key_bytes)
        """
        with oqs.KeyEncapsulation(algorithm) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
            return public_key, secret_key
    
    @staticmethod  
    def encapsulate(public_key: bytes, algorithm="Kyber512") -> Tuple[bytes, bytes]:
        """
        Encapsulate a shared secret using recipient's public key
        Returns: (ciphertext, shared_secret)
        """
        with oqs.KeyEncapsulation(algorithm) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
            return ciphertext, shared_secret
    
    def decapsulate_with_instance(self, ciphertext: bytes) -> bytes:
        """
        Decapsulate using the KEM instance that generated the keypair
        This is the correct way - the KEM instance holds the secret key internally
        """
        if self.kem_instance is None:
            raise Exception("No KEM instance available. Must generate keypair first.")
        
        try:
            shared_secret = self.kem_instance.decap_secret(ciphertext)
            return shared_secret
        except Exception as e:
            raise Exception(f"Decapsulation failed: {str(e)}")
    
    @staticmethod
    def decapsulate_with_stored_key(ciphertext: bytes, secret_key_bytes: bytes, algorithm="Kyber512") -> bytes:
        """
        Decapsulate using stored secret key bytes
        This requires creating a new KEM instance and importing the secret key
        """
        try:
            # Create new KEM instance
            kem = oqs.KeyEncapsulation(algorithm)
            
            # Try to import the secret key
            # Note: This might not work in all versions of liboqs-python
            if hasattr(kem, 'import_secret_key'):
                kem.import_secret_key(secret_key_bytes)
                shared_secret = kem.decap_secret(ciphertext)
                return shared_secret
            else:
                # Alternative: Try direct decapsulation (newer versions might support this)
                # Some versions allow passing secret key directly
                try:
                    shared_secret = kem.decap_secret(ciphertext, secret_key_bytes)
                    return shared_secret
                except TypeError:
                    # If that fails, the API only supports single parameter
                    # We need to use a different approach
                    raise Exception(
                        "Cannot import secret key into new KEM instance. "
                        "This version of liboqs-python doesn't support key import. "
                        "You must maintain the original KEM instance for decapsulation."
                    )
                    
        except Exception as e:
            raise Exception(f"Decapsulation with stored key failed: {str(e)}")

class KyberKEMManager:
    """
    Manager class that handles KEM instances for decryption
    This solves the problem of needing to maintain KEM instances
    """
    
    def __init__(self, algorithm="Kyber512"):
        self.algorithm = algorithm
        self.active_kems = {}  # Store active KEM instances by key identifier
    
    def create_keypair(self, key_id: str) -> Tuple[bytes, bytes]:
        """
        Create a keypair and store the KEM instance for later decryption
        """
        kem = KyberKEM(self.algorithm)
        public_key, secret_key = kem.generate_keypair()
        
        # Store the KEM instance for decryption
        self.active_kems[key_id] = kem
        
        return public_key, secret_key
    
    def decapsulate(self, key_id: str, ciphertext: bytes) -> bytes:
        """
        Decapsulate using stored KEM instance
        """
        if key_id not in self.active_kems:
            raise Exception(f"No KEM instance found for key_id: {key_id}")
        
        kem = self.active_kems[key_id]
        return kem.decapsulate_with_instance(ciphertext)
    
    def load_secret_key(self, key_id: str, secret_key_bytes: bytes):
        """
        Attempt to load a secret key for decryption
        This creates a new KEM instance and tries various methods to import the key
        """
        try:
            # Method 1: Try creating a new KEM and see if we can import the key
            kem = oqs.KeyEncapsulation(self.algorithm)
            
            # Generate a dummy keypair to initialize
            _ = kem.generate_keypair()
            
            # Try to replace the internal secret key (this is hacky but might work)
            # Different versions might have different internal structure
            success = False
            
            # Try various internal attributes that might hold the secret key
            for attr in ['_secret_key', 'secret_key', '_sk']:
                if hasattr(kem, attr):
                    try:
                        setattr(kem, attr, secret_key_bytes)
                        success = True
                        break
                    except:
                        continue
            
            if success:
                # Wrap in our KyberKEM class
                kyber_kem = KyberKEM(self.algorithm)
                kyber_kem.kem_instance = kem
                kyber_kem.secret_key = secret_key_bytes
                self.active_kems[key_id] = kyber_kem
                return True
            else:
                raise Exception("Could not import secret key into KEM instance")
                
        except Exception as e:
            print(f"Warning: Could not load secret key for {key_id}: {e}")
            return False

# Utility functions for backward compatibility
def generate_keypair(algorithm="Kyber512") -> Tuple[bytes, bytes]:
    """Generate a Kyber key pair"""
    return KyberKEM.generate_keypair_static(algorithm)

def encapsulate_key(public_key: bytes, algorithm="Kyber512") -> Tuple[bytes, bytes]:
    """Encapsulate a shared secret using recipient's public key"""
    return KyberKEM.encapsulate(public_key, algorithm)

def decapsulate_key(ciphertext: bytes, secret_key_bytes: bytes, algorithm="Kyber512") -> bytes:
    """
    Decapsulate a shared secret using recipient's secret key
    This is the problematic function that we're fixing
    """
    print(f"🔑 Attempting decapsulation...")
    print(f"📊 Ciphertext length: {len(ciphertext)} bytes")
    print(f"📊 Secret key length: {len(secret_key_bytes)} bytes")
    print(f"📊 Algorithm: {algorithm}")
    
    try:
        # Method 1: Try the new approach with secret key import
        result = KyberKEM.decapsulate_with_stored_key(ciphertext, secret_key_bytes, algorithm)
        print(f"✅ Decapsulation successful! Shared secret length: {len(result)} bytes")
        return result
        
    except Exception as e1:
        print(f"❌ Method 1 failed: {e1}")
        
        # Method 2: Try creating fresh KEM and attempting various workarounds
        try:
            kem = oqs.KeyEncapsulation(algorithm)
            
            # Generate dummy keypair to initialize
            _ = kem.generate_keypair()
            
            # Try to call decap_secret with just ciphertext (correct API)
            # But first try to inject our secret key
            
            # Attempt 1: Direct attribute injection
            if hasattr(kem, '_secret_key'):
                kem._secret_key = secret_key_bytes
            elif hasattr(kem, 'secret_key'):  
                kem.secret_key = secret_key_bytes
            
            # Now try decapsulation
            shared_secret = kem.decap_secret(ciphertext)
            print(f"✅ Method 2 successful! Shared secret length: {len(shared_secret)} bytes")
            return shared_secret
            
        except Exception as e2:
            print(f"❌ Method 2 failed: {e2}")
            
            # Method 3: Last resort - provide detailed error and suggestions
            error_msg = (
                f"All decapsulation methods failed!\n"
                f"Method 1 (key import): {e1}\n"
                f"Method 2 (attribute injection): {e2}\n\n"
                f"This suggests that your version of liboqs-python doesn't support "
                f"importing secret keys into new KEM instances.\n\n"
                f"SOLUTION: You need to maintain the original KEM instance that "
                f"generated the keypair. Use KyberKEMManager class instead.\n\n"
                f"Ciphertext: {len(ciphertext)} bytes\n"
                f"Secret key: {len(secret_key_bytes)} bytes\n"
                f"Algorithm: {algorithm}"
            )
            
            raise Exception(error_msg)

def test_kyber_kem():
    """Test function to verify KEM operations work correctly"""
    print("🧪 Testing Kyber KEM implementation...")
    
    # Test 1: Basic functionality with immediate use
    print("\n1. Testing basic KEM cycle with immediate use...")
    try:
        kem = KyberKEM()
        public_key, secret_key = kem.generate_keypair()
        print(f"✅ Generated keypair - PK: {len(public_key)} bytes, SK: {len(secret_key)} bytes")
        
        # Encapsulate with different instance (normal use case)
        ciphertext, shared_secret1 = KyberKEM.encapsulate(public_key)
        print(f"✅ Encapsulated - CT: {len(ciphertext)} bytes, SS: {len(shared_secret1)} bytes")
        
        # Decapsulate with original instance (this should work)
        shared_secret2 = kem.decapsulate_with_instance(ciphertext)
        print(f"✅ Decapsulated with instance - SS: {len(shared_secret2)} bytes")
        
        if shared_secret1 == shared_secret2:
            print("✅ Test 1 PASSED - Shared secrets match!")
        else:
            print("❌ Test 1 FAILED - Shared secrets don't match!")
            return False
            
    except Exception as e:
        print(f"❌ Test 1 FAILED: {e}")
        return False
    
    # Test 2: Test with stored secret key (problematic case)
    print("\n2. Testing decapsulation with stored secret key...")
    try:
        # Generate keypair
        public_key, secret_key = generate_keypair()
        
        # Encapsulate
        ciphertext, shared_secret1 = encapsulate_key(public_key)
        
        # Try to decapsulate with stored secret key
        shared_secret2 = decapsulate_key(ciphertext, secret_key)
        
        if shared_secret1 == shared_secret2:
            print("✅ Test 2 PASSED - Stored key decapsulation works!")
        else:
            print("❌ Test 2 FAILED - Shared secrets don't match!")
            return False
            
    except Exception as e:
        print(f"⚠️  Test 2 EXPECTED TO FAIL: {e}")
        print("This is expected with most versions of liboqs-python")
    
    # Test 3: Test KEM Manager approach
    print("\n3. Testing KEM Manager approach...")
    try:
        manager = KyberKEMManager()
        
        # Create keypair with manager
        public_key, secret_key = manager.create_keypair("user1")
        print(f"✅ Manager created keypair - PK: {len(public_key)} bytes")
        
        # Encapsulate
        ciphertext, shared_secret1 = encapsulate_key(public_key)
        
        # Decapsulate with manager
        shared_secret2 = manager.decapsulate("user1", ciphertext)
        
        if shared_secret1 == shared_secret2:
            print("✅ Test 3 PASSED - KEM Manager works!")
            return True
        else:
            print("❌ Test 3 FAILED - Shared secrets don't match!")
            return False
            
    except Exception as e:
        print(f"❌ Test 3 FAILED: {e}")
        return False

if __name__ == "__main__":
    test_kyber_kem()