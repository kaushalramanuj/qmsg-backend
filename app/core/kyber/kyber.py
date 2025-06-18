from oqs import KeyEncapsulation

class KyberKEM:
    """
    Python wrapper for Kyber KEM implementation using liboqs
    """
    def __init__(self):
        self.algorithm = "Kyber512"  # You can change this to Kyber768 or Kyber1024 for higher security

    @staticmethod
    def generate_keypair():
        """Generate a Kyber key pair"""
        with KeyEncapsulation("Kyber512") as kem:  # You can change this to Kyber768 or Kyber1024
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
            return public_key, secret_key
    
    @staticmethod
    def encapsulate(public_key):
        """
        Encapsulate a shared secret using recipient's public key
        Returns (ciphertext, shared_secret)
        """
        with KeyEncapsulation("Kyber512") as kem:  # You can change this to Kyber768 or Kyber1024
            ciphertext, shared_secret = kem.encap_secret(public_key)
            return ciphertext, shared_secret
    
    @staticmethod
    def decapsulate(ciphertext, private_key):
        """
        Decapsulate a shared secret using recipient's private key
        """
        with KeyEncapsulation("Kyber512") as kem:  # You can change this to Kyber768 or Kyber1024
            kem.import_secret_key(private_key)
            shared_secret = kem.decap_secret(ciphertext)
            return shared_secret 