"""
End-to-End Encryption Utilities
Provides cryptographic functions for secure client-to-client communication.
"""

import os
import base64
import json
from typing import Tuple, Dict, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


class E2EKeyManager:
    """Manages RSA key pairs for end-to-end encryption."""
    
    def __init__(self, key_size: int = 2048):
        """
        Initialize key manager.
        
        Args:
            key_size: RSA key size in bits (2048 or 4096)
        """
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
    
    def generate_key_pair(self) -> Tuple[bytes, bytes]:
        """
        Generate a new RSA key pair.
        
        Returns:
            Tuple of (public_key_pem, private_key_pem)
        """
        # Generate private key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        
        # Derive public key
        self.public_key = self.private_key.public_key()
        
        # Serialize keys to PEM format
        public_pem = self.export_public_key(self.public_key)
        private_pem = self.export_private_key(self.private_key)
        
        return public_pem, private_pem
    
    @staticmethod
    def export_public_key(public_key) -> bytes:
        """Export public key to PEM format."""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    @staticmethod
    def export_private_key(private_key) -> bytes:
        """Export private key to PEM format (unencrypted)."""
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    @staticmethod
    def import_public_key(pem_data: bytes):
        """Import public key from PEM format."""
        return serialization.load_pem_public_key(
            pem_data,
            backend=default_backend()
        )
    
    @staticmethod
    def import_private_key(pem_data: bytes):
        """Import private key from PEM format."""
        return serialization.load_pem_private_key(
            pem_data,
            password=None,
            backend=default_backend()
        )


class MessageEncryptor:
    """Handles message encryption, decryption, and signing using hybrid cryptography."""
    
    def __init__(self):
        """Initialize the message encryptor."""
        self.backend = default_backend()
    
    def aes_gcm_encrypt(self, plaintext: bytes, key: bytes, associated_data: bytes = b"") -> bytes:
        """
        Encrypt data with AES-256-GCM (for Double Ratchet).
        
        Args:
            plaintext: Data to encrypt
            key: 32-byte AES key
            associated_data: Additional authenticated data (not encrypted)
        
        Returns:
            nonce (12 bytes) + ciphertext + tag (16 bytes)
        """
        nonce = os.urandom(12)  # 96 bits for GCM
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        
        # Return: nonce + ciphertext + tag
        return nonce + ciphertext + tag
    
    def aes_gcm_decrypt(self, data: bytes, key: bytes, associated_data: bytes = b"") -> bytes:
        """
        Decrypt data with AES-256-GCM (for Double Ratchet).
        
        Args:
            data: nonce (12 bytes) + ciphertext + tag (16 bytes)
            key: 32-byte AES key
            associated_data: Additional authenticated data
        
        Returns:
            Decrypted plaintext
        """
        # Extract components
        nonce = data[:12]
        tag = data[-16:]
        ciphertext = data[12:-16]
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        
        if associated_data:
            decryptor.authenticate_additional_data(associated_data)
        
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    
    
    def encrypt_message(
        self, 
        plaintext: str, 
        recipient_public_key_pem: bytes
    ) -> Dict[str, str]:
        """
        Encrypt a message using hybrid encryption (AES + RSA).
        
        Process:
        1. Generate random AES-256 session key
        2. Encrypt message with AES-256-GCM
        3. Encrypt AES key with recipient's RSA public key
        
        Args:
            plaintext: Message to encrypt
            recipient_public_key_pem: Recipient's public key in PEM format
        
        Returns:
            Dictionary with encrypted_key, ciphertext, nonce, and tag
        """
        # Import recipient's public key
        recipient_public_key = E2EKeyManager.import_public_key(recipient_public_key_pem)
        
        # Generate random AES-256 session key
        session_key = os.urandom(32)  # 256 bits
        
        # Generate random nonce for AES-GCM
        nonce = os.urandom(12)  # 96 bits recommended for GCM
        
        # Encrypt message with AES-256-GCM
        cipher = Cipher(
            algorithms.AES(session_key),
            modes.GCM(nonce),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        tag = encryptor.tag  # Authentication tag
        
        # Encrypt the session key with RSA public key
        encrypted_session_key = recipient_public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Return all components as base64-encoded strings
        return {
            'encrypted_key': base64.b64encode(encrypted_session_key).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8')
        }
    
    def decrypt_message(
        self, 
        encrypted_data: Dict[str, str], 
        private_key_pem: bytes
    ) -> str:
        """
        Decrypt a message using hybrid decryption.
        
        Args:
            encrypted_data: Dictionary with encrypted_key, ciphertext, nonce, tag
            private_key_pem: Recipient's private key in PEM format
        
        Returns:
            Decrypted plaintext message
        
        Raises:
            ValueError: If decryption fails
        """
        try:
            # Import private key
            private_key = E2EKeyManager.import_private_key(private_key_pem)
            
            # Decode base64 components
            encrypted_session_key = base64.b64decode(encrypted_data['encrypted_key'])
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            nonce = base64.b64decode(encrypted_data['nonce'])
            tag = base64.b64decode(encrypted_data['tag'])
            
            # Decrypt the session key with RSA private key
            session_key = private_key.decrypt(
                encrypted_session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt message with AES-256-GCM
            cipher = Cipher(
                algorithms.AES(session_key),
                modes.GCM(nonce, tag),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            return plaintext.decode('utf-8')
            
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
    
    def sign_message(
        self, 
        message: str, 
        private_key_pem: bytes
    ) -> str:
        """
        Create a digital signature for a message.
        
        Args:
            message: Message to sign
            private_key_pem: Signer's private key in PEM format
        
        Returns:
            Base64-encoded signature
        """
        private_key = E2EKeyManager.import_private_key(private_key_pem)
        
        signature = private_key.sign(
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return base64.b64encode(signature).decode('utf-8')
    
    def verify_signature(
        self, 
        message: str, 
        signature: str, 
        public_key_pem: bytes
    ) -> bool:
        """
        Verify a digital signature.
        
        Args:
            message: Original message
            signature: Base64-encoded signature
            public_key_pem: Signer's public key in PEM format
        
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            public_key = E2EKeyManager.import_public_key(public_key_pem)
            signature_bytes = base64.b64decode(signature)
            
            public_key.verify(
                signature_bytes,
                message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return True
            
        except InvalidSignature:
            return False
        except Exception:
            return False
    
    def encrypt_for_multiple_recipients(
        self,
        plaintext: str,
        recipient_public_keys: Dict[str, bytes]
    ) -> Dict[str, Dict[str, str]]:
        """
        Encrypt a message for multiple recipients.
        
        Args:
            plaintext: Message to encrypt
            recipient_public_keys: Dictionary of {username: public_key_pem}
        
        Returns:
            Dictionary of {username: encrypted_data}
        """
        encrypted_payloads = {}
        
        for username, public_key_pem in recipient_public_keys.items():
            encrypted_payloads[username] = self.encrypt_message(
                plaintext, 
                public_key_pem
            )
        
        return encrypted_payloads


def generate_fingerprint(public_key_pem: bytes) -> str:
    """
    Generate a human-readable fingerprint for a public key.
    Useful for out-of-band key verification.
    
    Args:
        public_key_pem: Public key in PEM format
    
    Returns:
        SHA-256 fingerprint as hex string
    """
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(public_key_pem)
    fingerprint_bytes = digest.finalize()
    
    # Format as colon-separated hex
    fingerprint_hex = fingerprint_bytes.hex().upper()
    return ':'.join(fingerprint_hex[i:i+2] for i in range(0, len(fingerprint_hex), 2))


# Convenience functions
def create_key_pair(key_size: int = 2048) -> Tuple[bytes, bytes]:
    """
    Create a new RSA key pair.
    
    Returns:
        Tuple of (public_key_pem, private_key_pem)
    """
    manager = E2EKeyManager(key_size)
    return manager.generate_key_pair()


def encrypt_message(plaintext: str, recipient_public_key_pem: bytes) -> Dict[str, str]:
    """Encrypt a message for a single recipient."""
    encryptor = MessageEncryptor()
    return encryptor.encrypt_message(plaintext, recipient_public_key_pem)


def decrypt_message(encrypted_data: Dict[str, str], private_key_pem: bytes) -> str:
    """Decrypt a message."""
    encryptor = MessageEncryptor()
    return encryptor.decrypt_message(encrypted_data, private_key_pem)


def sign_message(message: str, private_key_pem: bytes) -> str:
    """Sign a message."""
    encryptor = MessageEncryptor()
    return encryptor.sign_message(message, private_key_pem)


def verify_signature(message: str, signature: str, public_key_pem: bytes) -> bool:
    """Verify a message signature."""
    encryptor = MessageEncryptor()
    return encryptor.verify_signature(message, signature, public_key_pem)
