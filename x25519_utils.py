# -*- coding: utf-8 -*-
"""
X25519 Key Agreement Utilities
Provides X25519 ECDH key generation and Diffie-Hellman operations for Forward Secrecy.
"""

import os
import hashlib
import hmac
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature
from typing import Tuple


class X25519KeyPair:
    """X25519 key pair for Elliptic Curve Diffie-Hellman (ECDH)"""
    
    def __init__(self, private_key=None):
        """
        Initialize X25519 key pair.
        
        Args:
            private_key: Optional existing private key (for deserialization)
        """
        if private_key is None:
            self.private_key = x25519.X25519PrivateKey.generate()
        else:
            self.private_key = private_key
        
        self.public_key = self.private_key.public_key()
    
    def get_public_bytes(self) -> bytes:
        """
        Get public key as raw bytes (32 bytes).
        
        Returns:
            32-byte public key
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def get_private_bytes(self) -> bytes:
        """
        Get private key as raw bytes (32 bytes).
        
        Returns:
            32-byte private key
        """
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    def dh(self, peer_public_key_bytes: bytes) -> bytes:
        """
        Perform Diffie-Hellman key exchange.
        
        Args:
            peer_public_key_bytes: Peer's 32-byte X25519 public key
        
        Returns:
            32-byte shared secret
        """
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(
            peer_public_key_bytes
        )
        return self.private_key.exchange(peer_public_key)
    
    @staticmethod
    def from_private_bytes(private_bytes: bytes) -> 'X25519KeyPair':
        """
        Create key pair from private key bytes.
        
        Args:
            private_bytes: 32-byte private key
        
        Returns:
            X25519KeyPair instance
        """
        private_key = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
        return X25519KeyPair(private_key)


class Ed25519KeyPair:
    """
    Ed25519 key pair for digital signatures.

    X25519 keys perform Diffie-Hellman but cannot sign. This is the long-term
    identity key: it signs the X25519 identity key and the signed pre-key, which
    is what lets a peer detect a substituted pre-key bundle. TOFU pins this key.
    """

    def __init__(self, private_key=None):
        """
        Initialize Ed25519 key pair.

        Args:
            private_key: Optional existing private key (for deserialization)
        """
        if private_key is None:
            self.private_key = ed25519.Ed25519PrivateKey.generate()
        else:
            self.private_key = private_key

        self.public_key = self.private_key.public_key()

    def get_public_bytes(self) -> bytes:
        """
        Get public key as raw bytes (32 bytes).

        Returns:
            32-byte public key
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def get_private_bytes(self) -> bytes:
        """
        Get private key as raw bytes (32 bytes).

        Returns:
            32-byte private key
        """
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

    def sign(self, data: bytes) -> bytes:
        """
        Sign data with the private key.

        Args:
            data: Message to sign

        Returns:
            64-byte Ed25519 signature
        """
        return self.private_key.sign(data)

    @staticmethod
    def verify(public_key_bytes: bytes, signature: bytes, data: bytes) -> bool:
        """
        Verify a signature against a public key.

        Static because the verifier only ever holds the peer's public key.

        Args:
            public_key_bytes: Signer's 32-byte Ed25519 public key
            signature: 64-byte signature to check
            data: Message that was signed

        Returns:
            True if the signature is valid, False otherwise
        """
        try:
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            public_key.verify(signature, data)
            return True
        except (InvalidSignature, ValueError):
            # ValueError covers a malformed key or signature length
            return False

    @staticmethod
    def from_private_bytes(private_bytes: bytes) -> 'Ed25519KeyPair':
        """
        Create key pair from private key bytes.

        Args:
            private_bytes: 32-byte private key

        Returns:
            Ed25519KeyPair instance
        """
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
        return Ed25519KeyPair(private_key)


def kdf_rk(root_key: bytes, dh_output: bytes) -> Tuple[bytes, bytes]:
    """
    Root Key Derivation Function (KDF).
    Derives new root key and chain key from current root key and DH output.
    
    This is the "ratchet" step that provides forward secrecy.
    
    Args:
        root_key: Current 32-byte root key
        dh_output: 32-byte Diffie-Hellman shared secret
    
    Returns:
        Tuple of (new_root_key, chain_key), each 32 bytes
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,  # 32 bytes for root key + 32 for chain key
        salt=root_key,
        info=b"DoubleRatchetRootKey"
    )
    output = hkdf.derive(dh_output)
    return output[:32], output[32:]  # (new_root_key, chain_key)


def kdf_ck(chain_key: bytes) -> Tuple[bytes, bytes]:
    """
    Chain Key Derivation Function (KDF).
    Derives next chain key and message key from current chain key.
    
    This provides per-message keys (no key reuse).
    
    Args:
        chain_key: Current 32-byte chain key
    
    Returns:
        Tuple of (new_chain_key, message_key), each 32 bytes
    """
    # Use HMAC-SHA256 as KDF (as per Signal spec)
    # message_key = HMAC(chain_key, 0x01)
    # next_chain_key = HMAC(chain_key, 0x02)
    
    message_key = hmac.new(chain_key, b"\x01", hashlib.sha256).digest()
    next_chain_key = hmac.new(chain_key, b"\x02", hashlib.sha256).digest()
    
    return next_chain_key, message_key


def derive_initial_root_key(shared_secret: bytes, info: bytes = b"InitialRootKey") -> bytes:
    """
    Derive initial root key from X3DH shared secret.
    
    Args:
        shared_secret: Shared secret from X3DH key agreement
        info: Optional context information
    
    Returns:
        32-byte initial root key
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info
    )
    return hkdf.derive(shared_secret)


def generate_fingerprint(public_key_bytes: bytes) -> str:
    """
    Generate SHA-256 fingerprint of public key for verification.
    
    Args:
        public_key_bytes: 32-byte X25519 public key
    
    Returns:
        Hex-encoded SHA-256 fingerprint
    """
    hash_obj = hashlib.sha256(public_key_bytes)
    fingerprint = hash_obj.hexdigest()
    return f"SHA256:{fingerprint[:16]}...{fingerprint[-16:]}"


def generate_safety_number(key1: bytes, key2: bytes, user1: str, user2: str) -> str:
    """
    Generate Signal-style 60-digit safety number for two users.
    Used for out-of-band verification.
    
    Args:
        key1: First user's public key (32 bytes)
        key2: Second user's public key (32 bytes)
        user1: First username
        user2: Second username
    
    Returns:
        60-digit safety number formatted in groups of 5
    """
    # Ensure consistent ordering
    if user1 < user2:
        combined = key1 + key2 + user1.encode() + user2.encode()
    else:
        combined = key2 + key1 + user2.encode() + user1.encode()
    
    # Hash to get deterministic number
    hash_val = hashlib.sha512(combined).digest()
    
    # Convert to integer and take first 60 digits
    num = int.from_bytes(hash_val, 'big')
    safety_num = str(num)[:60].zfill(60)
    
    # Format as groups of 5 digits
    formatted = ' '.join([safety_num[i:i+5] for i in range(0, 60, 5)])
    
    return formatted


# Test function
if __name__ == "__main__":
    print("Testing X25519 Key Agreement...")
    
    # Generate key pairs for Alice and Bob
    alice = X25519KeyPair()
    bob = X25519KeyPair()
    
    print(f"Alice public key: {alice.get_public_bytes().hex()[:32]}...")
    print(f"Bob public key: {bob.get_public_bytes().hex()[:32]}...")
    
    # Perform DH
    alice_shared = alice.dh(bob.get_public_bytes())
    bob_shared = bob.dh(alice.get_public_bytes())
    
    print(f"\nAlice computed shared secret: {alice_shared.hex()[:32]}...")
    print(f"Bob computed shared secret: {bob_shared.hex()[:32]}...")
    
    # Verify they match
    assert alice_shared == bob_shared, "Shared secrets don't match!"
    print("\n[OK] Shared secrets match!")
    
    # Test KDF
    root_key = os.urandom(32)
    new_rk, chain_key = kdf_rk(root_key, alice_shared)
    print(f"\n[OK] Derived root key: {new_rk.hex()[:32]}...")
    print(f"[OK] Derived chain key: {chain_key.hex()[:32]}...")
    
    # Test chain key ratchet
    ck1, mk1 = kdf_ck(chain_key)
    ck2, mk2 = kdf_ck(ck1)
    print(f"\n[OK] Message key 1: {mk1.hex()[:32]}...")
    print(f"[OK] Message key 2: {mk2.hex()[:32]}...")
    
    # Test fingerprint
    fp = generate_fingerprint(alice.get_public_bytes())
    print(f"\n[OK] Alice fingerprint: {fp}")
    
    # Test safety number
    safety = generate_safety_number(
        alice.get_public_bytes(),
        bob.get_public_bytes(),
        "Alice",
        "Bob"
    )
    print(f"\n[OK] Safety number:\n  {safety}")

    # Test Ed25519 signatures
    signer = Ed25519KeyPair()
    signer_pub = signer.get_public_bytes()
    assert len(signer_pub) == 32

    payload = alice.get_public_bytes() + bob.get_public_bytes()
    signature = signer.sign(payload)
    assert len(signature) == 64
    assert Ed25519KeyPair.verify(signer_pub, signature, payload)
    print(f"\n[OK] Ed25519 signature verifies")

    # A tampered payload must NOT verify
    tampered = bytearray(payload)
    tampered[0] ^= 0x01
    assert not Ed25519KeyPair.verify(signer_pub, signature, bytes(tampered))
    print("[OK] Tampered payload rejected")

    # A signature from a different key must NOT verify
    attacker = Ed25519KeyPair()
    assert not Ed25519KeyPair.verify(signer_pub, attacker.sign(payload), payload)
    print("[OK] Wrong-signer signature rejected")

    # Garbage signature must return False, not raise
    assert not Ed25519KeyPair.verify(signer_pub, b"\x00" * 64, payload)
    assert not Ed25519KeyPair.verify(signer_pub, b"short", payload)
    print("[OK] Malformed signature rejected without raising")

    # Round-trip through raw private bytes
    restored = Ed25519KeyPair.from_private_bytes(signer.get_private_bytes())
    assert restored.get_public_bytes() == signer_pub
    assert Ed25519KeyPair.verify(signer_pub, restored.sign(payload), payload)
    print("[OK] Ed25519 private key round-trip works")

    print("\n[PASS] All X25519 tests passed!")
