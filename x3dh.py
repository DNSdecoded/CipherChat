# -*- coding: utf-8 -*-
"""
X3DH (Extended Triple Diffie-Hellman) Key Agreement Protocol
Establishes initial shared secret for Double Ratchet.

Based on Signal's X3DH specification:
https://signal.org/docs/specifications/x3dh/
"""

import os
import hashlib
from typing import Tuple, Dict, Optional
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from x25519_utils import X25519KeyPair, Ed25519KeyPair


def prekey_signing_payload(identity_key: bytes, signed_prekey: bytes) -> bytes:
    """
    Build the byte string covered by the pre-key signature.

    Both inputs are fixed 32-byte X25519 public keys, so plain concatenation is
    unambiguous. Binding the identity key into the signature is what stops an
    attacker from pairing a victim's signed pre-key with their own identity key.

    Args:
        identity_key: 32-byte X25519 identity public key
        signed_prekey: 32-byte X25519 signed pre-key public key

    Returns:
        Payload to sign / verify
    """
    return b"CipherChat-SPK-v3" + identity_key + signed_prekey


@dataclass
class X3DHPreKeyBundle:
    """
    Pre-key bundle for X3DH key agreement.
    Published by Bob, used by Alice to initiate communication.
    """
    # Identity key (long-term, never changes)
    identity_key: bytes  # 32-byte X25519 public key

    # Signing key (long-term Ed25519 public key; this is what TOFU pins)
    signing_key: bytes  # 32-byte Ed25519 public key

    # Signed pre-key (medium-term, rotated periodically)
    signed_prekey: bytes  # 32-byte X25519 public key
    signed_prekey_signature: bytes  # Ed25519 sig over identity_key||signed_prekey

    # One-time pre-keys (ephemeral, used once and deleted)
    onetime_prekey: Optional[bytes] = None  # 32-byte X25519 public key

    def to_dict(self) -> dict:
        """Serialize bundle for transmission"""
        return {
            'identity_key': self.identity_key.hex(),
            'signing_key': self.signing_key.hex(),
            'signed_prekey': self.signed_prekey.hex(),
            'signed_prekey_signature': self.signed_prekey_signature.hex(),
            'onetime_prekey': self.onetime_prekey.hex() if self.onetime_prekey else None
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'X3DHPreKeyBundle':
        """
        Deserialize bundle.

        Raises:
            KeyError, ValueError: on a malformed or truncated bundle. Callers
                take bundles straight off the wire, so they must catch these.
        """
        return cls(
            identity_key=bytes.fromhex(data['identity_key']),
            signing_key=bytes.fromhex(data['signing_key']),
            signed_prekey=bytes.fromhex(data['signed_prekey']),
            signed_prekey_signature=bytes.fromhex(data['signed_prekey_signature']),
            onetime_prekey=bytes.fromhex(data['onetime_prekey']) if data.get('onetime_prekey') else None
        )


class X3DHKeyManager:
    """
    Manages X3DH key bundles for a user.
    Generates and maintains identity, signed pre-keys, and one-time pre-keys.
    """
    
    def __init__(self):
        """Initialize key manager"""
        # Long-term identity key (X25519, used for Diffie-Hellman)
        self.identity_keypair = X25519KeyPair()

        # Long-term signing key (Ed25519). X25519 keys cannot sign, so identity
        # authentication rides on this key; TOFU pins it.
        self.signing_keypair = Ed25519KeyPair()

        # Medium-term signed pre-key (rotated periodically)
        self.signed_prekey_pair = X25519KeyPair()
        
        # One-time pre-keys (generated in batches)
        # Disabled until MITM protection is implemented
        self.onetime_prekey_pairs = []
        
        # Generate initial batch of one-time keys (disabled)
        # self.generate_onetime_prekeys(10)
    
    def generate_onetime_prekeys(self, count: int = 10):
        """
        Generate a batch of one-time pre-keys.
        
        Args:
            count: Number of one-time keys to generate
        """
        for _ in range(count):
            self.onetime_prekey_pairs.append(X25519KeyPair())
    
    def get_prekey_bundle(self) -> X3DHPreKeyBundle:
        """
        Get a pre-key bundle for publishing to the server.
        
        Returns:
            X3DHPreKeyBundle with public keys
        """
        # NOTE: One-time prekeys are DISABLED until MITM protection is implemented
        # OPKs without identity verification create a false sense of security
        # and are vulnerable to server-side key substitution attacks.
        onetime_key = None

        identity_public = self.identity_keypair.get_public_bytes()
        signed_prekey_public = self.signed_prekey_pair.get_public_bytes()

        return X3DHPreKeyBundle(
            identity_key=identity_public,
            signing_key=self.signing_keypair.get_public_bytes(),
            signed_prekey=signed_prekey_public,
            signed_prekey_signature=self.signing_keypair.sign(
                prekey_signing_payload(identity_public, signed_prekey_public)
            ),
            onetime_prekey=onetime_key  # Always None until MITM protection
        )


def verify_prekey_bundle(bundle: X3DHPreKeyBundle) -> bool:
    """
    Verify that a bundle's signed pre-key really was signed by its signing key.

    This is the check that makes the bundle self-consistent. It does NOT tell you
    the signing key belongs to the person you think it does — that is the job of
    the TOFU pin in the client. Both are required: the pin establishes which
    signing key is authentic, this proves the DH keys are bound to that key.

    Args:
        bundle: Bundle received from the server

    Returns:
        True if the signature is valid over identity_key||signed_prekey
    """
    return Ed25519KeyPair.verify(
        bundle.signing_key,
        bundle.signed_prekey_signature,
        prekey_signing_payload(bundle.identity_key, bundle.signed_prekey)
    )


def x3dh_initiate(
    alice_identity_keypair: X25519KeyPair,
    bob_bundle: X3DHPreKeyBundle
) -> Tuple[bytes, bytes]:
    """
    Initiate X3DH key agreement (Alice's side).
    
    Performs 3 or 4 Diffie-Hellman operations:
    - DH1 = DH(IK_A, SPK_B)
    - DH2 = DH(EK_A, IK_B)
    - DH3 = DH(EK_A, SPK_B)
    - DH4 = DH(EK_A, OPK_B)  [if one-time key available]
    
    Args:
        alice_identity_keypair: Alice's identity key pair
        bob_bundle: Bob's pre-key bundle
    
    Returns:
        Tuple of (shared_secret, alice_ephemeral_public_key)
    """
    # Generate ephemeral key for Alice
    alice_ephemeral = X25519KeyPair()
    
    # Perform DH operations
    dh1 = alice_identity_keypair.dh(bob_bundle.signed_prekey)
    dh2 = alice_ephemeral.dh(bob_bundle.identity_key)
    dh3 = alice_ephemeral.dh(bob_bundle.signed_prekey)
    
    # DH4 if one-time key is available
    if bob_bundle.onetime_prekey:
        dh4 = alice_ephemeral.dh(bob_bundle.onetime_prekey)
        dh_concat = dh1 + dh2 + dh3 + dh4
    else:
        dh_concat = dh1 + dh2 + dh3
    
    # Derive shared secret using HKDF
    shared_secret = _derive_x3dh_secret(dh_concat)
    
    return shared_secret, alice_ephemeral.get_public_bytes()


def x3dh_respond(
    bob_identity_keypair: X25519KeyPair,
    bob_signed_prekey_pair: X25519KeyPair,
    bob_onetime_prekey_pair: Optional[X25519KeyPair],
    alice_identity_public: bytes,
    alice_ephemeral_public: bytes
) -> bytes:
    """
    Respond to X3DH key agreement (Bob's side).
    
    Performs the same DH operations as Alice to derive shared secret.
    
    Args:
        bob_identity_keypair: Bob's identity key pair
        bob_signed_prekey_pair: Bob's signed pre-key pair
        bob_onetime_prekey_pair: Bob's one-time pre-key pair (if used)
        alice_identity_public: Alice's identity public key
        alice_ephemeral_public: Alice's ephemeral public key
    
    Returns:
        Shared secret (same as Alice's)
    """
    # Perform DH operations (same as Alice, but reversed)
    dh1 = bob_signed_prekey_pair.dh(alice_identity_public)
    dh2 = bob_identity_keypair.dh(alice_ephemeral_public)
    dh3 = bob_signed_prekey_pair.dh(alice_ephemeral_public)
    
    # DH4 if one-time key was used
    if bob_onetime_prekey_pair:
        dh4 = bob_onetime_prekey_pair.dh(alice_ephemeral_public)
        dh_concat = dh1 + dh2 + dh3 + dh4
    else:
        dh_concat = dh1 + dh2 + dh3
    
    # Derive shared secret
    shared_secret = _derive_x3dh_secret(dh_concat)
    
    return shared_secret


def _derive_x3dh_secret(dh_concat: bytes) -> bytes:
    """
    Derive X3DH shared secret from concatenated DH outputs.
    
    Args:
        dh_concat: Concatenated DH outputs
    
    Returns:
        32-byte shared secret
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"X3DH",
        info=b"Signal_X3DH_Shared_Secret"
    )
    return hkdf.derive(dh_concat)


# Test function
if __name__ == "__main__":
    print("Testing X3DH Key Agreement...")
    
    # Bob generates his key bundle
    print("\n[1] Bob generates key bundle...")
    bob_key_manager = X3DHKeyManager()
    
    # Save the one-time key BEFORE getting the bundle
    saved_onetime_keypair = None
    # OPKs disabled, so this will be None
    
    bob_bundle = bob_key_manager.get_prekey_bundle()
    
    print(f"[OK] Bob's identity key: {bob_bundle.identity_key.hex()[:32]}...")
    print(f"[OK] Bob's signing key: {bob_bundle.signing_key.hex()[:32]}...")
    print(f"[OK] Bob's signed prekey: {bob_bundle.signed_prekey.hex()[:32]}...")
    print(f"[OK] Bob's onetime prekey: {bob_bundle.onetime_prekey.hex()[:32] if bob_bundle.onetime_prekey else 'None'}...")

    # The bundle must verify against its own signing key
    assert verify_prekey_bundle(bob_bundle), "Bob's own bundle failed verification!"
    print("[OK] Bundle signature verifies")

    # A substituted signed pre-key must be detected
    forged = X3DHPreKeyBundle(
        identity_key=bob_bundle.identity_key,
        signing_key=bob_bundle.signing_key,
        signed_prekey=X25519KeyPair().get_public_bytes(),  # attacker's key
        signed_prekey_signature=bob_bundle.signed_prekey_signature,
        onetime_prekey=None
    )
    assert not verify_prekey_bundle(forged), "Substituted pre-key was accepted!"
    print("[OK] Substituted signed pre-key rejected")

    # Swapping in the attacker's own identity key must also be detected,
    # since the identity key is covered by the signature
    mixed = X3DHPreKeyBundle(
        identity_key=X25519KeyPair().get_public_bytes(),
        signing_key=bob_bundle.signing_key,
        signed_prekey=bob_bundle.signed_prekey,
        signed_prekey_signature=bob_bundle.signed_prekey_signature,
        onetime_prekey=None
    )
    assert not verify_prekey_bundle(mixed), "Substituted identity key was accepted!"
    print("[OK] Substituted identity key rejected")

    # A wholly attacker-generated bundle verifies against ITS OWN key — that is
    # expected, and is exactly why TOFU must pin the signing key separately.
    attacker_bundle = X3DHKeyManager().get_prekey_bundle()
    assert verify_prekey_bundle(attacker_bundle)
    assert attacker_bundle.signing_key != bob_bundle.signing_key
    print("[OK] Attacker bundle is self-consistent but has a different signing key")
    
    # Alice initiates X3DH
    print("\n[2] Alice initiates X3DH...")
    alice_identity = X25519KeyPair()
    alice_shared_secret, alice_ephemeral_pub = x3dh_initiate(alice_identity, bob_bundle)
    
    print(f"[OK] Alice's shared secret: {alice_shared_secret.hex()[:32]}...")
    print(f"[OK] Alice's ephemeral key: {alice_ephemeral_pub.hex()[:32]}...")
    
    # Bob responds to X3DH
    print("\n[3] Bob responds to X3DH...")
    
    bob_shared_secret = x3dh_respond(
        bob_key_manager.identity_keypair,
        bob_key_manager.signed_prekey_pair,
        saved_onetime_keypair,  # Use the saved one-time key
        alice_identity.get_public_bytes(),
        alice_ephemeral_pub
    )
    
    print(f"[OK] Bob's shared secret: {bob_shared_secret.hex()[:32]}...")
    
    # Verify shared secrets match
    print("\n[4] Verifying shared secrets...")
    assert alice_shared_secret == bob_shared_secret, "Shared secrets don't match!"
    print("[OK] Shared secrets match!")
    
    # Test bundle serialization
    print("\n[5] Testing bundle serialization...")
    bundle_dict = bob_bundle.to_dict()
    restored_bundle = X3DHPreKeyBundle.from_dict(bundle_dict)
    assert restored_bundle.identity_key == bob_bundle.identity_key
    assert restored_bundle.signing_key == bob_bundle.signing_key
    assert restored_bundle.signed_prekey_signature == bob_bundle.signed_prekey_signature
    # Verification must survive a round trip through the wire format
    assert verify_prekey_bundle(restored_bundle)
    print("[OK] Bundle serialization works!")
    
    print("\n[PASS] All X3DH tests passed!")
