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

    # One-time pre-keys (ephemeral, used once and deleted).
    # Deliberately NOT covered by signed_prekey_signature, matching Signal: a
    # substituted one-time key only breaks the session, because DH1..DH3 still
    # involve keys the attacker cannot compute. Substitution is denial of
    # service, not compromise.
    onetime_prekey: Optional[bytes] = None  # 32-byte X25519 public key
    onetime_prekey_id: Optional[int] = None  # which key the owner must consume

    def to_dict(self) -> dict:
        """Serialize bundle for transmission"""
        return {
            'identity_key': self.identity_key.hex(),
            'signing_key': self.signing_key.hex(),
            'signed_prekey': self.signed_prekey.hex(),
            'signed_prekey_signature': self.signed_prekey_signature.hex(),
            'onetime_prekey': self.onetime_prekey.hex() if self.onetime_prekey else None,
            'onetime_prekey_id': self.onetime_prekey_id
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
            onetime_prekey=bytes.fromhex(data['onetime_prekey']) if data.get('onetime_prekey') else None,
            onetime_prekey_id=data.get('onetime_prekey_id')
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
        
        # One-time pre-keys, by id. Each is handed to exactly one initiator by
        # the server and destroyed on first use, which is what gives the very
        # first message forward secrecy before any ratchet step has happened.
        self.onetime_prekeys = {}  # {id: X25519KeyPair}
        self._next_onetime_id = 0

        # Generate initial batch
        self.generate_onetime_prekeys(self.DEFAULT_ONETIME_COUNT)

    DEFAULT_ONETIME_COUNT = 10

    def generate_onetime_prekeys(self, count: int = 10) -> list:
        """
        Generate a batch of one-time pre-keys.

        Args:
            count: Number of one-time keys to generate

        Returns:
            Public entries to upload: [{'id': int, 'key': hex_str}, ...]
        """
        entries = []
        for _ in range(count):
            key_id = self._next_onetime_id
            self._next_onetime_id += 1

            keypair = X25519KeyPair()
            self.onetime_prekeys[key_id] = keypair
            entries.append({'id': key_id, 'key': keypair.get_public_bytes().hex()})

        return entries

    def consume_onetime_prekey(self, key_id) -> Optional[X25519KeyPair]:
        """
        Take a one-time pre-key out of the store, permanently.

        Returns None for an unknown or already-used id, which is the expected
        outcome for a replayed first message — the caller must treat that as a
        failure rather than silently falling back to a 3-DH handshake, or the
        one-time guarantee is lost.

        Args:
            key_id: Identifier the initiator echoed back

        Returns:
            The key pair, or None if it is not available
        """
        if key_id is None:
            return None
        return self.onetime_prekeys.pop(key_id, None)

    def onetime_prekey_count(self) -> int:
        """Number of unused one-time pre-keys still held."""
        return len(self.onetime_prekeys)
    
    def get_prekey_bundle(self) -> X3DHPreKeyBundle:
        """
        Get a pre-key bundle for publishing to the server.
        
        Returns:
            X3DHPreKeyBundle with public keys
        """
        # The bundle itself carries no one-time key. The server holds the pool
        # and attaches a distinct one per requester, so that two initiators
        # never receive the same one-time key.
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
            onetime_prekey=onetime_key  # server attaches one per requester
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
    
    # The server would hand out one of Bob's one-time keys; simulate that here
    assert bob_key_manager.onetime_prekey_count() == X3DHKeyManager.DEFAULT_ONETIME_COUNT
    served_id = next(iter(bob_key_manager.onetime_prekeys))
    served_public = bob_key_manager.onetime_prekeys[served_id].get_public_bytes()

    bob_bundle = bob_key_manager.get_prekey_bundle()
    bob_bundle.onetime_prekey = served_public
    bob_bundle.onetime_prekey_id = served_id

    # Bob consumes it when the first message arrives
    saved_onetime_keypair = bob_key_manager.consume_onetime_prekey(served_id)
    assert saved_onetime_keypair is not None, "one-time key was not available"

    # Consuming the same id twice must fail — that is what makes it one-time
    assert bob_key_manager.consume_onetime_prekey(served_id) is None
    assert bob_key_manager.consume_onetime_prekey(9999) is None
    assert bob_key_manager.onetime_prekey_count() == X3DHKeyManager.DEFAULT_ONETIME_COUNT - 1
    
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
