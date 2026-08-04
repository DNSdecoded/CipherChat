# -*- coding: utf-8 -*-
"""
Double Ratchet Algorithm Implementation
Provides Perfect Forward Secrecy and Future Secrecy for encrypted messaging.

Based on the Signal Protocol specification:
https://signal.org/docs/specifications/doubleratchet/
"""

import os
import copy
import json
import base64
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Tuple
from datetime import datetime

from x25519_utils import X25519KeyPair, kdf_rk, kdf_ck
from crypto_utils import MessageEncryptor


def _header_ad(header: dict) -> bytes:
    """
    Canonicalize a message header into AES-GCM associated data.

    The header travels in cleartext, so without this it is unauthenticated and an
    attacker can rewrite `dh_public` to force the receiver onto a chain they
    control. Binding it as AD makes any edit fail the GCM tag.

    Sender and receiver must produce byte-identical output, hence sorted keys and
    no whitespace. Any field added to the header is covered automatically.

    Args:
        header: Message header dict (JSON-serializable values only)

    Returns:
        Canonical UTF-8 encoding of the header
    """
    return json.dumps(header, sort_keys=True, separators=(',', ':')).encode('utf-8')


@dataclass
class RatchetState:
    """
    Double Ratchet state for one conversation.
    
    The state includes:
    - DH ratchet keys (for forward secrecy)
    - Root key (master secret)
    - Sending and receiving chain keys
    - Message numbers (for ordering)
    - Skipped message keys (for out-of-order delivery)
    """
    
    # DH Ratchet keys
    dh_self_private: bytes  # Our current DH private key (32 bytes)
    dh_self_public: bytes   # Our current DH public key (32 bytes)
    dh_peer: Optional[bytes] = None  # Peer's current DH public key (32 bytes)
    
    # Root key (master secret)
    root_key: bytes = field(default_factory=lambda: os.urandom(32))
    
    # Sending chain
    chain_key_send: Optional[bytes] = None
    message_number_send: int = 0
    
    # Receiving chain
    chain_key_recv: Optional[bytes] = None
    message_number_recv: int = 0
    previous_chain_length: int = 0
    
    # Skipped message keys for out-of-order messages
    # Format: {(dh_public_hex, msg_num): message_key}
    skipped_message_keys: Dict[Tuple[str, int], bytes] = field(default_factory=dict)
    
    @classmethod
    def initialize_alice(cls, shared_secret: bytes, bob_public_key: bytes) -> 'RatchetState':
        """
        Initialize ratchet state for Alice (initiator).
        Alice sends the first message.
        
        Args:
            shared_secret: Initial shared secret from X3DH
            bob_public_key: Bob's initial DH public key
        
        Returns:
            Initialized RatchetState for Alice
        """
        # Generate Alice's DH key pair
        alice_dh = X25519KeyPair()
        
        # Perform initial DH ratchet
        dh_output = alice_dh.dh(bob_public_key)
        root_key, chain_key_send = kdf_rk(shared_secret, dh_output)
        
        return cls(
            dh_self_private=alice_dh.get_private_bytes(),
            dh_self_public=alice_dh.get_public_bytes(),
            dh_peer=bob_public_key,
            root_key=root_key,
            chain_key_send=chain_key_send,
            chain_key_recv=None
        )
    
    @classmethod
    def initialize_bob(cls, shared_secret: bytes, bob_dh_keypair: X25519KeyPair) -> 'RatchetState':
        """
        Initialize ratchet state for Bob (responder).
        Bob receives the first message.
        
        Args:
            shared_secret: Initial shared secret from X3DH
            bob_dh_keypair: Bob's DH key pair (used in X3DH)
        
        Returns:
            Initialized RatchetState for Bob
        """
        return cls(
            dh_self_private=bob_dh_keypair.get_private_bytes(),
            dh_self_public=bob_dh_keypair.get_public_bytes(),
            dh_peer=None,
            root_key=shared_secret,
            chain_key_send=None,
            chain_key_recv=None
        )
    
    def to_dict(self) -> dict:
        """Serialize state to dictionary (for storage)"""
        return {
            'dh_self_private': base64.b64encode(self.dh_self_private).decode(),
            'dh_self_public': base64.b64encode(self.dh_self_public).decode(),
            'dh_peer': base64.b64encode(self.dh_peer).decode() if self.dh_peer else None,
            'root_key': base64.b64encode(self.root_key).decode(),
            'chain_key_send': base64.b64encode(self.chain_key_send).decode() if self.chain_key_send else None,
            'message_number_send': self.message_number_send,
            'chain_key_recv': base64.b64encode(self.chain_key_recv).decode() if self.chain_key_recv else None,
            'message_number_recv': self.message_number_recv,
            'previous_chain_length': self.previous_chain_length,
            'skipped_message_keys': {
                f"{k[0]}:{k[1]}": base64.b64encode(v).decode()
                for k, v in self.skipped_message_keys.items()
            }
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'RatchetState':
        """Deserialize state from dictionary"""
        skipped = {}
        for key_str, mk_b64 in data.get('skipped_message_keys', {}).items():
            dh_hex, msg_num_str = key_str.split(':')
            skipped[(dh_hex, int(msg_num_str))] = base64.b64decode(mk_b64)
        
        return cls(
            dh_self_private=base64.b64decode(data['dh_self_private']),
            dh_self_public=base64.b64decode(data['dh_self_public']),
            dh_peer=base64.b64decode(data['dh_peer']) if data.get('dh_peer') else None,
            root_key=base64.b64decode(data['root_key']),
            chain_key_send=base64.b64decode(data['chain_key_send']) if data.get('chain_key_send') else None,
            message_number_send=data['message_number_send'],
            chain_key_recv=base64.b64decode(data['chain_key_recv']) if data.get('chain_key_recv') else None,
            message_number_recv=data['message_number_recv'],
            previous_chain_length=data['previous_chain_length'],
            skipped_message_keys=skipped
        )


class DoubleRatchet:
    """
    Double Ratchet protocol implementation.
    
    Provides:
    - Perfect Forward Secrecy (PFS)
    - Future Secrecy
    - Per-message keys
    - Out-of-order message handling
    """
    
    MAX_SKIP = 1000  # Maximum number of message keys to skip
    
    def __init__(self, state: RatchetState):
        """
        Initialize Double Ratchet with state.
        
        Args:
            state: RatchetState instance
        """
        self.state = state
        self.encryptor = MessageEncryptor()
    
    # Header fields the ratchet owns; callers may not override these
    _RESERVED_HEADER_FIELDS = frozenset(
        {'dh_public', 'message_number', 'previous_chain_length'}
    )

    def ratchet_encrypt(self, plaintext: bytes,
                        extra_header: Optional[dict] = None) -> Tuple[bytes, dict]:
        """
        Encrypt message and advance sending ratchet.

        The returned header is bound into the ciphertext as associated data, so
        it must be transmitted verbatim — a single altered field makes the
        recipient's decrypt fail. Callers pass any extra fields in up front
        rather than mutating the header afterwards.

        Args:
            plaintext: Message to encrypt
            extra_header: Extra header fields to bind (e.g. sender,
                x3dh_ephemeral). JSON-serializable values only.

        Returns:
            Tuple of (ciphertext, header_dict)

        Raises:
            ValueError: If extra_header collides with a ratchet-owned field
        """
        # Create header
        header = {
            'dh_public': self.state.dh_self_public.hex(),
            'message_number': self.state.message_number_send,
            'previous_chain_length': self.state.previous_chain_length
        }

        if extra_header:
            clash = self._RESERVED_HEADER_FIELDS & set(extra_header)
            if clash:
                raise ValueError(f"extra_header may not override {sorted(clash)}")
            header.update(extra_header)

        # Derive message key from sending chain
        self.state.chain_key_send, message_key = kdf_ck(self.state.chain_key_send)

        # Encrypt with AES-256-GCM, binding the header as associated data
        ciphertext = self.encryptor.aes_gcm_encrypt(
            plaintext, message_key, _header_ad(header)
        )

        # Increment message number
        self.state.message_number_send += 1

        return ciphertext, header

    def ratchet_decrypt(self, ciphertext: bytes, header: dict) -> bytes:
        """
        Decrypt message and advance ratchet if needed.

        All state changes are applied to a trial copy and only committed once
        decryption authenticates. Otherwise a forged or corrupted message would
        leave the chain advanced and desynchronize the session permanently —
        a trivial denial of service.

        Args:
            ciphertext: Encrypted message
            header: Message header, exactly as received

        Returns:
            Decrypted plaintext

        Raises:
            InvalidTag: If the ciphertext or header fails authentication
        """
        trial_state = copy.deepcopy(self.state)
        plaintext = self._decrypt_into(trial_state, ciphertext, header)

        # Authenticated — safe to commit
        self.state = trial_state
        return plaintext

    def _decrypt_into(self, state: RatchetState, ciphertext: bytes, header: dict) -> bytes:
        """
        Decrypt against `state`, mutating it. Raises before/without committing
        if authentication fails.

        Args:
            state: Ratchet state to advance (a trial copy)
            ciphertext: Encrypted message
            header: Message header, exactly as received

        Returns:
            Decrypted plaintext
        """
        associated_data = _header_ad(header)

        header_dh = bytes.fromhex(header['dh_public'])
        msg_num = header['message_number']
        prev_chain_len = header['previous_chain_length']

        # Check if this is a new DH ratchet step
        if state.dh_peer is None or header_dh != state.dh_peer:
            # Skip messages from previous chain if needed
            self._skip_message_keys(state, prev_chain_len)

            # Perform DH ratchet step
            self._dh_ratchet(state, header_dh)

        # Try to decrypt with skipped keys first (out-of-order).
        # Popping from the trial copy means a failed decrypt does not burn the key.
        skipped_key = state.skipped_message_keys.pop((header_dh.hex(), msg_num), None)
        if skipped_key:
            return self.encryptor.aes_gcm_decrypt(ciphertext, skipped_key, associated_data)

        # Skip messages if this message number is ahead
        self._skip_message_keys(state, msg_num)

        # Derive message key
        state.chain_key_recv, message_key = kdf_ck(state.chain_key_recv)
        state.message_number_recv += 1

        # Decrypt
        return self.encryptor.aes_gcm_decrypt(ciphertext, message_key, associated_data)

    def _dh_ratchet(self, state: RatchetState, peer_public_key: bytes):
        """
        Perform DH ratchet step.

        This is called when we receive a message with a new DH public key.
        It provides forward secrecy by generating new keys.

        Args:
            state: Ratchet state to advance
            peer_public_key: Peer's new DH public key
        """
        # Store previous chain length
        state.previous_chain_length = state.message_number_send

        # Reset message numbers
        state.message_number_send = 0
        state.message_number_recv = 0

        # Update peer's DH public key
        state.dh_peer = peer_public_key

        # Perform DH with our current key
        dh_self = X25519KeyPair.from_private_bytes(state.dh_self_private)
        dh_output = dh_self.dh(peer_public_key)

        # Update root key and receiving chain
        state.root_key, state.chain_key_recv = kdf_rk(state.root_key, dh_output)

        # Generate new DH key pair
        new_dh = X25519KeyPair()
        state.dh_self_private = new_dh.get_private_bytes()
        state.dh_self_public = new_dh.get_public_bytes()

        # Perform DH with new key
        dh_output = new_dh.dh(peer_public_key)

        # Update root key and sending chain
        state.root_key, state.chain_key_send = kdf_rk(state.root_key, dh_output)

    def _skip_message_keys(self, state: RatchetState, until: int):
        """
        Store keys for skipped messages (out-of-order handling).

        Args:
            state: Ratchet state to advance
            until: Message number to skip until

        Raises:
            Exception: If too many messages would be skipped
        """
        if state.message_number_recv + self.MAX_SKIP < until:
            raise Exception(f"Too many skipped messages: {until - state.message_number_recv}")

        if state.chain_key_recv is not None:
            while state.message_number_recv < until:
                ck, mk = kdf_ck(state.chain_key_recv)

                # Store skipped message key
                key = (state.dh_peer.hex(), state.message_number_recv)
                state.skipped_message_keys[key] = mk

                state.chain_key_recv = ck
                state.message_number_recv += 1


# Test function
if __name__ == "__main__":
    print("Testing Double Ratchet...")
    
    # Simulate X3DH shared secret
    shared_secret = os.urandom(32)
    
    # Bob generates his initial DH key pair (for X3DH)
    bob_initial_dh = X25519KeyPair()
    
    # Alice initializes her ratchet
    alice_state = RatchetState.initialize_alice(shared_secret, bob_initial_dh.get_public_bytes())
    alice_ratchet = DoubleRatchet(alice_state)
    
    # Bob initializes his ratchet with the same DH keypair used in X3DH
    bob_state = RatchetState.initialize_bob(shared_secret, bob_initial_dh)
    bob_ratchet = DoubleRatchet(bob_state)
    
    print("[OK] Ratchets initialized")
    
    # Alice sends first message
    plaintext1 = b"Hello Bob!"
    ciphertext1, header1 = alice_ratchet.ratchet_encrypt(plaintext1)
    print(f"[OK] Alice encrypted: {plaintext1.decode()}")
    
    # Bob receives and decrypts
    decrypted1 = bob_ratchet.ratchet_decrypt(ciphertext1, header1)
    assert decrypted1 == plaintext1
    print(f"[OK] Bob decrypted: {decrypted1.decode()}")
    
    # Bob sends reply
    plaintext2 = b"Hi Alice!"
    ciphertext2, header2 = bob_ratchet.ratchet_encrypt(plaintext2)
    print(f"[OK] Bob encrypted: {plaintext2.decode()}")
    
    # Alice receives
    decrypted2 = alice_ratchet.ratchet_decrypt(ciphertext2, header2)
    assert decrypted2 == plaintext2
    print(f"[OK] Alice decrypted: {decrypted2.decode()}")
    
    # Test multiple messages
    for i in range(5):
        msg = f"Message {i}".encode()
        ct, hdr = alice_ratchet.ratchet_encrypt(msg)
        dec = bob_ratchet.ratchet_decrypt(ct, hdr)
        assert dec == msg
    
    print("[OK] Multiple messages exchanged successfully")

    # Extra header fields must round-trip and be bound
    ct, hdr = alice_ratchet.ratchet_encrypt(b"bound", extra_header={'sender': 'alice'})
    assert hdr['sender'] == 'alice'
    assert bob_ratchet.ratchet_decrypt(ct, hdr) == b"bound"
    print("[OK] Extra header fields round-trip")

    # Callers must not be able to forge ratchet-owned fields
    try:
        alice_ratchet.ratchet_encrypt(b"x", extra_header={'message_number': 999})
        raise AssertionError("Reserved header field was accepted!")
    except ValueError:
        print("[OK] Reserved header field rejected")

    # --- Header tampering must be detected ---
    ct, hdr = alice_ratchet.ratchet_encrypt(b"secret", extra_header={'sender': 'alice'})

    # 1. Forged sender
    forged = dict(hdr, sender='mallory')
    try:
        bob_ratchet.ratchet_decrypt(ct, forged)
        raise AssertionError("Forged sender was accepted!")
    except AssertionError:
        raise
    except Exception:
        print("[OK] Forged sender rejected")

    # 2. Swapped dh_public — the attack the AD binding exists to stop
    swapped = dict(hdr, dh_public=X25519KeyPair().get_public_bytes().hex())
    try:
        bob_ratchet.ratchet_decrypt(ct, swapped)
        raise AssertionError("Swapped dh_public was accepted!")
    except AssertionError:
        raise
    except Exception:
        print("[OK] Swapped dh_public rejected")

    # 3. Bumped message_number
    bumped = dict(hdr, message_number=hdr['message_number'] + 1)
    try:
        bob_ratchet.ratchet_decrypt(ct, bumped)
        raise AssertionError("Bumped message_number was accepted!")
    except AssertionError:
        raise
    except Exception:
        print("[OK] Bumped message_number rejected")

    # 4. After all those failures the session must still work — a rejected
    #    forgery must not have advanced or corrupted Bob's state.
    assert bob_ratchet.ratchet_decrypt(ct, hdr) == b"secret"
    print("[OK] Session survives rejected forgeries")

    followup = b"still alive"
    ct2, hdr2 = alice_ratchet.ratchet_encrypt(followup, extra_header={'sender': 'alice'})
    assert bob_ratchet.ratchet_decrypt(ct2, hdr2) == followup
    print("[OK] Conversation continues after tampering attempts")

    # Out-of-order delivery still works with AD binding in place
    ct_a, hdr_a = alice_ratchet.ratchet_encrypt(b"first", extra_header={'sender': 'alice'})
    ct_b, hdr_b = alice_ratchet.ratchet_encrypt(b"second", extra_header={'sender': 'alice'})
    assert bob_ratchet.ratchet_decrypt(ct_b, hdr_b) == b"second"  # arrives early
    assert bob_ratchet.ratchet_decrypt(ct_a, hdr_a) == b"first"   # skipped key
    print("[OK] Out-of-order delivery works")

    # Test state serialization
    alice_dict = alice_state.to_dict()
    alice_restored = RatchetState.from_dict(alice_dict)
    print("[OK] State serialization works")

    print("\n[PASS] All Double Ratchet tests passed!")
