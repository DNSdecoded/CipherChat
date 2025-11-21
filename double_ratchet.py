# -*- coding: utf-8 -*-
"""
Double Ratchet Algorithm Implementation
Provides Perfect Forward Secrecy and Future Secrecy for encrypted messaging.

Based on the Signal Protocol specification:
https://signal.org/docs/specifications/doubleratchet/
"""

import os
import json
import base64
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Tuple
from datetime import datetime

from x25519_utils import X25519KeyPair, kdf_rk, kdf_ck
from crypto_utils import MessageEncryptor


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
    
    def ratchet_encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> Tuple[bytes, dict]:
        """
        Encrypt message and advance sending ratchet.
        
        Args:
            plaintext: Message to encrypt
            associated_data: Additional authenticated data (not encrypted)
        
        Returns:
            Tuple of (ciphertext, header_dict)
            header_dict contains: dh_public, message_number, previous_chain_length
        """
        # Derive message key from sending chain
        self.state.chain_key_send, message_key = kdf_ck(self.state.chain_key_send)
        
        # Create header
        header = {
            'dh_public': self.state.dh_self_public.hex(),
            'message_number': self.state.message_number_send,
            'previous_chain_length': self.state.previous_chain_length
        }
        
        # Encrypt with AES-256-GCM using message key
        ciphertext = self.encryptor.aes_gcm_encrypt(plaintext, message_key, associated_data)
        
        # Increment message number
        self.state.message_number_send += 1
        
        return ciphertext, header
    
    def ratchet_decrypt(self, ciphertext: bytes, header: dict, 
                       associated_data: bytes = b"") -> bytes:
        """
        Decrypt message and advance ratchet if needed.
        
        Args:
            ciphertext: Encrypted message
            header: Message header with dh_public, message_number, previous_chain_length
            associated_data: Additional authenticated data
        
        Returns:
            Decrypted plaintext
        """
        header_dh = bytes.fromhex(header['dh_public'])
        msg_num = header['message_number']
        prev_chain_len = header['previous_chain_length']
        
        # Check if this is a new DH ratchet step
        if self.state.dh_peer is None or header_dh != self.state.dh_peer:
            # Skip messages from previous chain if needed
            self._skip_message_keys(prev_chain_len)
            
            # Perform DH ratchet step
            self._dh_ratchet(header_dh)
        
        # Try to decrypt with skipped keys first (out-of-order)
        skipped_key = self.state.skipped_message_keys.get((header_dh.hex(), msg_num))
        if skipped_key:
            del self.state.skipped_message_keys[(header_dh.hex(), msg_num)]
            return self.encryptor.aes_gcm_decrypt(ciphertext, skipped_key, associated_data)
        
        # Skip messages if this message number is ahead
        self._skip_message_keys(msg_num)
        
        # Derive message key
        self.state.chain_key_recv, message_key = kdf_ck(self.state.chain_key_recv)
        self.state.message_number_recv += 1
        
        # Decrypt
        return self.encryptor.aes_gcm_decrypt(ciphertext, message_key, associated_data)
    
    def _dh_ratchet(self, peer_public_key: bytes):
        """
        Perform DH ratchet step.
        
        This is called when we receive a message with a new DH public key.
        It provides forward secrecy by generating new keys.
        
        Args:
            peer_public_key: Peer's new DH public key
        """
        # Store previous chain length
        self.state.previous_chain_length = self.state.message_number_send
        
        # Reset message numbers
        self.state.message_number_send = 0
        self.state.message_number_recv = 0
        
        # Update peer's DH public key
        self.state.dh_peer = peer_public_key
        
        # Perform DH with our current key
        dh_self = X25519KeyPair.from_private_bytes(self.state.dh_self_private)
        dh_output = dh_self.dh(peer_public_key)
        
        # Update root key and receiving chain
        self.state.root_key, self.state.chain_key_recv = kdf_rk(
            self.state.root_key, dh_output
        )
        
        # Generate new DH key pair
        new_dh = X25519KeyPair()
        self.state.dh_self_private = new_dh.get_private_bytes()
        self.state.dh_self_public = new_dh.get_public_bytes()
        
        # Perform DH with new key
        dh_output = new_dh.dh(peer_public_key)
        
        # Update root key and sending chain
        self.state.root_key, self.state.chain_key_send = kdf_rk(
            self.state.root_key, dh_output
        )
    
    def _skip_message_keys(self, until: int):
        """
        Store keys for skipped messages (out-of-order handling).
        
        Args:
            until: Message number to skip until
        
        Raises:
            Exception: If too many messages would be skipped
        """
        if self.state.message_number_recv + self.MAX_SKIP < until:
            raise Exception(f"Too many skipped messages: {until - self.state.message_number_recv}")
        
        if self.state.chain_key_recv is not None:
            while self.state.message_number_recv < until:
                ck, mk = kdf_ck(self.state.chain_key_recv)
                
                # Store skipped message key
                key = (self.state.dh_peer.hex(), self.state.message_number_recv)
                self.state.skipped_message_keys[key] = mk
                
                self.state.chain_key_recv = ck
                self.state.message_number_recv += 1


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
    
    # Test state serialization
    alice_dict = alice_state.to_dict()
    alice_restored = RatchetState.from_dict(alice_dict)
    print("[OK] State serialization works")
    
    print("\n[PASS] All Double Ratchet tests passed!")
