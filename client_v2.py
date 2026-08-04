# -*- coding: utf-8 -*-
"""
Encrypted Dual-Stack Chat Client v2.0
Terminal-based chat client with Forward Secrecy (X3DH + Double Ratchet).
"""

import socket
import ssl
import threading
import json
import sys
import os
import base64
import getpass

# Configure stdout for UTF-8 on Windows
if sys.platform == 'win32':
    import codecs
    if hasattr(sys.stdout, 'buffer'):
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

from datetime import datetime

import config

# Forward Secrecy imports
if config.E2E_ENABLED:
    from x3dh import (
        X3DHKeyManager, X3DHPreKeyBundle, x3dh_initiate, x3dh_respond,
        verify_prekey_bundle,
    )
    from double_ratchet import RatchetState, DoubleRatchet
    from x25519_utils import X25519KeyPair, generate_fingerprint, generate_safety_number
    from ratchet_store import RatchetStore, RatchetStoreError


class ChatClient:
    """Encrypted chat client with Forward Secrecy and dual-stack support."""
    
    PROTOCOL_VERSION = "3.0"  # Ed25519-signed bundles + AEAD-bound headers

    # Mirrors ChatServer.MAX_BUFFER_SIZE; a hostile or broken server can flood
    # the client just as easily as the reverse.
    MAX_BUFFER_SIZE = 64 * 1024


    def __init__(self, server_host, server_port, username, store=None):
        self.server_host = server_host
        self.server_port = server_port
        self.username = username
        self.socket = None
        self.running = False
        self.address_family = None

        # Encrypted at-rest state; a disabled store makes every call a no-op
        self.store = store or RatchetStore(username, "")

        # Forward Secrecy (X3DH + Double Ratchet)
        self.e2e_enabled = config.E2E_ENABLED
        if self.e2e_enabled:
            # X3DH key manager
            self.x3dh_manager = X3DHKeyManager()

            # Ratchet states for each peer
            self.ratchet_states = {}  # {username: DoubleRatchet}
            self.ratchet_lock = threading.Lock()
            
            # Peer X3DH bundles
            self.peer_bundles = {}  # {username: X3DHPreKeyBundle}
            self.bundles_lock = threading.Lock()
            
            # Track initialization
            self.keys_initialized = False
            
            # TOFU: Trust-on-First-Use for MITM protection
            self.trusted_keys = {}  # {username: identity_key_hex}
            self.trusted_keys_file = 'trusted_keys.json'
            self.load_trusted_keys()

            # Restore identity and sessions before anything touches the network
            self.restore_state()

    def restore_state(self):
        """
        Load persisted identity keys and ratchet sessions, if any.

        Must run before generate_keys(), because the bundle we publish has to be
        built from the restored identity — publishing a fresh one would trip
        every peer's TOFU warning.
        """
        try:
            saved = self.store.load()
        except RatchetStoreError as e:
            # Refuse to silently continue with a new identity: that is exactly
            # what an attacker who deleted the file would want.
            print(f"\n[ERROR] {e}", file=sys.stderr)
            print(f"[ERROR] Delete {self.store.path} to start over with a NEW "
                  f"identity (all peers will see a key-change warning).",
                  file=sys.stderr)
            raise SystemExit(1)

        if not saved:
            if self.store.enabled:
                print("[STORE] No saved state; creating a new identity")
            return

        try:
            self.x3dh_manager = X3DHKeyManager.from_private_state(saved['x3dh'])
            for peer, state_dict in saved.get('ratchets', {}).items():
                self.ratchet_states[peer] = DoubleRatchet(
                    RatchetState.from_dict(state_dict)
                )
        except (KeyError, ValueError, TypeError) as e:
            print(f"\n[ERROR] Saved state is unusable: {e}", file=sys.stderr)
            raise SystemExit(1)

        print(f"[STORE] Restored identity and {len(self.ratchet_states)} session(s)")

    def save_state(self):
        """
        Persist identity keys and every ratchet session.

        Called after each send and each successful decrypt: the ratchet advances
        on both, and a state file that lags the wire cannot decrypt what arrives
        next.
        """
        if not self.store.enabled or not self.e2e_enabled:
            return

        try:
            with self.ratchet_lock:
                ratchets = {
                    peer: ratchet.state.to_dict()
                    for peer, ratchet in self.ratchet_states.items()
                }
            self.store.save({
                'username': self.username,
                'x3dh': self.x3dh_manager.export_private_state(),
                'ratchets': ratchets,
            })
        except Exception as e:
            # Never let a storage failure kill a live conversation
            print(f"\n[WARN] Could not save state: {e}", file=sys.stderr)
    
    def create_ssl_context(self):
        """Create SSL context for TLS encryption."""
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # Pin the self-signed server certificate. Without this the transport is
        # unauthenticated and anyone on the path can terminate TLS, read every
        # key bundle, and substitute their own — defeating E2E before it starts.
        # The operator distributes certs/server.crt to clients out-of-band.
        try:
            ssl_context.load_verify_locations(config.SERVER_CERT)
        except FileNotFoundError:
            print(f"[ERROR] Server certificate not found: {config.SERVER_CERT}",
                  file=sys.stderr)
            print("        Obtain it from the server operator, or run "
                  "'python generate_certs.py' if you run the server yourself.",
                  file=sys.stderr)
            raise

        ssl_context.verify_mode = ssl.CERT_REQUIRED
        ssl_context.check_hostname = True

        return ssl_context
    
    def detect_address_family(self):
        """Detect whether to use IPv4 or IPv6."""
        if self.server_host.lower() == 'localhost':
            return socket.AF_INET6
        
        try:
            socket.inet_pton(socket.AF_INET6, self.server_host)
            return socket.AF_INET6
        except socket.error:
            pass
        
        try:
            socket.inet_pton(socket.AF_INET, self.server_host)
            return socket.AF_INET
        except socket.error:
            pass
        
        return socket.AF_INET6
    
    def connect(self):
        """Connect to server with TLS encryption."""
        self.address_family = self.detect_address_family()
        family = self.address_family
        protocol_name = "IPv6" if family == socket.AF_INET6 else "IPv4"
        
        try:
            raw_socket = socket.socket(family, socket.SOCK_STREAM)
            raw_socket.settimeout(config.CLIENT_TIMEOUT)
            
            print(f"Connecting to {self.server_host}:{self.server_port} using {protocol_name}...")
            raw_socket.connect((self.server_host, self.server_port))
            
            ssl_context = self.create_ssl_context()
            # server_hostname drives certificate hostname checking; None disables it
            self.socket = ssl_context.wrap_socket(
                raw_socket,
                server_hostname=self.server_host
            )

            print(f"[OK] Connected via {protocol_name}")
            print(f"[OK] TLS encryption enabled ({self.socket.version()})")
            print("=" * 60)
            
            # Disable Nagle's algorithm for real-time delivery
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.socket.settimeout(None)
            
            return True
            
        except socket.timeout:
            print(f"[ERROR] Connection timeout", file=sys.stderr)
            if self.server_host.lower() == 'localhost' and family == socket.AF_INET6:
                print("Trying IPv4 fallback...", file=sys.stderr)
                return self.connect_with_fallback()
            return False
            
        except ConnectionRefusedError:
            print(f"[ERROR] Connection refused - is server running?", file=sys.stderr)
            if self.server_host.lower() == 'localhost' and family == socket.AF_INET6:
                print("Trying IPv4 fallback...", file=sys.stderr)
                return self.connect_with_fallback()
            return False
            
        except Exception as e:
            print(f"[ERROR] Connection error: {e}", file=sys.stderr)
            return False
    
    def connect_with_fallback(self):
        """Fallback to IPv4 if IPv6 fails."""
        try:
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_socket.settimeout(config.CLIENT_TIMEOUT)
            
            print(f"Connecting to {config.CLIENT_LOCALHOST_IPV4}:{self.server_port} using IPv4...")
            raw_socket.connect((config.CLIENT_LOCALHOST_IPV4, self.server_port))
            
            ssl_context = self.create_ssl_context()
            # Must match the address actually dialled, not the original hostname,
            # or hostname checking fails against the cert's IP SAN.
            self.socket = ssl_context.wrap_socket(
                raw_socket,
                server_hostname=config.CLIENT_LOCALHOST_IPV4
            )

            print(f"[OK] Connected via IPv4")
            print(f"[OK] TLS encryption enabled ({self.socket.version()})")
            print("=" * 60)
            
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.socket.settimeout(None)
            return True
            
        except Exception as e:
            print(f"[ERROR] IPv4 fallback failed: {e}", file=sys.stderr)
            return False
    
    def generate_keys(self):
        """Generate X3DH key bundle for Forward Secrecy."""
        if not self.e2e_enabled:
            return
        
        # Generate X3DH key bundle
        print("[E2E] Generating X3DH key bundle...")
        bundle = self.x3dh_manager.get_prekey_bundle()
        
        # Display signing key fingerprint. This must be the key TOFU pins, or
        # what users compare out-of-band would not be what is actually verified.
        fingerprint = generate_fingerprint(self.x3dh_manager.signing_keypair.get_public_bytes())
        print(f"[E2E] Identity key fingerprint:")
        print(f"      {fingerprint}")
        print(f"[E2E] Protocol: Signal (X3DH + Double Ratchet)")
        print(f"[E2E] Sending X3DH bundle with JOIN")
        
        # Publish the one-time key pool alongside the bundle. The server hands
        # out one per requester so no two initiators share a key.
        onetime_prekeys = [
            {'id': key_id, 'key': pair.get_public_bytes().hex()}
            for key_id, pair in self.x3dh_manager.onetime_prekeys.items()
        ]
        print(f"[E2E] Publishing {len(onetime_prekeys)} one-time pre-key(s)")

        # Send JOIN with X3DH bundle
        join_msg = {
            'type': 'join',
            'username': self.username,
            'x3dh_bundle': bundle.to_dict(),
            'onetime_prekeys': onetime_prekeys,
            'protocol_version': self.PROTOCOL_VERSION
        }
        self.send_message(join_msg)
    
    def send_message(self, message):
        """Send JSON message to server."""
        try:
            data = json.dumps(message).encode('utf-8')
            self.socket.sendall(data + b'\n')
        except Exception as e:
            print(f"\n[ERROR] Send failed: {e}", file=sys.stderr)
            self.running = False
    
    TRUSTED_KEYS_VERSION = 2  # v2 pins the Ed25519 signing key, v1 pinned X25519

    def load_trusted_keys(self):
        """Load trusted signing keys from disk (TOFU)."""
        self.trusted_keys = {}
        try:
            if not os.path.exists(self.trusted_keys_file):
                return

            with open(self.trusted_keys_file, 'r') as f:
                data = json.load(f)

            # A v1 file pinned X25519 identity keys. Those are not the keys we
            # verify against any more, so migrating them would pin the wrong
            # thing and silently defeat the check. Discard and re-TOFU instead.
            if not isinstance(data, dict) or data.get('version') != self.TRUSTED_KEYS_VERSION:
                print(f"[TOFU] Ignoring outdated {self.trusted_keys_file} "
                      f"(pre-v{self.TRUSTED_KEYS_VERSION} format).")
                print("[TOFU] All peers will be treated as first contact — "
                      "re-verify fingerprints out-of-band.")
                return

            self.trusted_keys = data.get('keys', {})
            print(f"[TOFU] Loaded {len(self.trusted_keys)} trusted key(s)")
        except Exception as e:
            print(f"[WARN] Could not load trusted keys: {e}")
            self.trusted_keys = {}

    def save_trusted_keys(self):
        """Save trusted signing keys to disk with owner-only permissions."""
        payload = {'version': self.TRUSTED_KEYS_VERSION, 'keys': self.trusted_keys}
        try:
            # 0600 so other local users cannot read or tamper with the pins.
            # The mode is ignored on Windows; it matters on POSIX.
            fd = os.open(
                self.trusted_keys_file,
                os.O_CREAT | os.O_WRONLY | os.O_TRUNC,
                0o600
            )
            with os.fdopen(fd, 'w') as f:
                json.dump(payload, f, indent=2)
        except Exception as e:
            print(f"[WARN] Could not save trusted keys: {e}")

    def _accept_peer_bundle(self, username: str, bundle) -> bool:
        """
        Decide whether to accept a peer's pre-key bundle.

        Two independent checks, both required:
        1. The bundle is internally consistent — its signed pre-key and identity
           key really were signed by its signing key. Catches a tampered bundle.
        2. The signing key matches what we pinned for this username (TOFU).
           Catches a wholesale substituted bundle, which would pass check 1.

        Args:
            username: Peer username
            bundle: X3DHPreKeyBundle received from the server

        Returns:
            True if the bundle should be trusted
        """
        if not verify_prekey_bundle(bundle):
            print(f"\n[SECURITY] Bundle from {username} has an invalid signature — rejected.")
            return False

        return self.verify_identity_key(username, bundle.signing_key)

    def verify_identity_key(self, username: str, identity_key: bytes) -> bool:
        """
        Verify a peer's signing key using TOFU (Trust-on-First-Use).

        Args:
            username: Peer username
            identity_key: Peer's Ed25519 signing public key

        Returns:
            True if key is trusted, False if rejected
        """
        identity_key_hex = identity_key.hex()
        stored_key = self.trusted_keys.get(username)
        
        if stored_key is None:
            # First contact - trust and store
            fingerprint = generate_fingerprint(identity_key)
            print(f"\n{'='*60}")
            print(f"[TOFU] First contact with {username}")
            print(f"{'='*60}")
            print(f"Identity fingerprint:")
            print(f"  {fingerprint}")
            print(f"\nThis key will be trusted for future sessions.")
            print(f"Verify this fingerprint with {username} out-of-band")
            print(f"(phone call, in person, etc.) to prevent MITM attacks.")
            print(f"{'='*60}\n")
            
            self.trusted_keys[username] = identity_key_hex
            self.save_trusted_keys()
            return True
        
        if stored_key != identity_key_hex:
            # KEY CHANGED - Potential MITM attack!
            old_fingerprint = generate_fingerprint(bytes.fromhex(stored_key))
            new_fingerprint = generate_fingerprint(identity_key)
            
            print(f"\n{'='*60}")
            print(f"⚠️  SECURITY WARNING: {username}'s key changed!")
            print(f"{'='*60}")
            print(f"Old fingerprint: {old_fingerprint}")
            print(f"New fingerprint: {new_fingerprint}")
            print(f"\nPossible reasons:")
            print(f"  1. {username} reinstalled the app (legitimate)")
            print(f"  2. Man-in-the-middle attack (DANGER!)")
            print(f"\n⚠️  DO NOT ACCEPT unless you verified with {username}!")
            print(f"{'='*60}\n")
            
            try:
                response = input(f"Accept new key for {username}? (yes/no): ").strip().lower()
                if response == 'yes':
                    self.trusted_keys[username] = identity_key_hex
                    self.save_trusted_keys()
                    print(f"[TOFU] Accepted new key for {username}")
                    return True
                else:
                    print(f"[TOFU] Rejected new key for {username}")
                    return False
            except (EOFError, KeyboardInterrupt):
                print(f"\n[TOFU] Rejected new key for {username}")
                return False
        
        # Key matches - trusted
        return True
    
    def send_encrypted_message(self, plaintext: str):
        """
        Encrypt and send message using Double Ratchet.
        Messages are sent individually to each peer.
        """
        if not self.e2e_enabled:
            # Fallback to plaintext
            self.send_message({'type': 'message', 'content': plaintext})
            return
        
        # Get all peers
        with self.bundles_lock:
            if not self.peer_bundles:
                print("\n[WARN] No other users in chat yet.")
                return
            
            peers = list(self.peer_bundles.keys())
        
        # Send to each peer individually
        for peer in peers:
            try:
                # Get or initialize ratchet
                with self.ratchet_lock:
                    if peer not in self.ratchet_states:
                        # Only initialize if we don't have a ratchet yet
                        self._initialize_ratchet_with_peer(peer)
                    
                    ratchet = self.ratchet_states[peer]
                
                # Build the complete header BEFORE encrypting. Every field here
                # is bound into the AEAD tag, so nothing may be added afterwards.
                extra_header = {'sender': self.username}

                # Include X3DH ephemeral key in first message if this is the initiator
                is_first_message = hasattr(ratchet, 'x3dh_ephemeral_pub')
                if is_first_message:
                    extra_header['x3dh_ephemeral'] = ratchet.x3dh_ephemeral_pub.hex()
                    if getattr(ratchet, 'x3dh_onetime_id', None) is not None:
                        extra_header['onetime_prekey_id'] = ratchet.x3dh_onetime_id

                # Encrypt with ratchet
                ciphertext, header = ratchet.ratchet_encrypt(
                    plaintext.encode(), extra_header=extra_header
                )

                # Only drop the ephemeral key once it has actually been sent
                if is_first_message:
                    delattr(ratchet, 'x3dh_ephemeral_pub')

                # Send ratchet message
                msg = {
                    'type': 'ratchet_message',
                    'sender': self.username,
                    'recipient': peer,
                    'header': header,
                    'ciphertext': base64.b64encode(ciphertext).decode(),
                    'timestamp': datetime.now().isoformat()
                }
                self.send_message(msg)
                
            except Exception as e:
                print(f"\n[ERROR] Failed to encrypt for {peer}: {e}", file=sys.stderr)

        # The sending chain advanced; persist before the next message
        self.save_state()
    
    def _initialize_ratchet_with_peer(self, peer_username: str):
        """
        Initialize Double Ratchet with a peer using X3DH (Alice's role).
        Called when sending first message to a peer.
        """
        # Get bundle with lock
        with self.bundles_lock:
            bundle = self.peer_bundles[peer_username]
        
        # Perform X3DH as initiator
        shared_secret, ephemeral_pub = x3dh_initiate(
            self.x3dh_manager.identity_keypair,
            bundle
        )
        
        # Initialize ratchet (we're Alice)
        state = RatchetState.initialize_alice(shared_secret, bundle.signed_prekey)
        ratchet = DoubleRatchet(state)
        
        # Store X3DH ephemeral key for first message
        # This is needed so the responder can derive the same shared secret
        ratchet.x3dh_ephemeral_pub = ephemeral_pub

        # Tell the responder which one-time key we consumed, so it can pick the
        # matching private key. Without this it cannot reproduce DH4.
        ratchet.x3dh_onetime_id = bundle.onetime_prekey_id

        self.ratchet_states[peer_username] = ratchet

        used_opk = "with" if bundle.onetime_prekey else "without"
        print(f"[E2E] Initialized ratchet with {peer_username} (initiator, {used_opk} one-time key)")
    
    def _initialize_ratchet_as_responder(self, sender: str, alice_ephemeral_pub: bytes,
                                         onetime_prekey_id=None):
        """
        Initialize Double Ratchet when receiving first message (Bob's role).

        Args:
            sender: Peer who initiated
            alice_ephemeral_pub: Initiator's ephemeral public key
            onetime_prekey_id: One-time key the initiator says it used, if any
        """
        # Get bundle with lock
        with self.bundles_lock:
            sender_bundle = self.peer_bundles.get(sender)

        if not sender_bundle:
            raise Exception(f"No bundle for {sender}")

        # Consume the one-time key the initiator claims to have used. It is
        # destroyed here: a second message naming the same id gets None and
        # therefore derives a different secret and fails to decrypt.
        onetime_keypair = self.x3dh_manager.consume_onetime_prekey(onetime_prekey_id)
        if onetime_prekey_id is not None and onetime_keypair is None:
            raise Exception(
                f"One-time pre-key {onetime_prekey_id} is unknown or already used"
            )

        # Perform X3DH as responder
        shared_secret = x3dh_respond(
            self.x3dh_manager.identity_keypair,
            self.x3dh_manager.signed_prekey_pair,
            onetime_keypair,
            sender_bundle.identity_key,
            alice_ephemeral_pub
        )
        
        # Initialize ratchet (we're Bob)
        state = RatchetState.initialize_bob(
            shared_secret,
            self.x3dh_manager.signed_prekey_pair
        )
        self.ratchet_states[sender] = DoubleRatchet(state)
        
        print(f"[E2E] Initialized ratchet with {sender} (responder)")
    
    def receive_messages(self):
        """Receive and handle messages from server."""
        buffer = ""
        
        while self.running:
            try:
                data = self.socket.recv(config.BUFFER_SIZE)
                if not data:
                    print("\n[ERROR] Connection closed by server")
                    self.running = False
                    break
                
                buffer += data.decode('utf-8')

                if len(buffer) > self.MAX_BUFFER_SIZE:
                    print("\n[ERROR] Server sent an oversized message; disconnecting.",
                          file=sys.stderr)
                    self.running = False
                    break

                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    if line.strip():
                        try:
                            message = json.loads(line)
                            self._handle_message(message)
                        except json.JSONDecodeError:
                            pass
                
            except ConnectionResetError:
                print("\n[ERROR] Connection reset")
                self.running = False
                break
            except Exception as e:
                if self.running:
                    print(f"\n[ERROR] Receive error: {e}", file=sys.stderr)
                    self.running = False
                break
    
    def _handle_message(self, message: dict):
        """Handle incoming message based on type."""
        msg_type = message.get('type')
        
        if msg_type == 'bundle_sync':
            # Receive all existing bundles
            bundles_dict = message.get('bundles', {})
            with self.bundles_lock:
                for username, bundle_dict in bundles_dict.items():
                    try:
                        bundle = X3DHPreKeyBundle.from_dict(bundle_dict)
                    except (KeyError, ValueError, TypeError):
                        print(f"[SECURITY] Malformed bundle for {username} - ignored")
                        continue

                    if not self._accept_peer_bundle(username, bundle):
                        continue

                    self.peer_bundles[username] = bundle
                self.keys_initialized = True
            
            if bundles_dict:
                print(f"\n[E2E] Received {len(bundles_dict)} bundle(s)")
            else:
                print(f"\n[E2E] No other users yet (you're first)")
        
        elif msg_type == 'key_bundle':
            # New user's bundle
            username = message.get('username')
            bundle_dict = message.get('bundle')
            if username and bundle_dict:
                try:
                    bundle = X3DHPreKeyBundle.from_dict(bundle_dict)
                except (KeyError, ValueError, TypeError):
                    print(f"[SECURITY] Malformed bundle for {username} - ignored")
                    return

                if not self._accept_peer_bundle(username, bundle):
                    return

                with self.bundles_lock:
                    self.peer_bundles[username] = bundle
                    self.keys_initialized = True
                print(f"[E2E] Received bundle for {username}")
        
        elif msg_type == 'opk_replenish':
            # Server's pool for us is running low; generate and upload more.
            target = message.get('count') or X3DHKeyManager.DEFAULT_ONETIME_COUNT
            entries = self.x3dh_manager.generate_onetime_prekeys(target)
            self.send_message({
                'type': 'opk_upload',
                'onetime_prekeys': entries,
            })
            print(f"\n[E2E] Uploaded {len(entries)} fresh one-time pre-key(s)")

        elif msg_type == 'bundle_removal':
            # User disconnected
            username = message.get('username')
            if username:
                with self.bundles_lock:
                    if username in self.peer_bundles:
                        del self.peer_bundles[username]
                with self.ratchet_lock:
                    if username in self.ratchet_states:
                        del self.ratchet_states[username]
                print(f"\n[E2E] Removed bundle for {username}")
        
        elif msg_type == 'ratchet_message':
            # Encrypted message
            self._handle_ratchet_message(message)
        
        elif msg_type == 'system':
            # System message
            content = message.get('content', '')
            print(f"\n[SYSTEM] {content}")
            sys.stdout.flush()
            print(f"{self.username}> ", end='', flush=True)
        
        elif msg_type == 'message':
            # Plaintext message (fallback)
            username = message.get('username', 'Unknown')
            content = message.get('content', '')
            timestamp = message.get('timestamp', '')
            
            try:
                dt = datetime.fromisoformat(timestamp)
                time_str = dt.strftime('%H:%M:%S')
            except:
                time_str = ''
            
            if time_str:
                print(f"\n[{time_str}] {username}: {content}")
            else:
                print(f"\n{username}: {content}")
            
            sys.stdout.flush()
            print(f"{self.username}> ", end='', flush=True)
    
    def _handle_ratchet_message(self, message: dict):
        """Decrypt and display ratchet message."""
        sender = message.get('sender')
        header = message.get('header')
        ciphertext_b64 = message.get('ciphertext')
        timestamp = message.get('timestamp', '')
        
        try:
            ciphertext = base64.b64decode(ciphertext_b64)
            
            # Get or initialize ratchet
            with self.ratchet_lock:
                if sender not in self.ratchet_states:
                    # First message from this sender - check for X3DH ephemeral key
                    if 'x3dh_ephemeral' in header:
                        # This is the first message, use X3DH ephemeral key
                        alice_ephemeral = bytes.fromhex(header['x3dh_ephemeral'])
                    else:
                        # Fallback to ratchet DH key (shouldn't happen in normal flow)
                        alice_ephemeral = bytes.fromhex(header['dh_public'])

                    self._initialize_ratchet_as_responder(
                        sender, alice_ephemeral, header.get('onetime_prekey_id')
                    )
                
                ratchet = self.ratchet_states[sender]
            
            # Decrypt
            plaintext = ratchet.ratchet_decrypt(ciphertext, header)

            # The header is AEAD-bound, so its `sender` is what the peer actually
            # encrypted. The envelope `sender` is only what the server routed by.
            # A mismatch means someone is claiming another user's messages.
            claimed = header.get('sender')
            if claimed != sender:
                print(f"\n[SECURITY] Dropped message routed as '{sender}' but "
                      f"signed by '{claimed}'.")
                sys.stdout.flush()
                print(f"{self.username}> ", end='', flush=True)
                return

            # Display
            try:
                dt = datetime.fromisoformat(timestamp)
                time_str = dt.strftime('%H:%M:%S')
            except:
                time_str = ''
            
            if time_str:
                print(f"\n[{time_str}] [FS] {sender}: {plaintext.decode()}")
            else:
                print(f"\n[FS] {sender}: {plaintext.decode()}")

            # Receiving chain advanced (and a one-time key may have been
            # consumed); persist so a restart does not replay or desync
            self.save_state()

            sys.stdout.flush()
            print(f"{self.username}> ", end='', flush=True)
            
        except Exception:
            # Deliberately generic: the exception text and traceback expose
            # ratchet internals, and a peer can trigger this at will.
            print(f"\n[WARN] Could not decrypt a message from {sender} "
                  f"(tampered, replayed, or out of sync).", file=sys.stderr)
            sys.stdout.flush()
            print(f"{self.username}> ", end='', flush=True)
    
    def send_messages(self):
        """Handle user input and send messages."""
        print()
        print("Type your messages below. Press Ctrl+C to quit.")
        print("=" * 60)
        
        while self.running:
            try:
                user_input = input(f"{self.username}> ")
                
                if not user_input.strip():
                    continue
                
                # Send encrypted message
                if self.e2e_enabled:
                    self.send_encrypted_message(user_input.strip())
                else:
                    msg = {
                        'type': 'message',
                        'content': user_input.strip()
                    }
                    self.send_message(msg)
                
            except EOFError:
                break
            except KeyboardInterrupt:
                print("\n\nDisconnecting...")
                break
            except Exception as e:
                print(f"\n[ERROR] {e}", file=sys.stderr)
                break
    
    def start(self):
        """Start the chat client."""
        if not self.connect():
            return False
        
        self.running = True
        
        # Receive welcome message
        try:
            data = self.socket.recv(config.BUFFER_SIZE)
            if data:
                message = json.loads(data.decode('utf-8'))
                print(f"\n{message.get('content', '')}\n")
        except:
            pass
        
        # Generate X3DH keys
        if self.e2e_enabled:
            self.generate_keys()
        # Start receiver thread
        receiver_thread = threading.Thread(
            target=self.receive_messages,
            daemon=True
        )
        receiver_thread.start()
        
        # Handle sending in main thread
        self.send_messages()
        
        # Cleanup
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        print("Disconnected.")
        return True
    
    def stop(self):
        """Stop the client."""
        self.running = False


def main():
    """Main entry point."""
    print("=" * 60)
    print("     Encrypted Chat Client v2.0")
    print("     Forward Secrecy (Signal Protocol)")
    print("=" * 60)
    print()
    
    try:
        server = input(f"Server address (default: localhost): ").strip()
        if not server:
            server = "localhost"
        
        port_input = input(f"Server port (default: {config.SERVER_PORT}): ").strip()
        if port_input:
            port = int(port_input)
        else:
            port = config.SERVER_PORT
        
        username = input("Enter your username: ").strip()
        if not username:
            username = "Anonymous"
        
        username = username[:config.USERNAME_MAX_LENGTH]

        print()
        print("A passphrase encrypts your identity and sessions on disk, so peers")
        print("do not see a key-change warning every time you restart.")
        print("Leave blank to keep everything in memory only (previous behaviour).")
        passphrase = getpass.getpass("Passphrase (blank for none): ")

        print()

    except KeyboardInterrupt:
        print("\n\nCancelled.")
        return
    except ValueError:
        print("[ERROR] Invalid port number", file=sys.stderr)
        return
    
    store = RatchetStore(username, passphrase)
    if store.enabled and not store.exists():
        # New store: make sure a typo does not lock the user out of an identity
        # their peers are about to pin.
        if getpass.getpass("Confirm passphrase: ") != passphrase:
            print("[ERROR] Passphrases do not match.", file=sys.stderr)
            return

    client = ChatClient(server, port, username, store=store)
    
    try:
        client.start()
    except KeyboardInterrupt:
        print("\n\nDisconnecting...")
    finally:
        client.stop()


if __name__ == '__main__':
    main()
