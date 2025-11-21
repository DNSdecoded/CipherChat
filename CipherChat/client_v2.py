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
    from x3dh import X3DHKeyManager, X3DHPreKeyBundle, x3dh_initiate, x3dh_respond
    from double_ratchet import RatchetState, DoubleRatchet
    from x25519_utils import X25519KeyPair, generate_fingerprint, generate_safety_number


class ChatClient:
    """Encrypted chat client with Forward Secrecy and dual-stack support."""
    
    PROTOCOL_VERSION = "2.0"  # Forward Secrecy protocol
    
    def __init__(self, server_host, server_port, username, verify_cert=False):
        self.server_host = server_host
        self.server_port = server_port
        self.username = username
        self.verify_cert = verify_cert
        self.socket = None
        self.running = False
        self.address_family = None
        
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
    
    def create_ssl_context(self):
        """Create SSL context for TLS encryption."""
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        if self.verify_cert:
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            ssl_context.check_hostname = True
            ssl_context.load_verify_locations(config.SERVER_CERT)
        else:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        
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
            self.socket = ssl_context.wrap_socket(
                raw_socket,
                server_hostname=None
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
            self.socket = ssl_context.wrap_socket(raw_socket, server_hostname=None)
            
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
        
        # Display identity key fingerprint
        fingerprint = generate_fingerprint(self.x3dh_manager.identity_keypair.get_public_bytes())
        print(f"[E2E] Identity key fingerprint:")
        print(f"      {fingerprint}")
        print(f"[E2E] Protocol: Signal (X3DH + Double Ratchet)")
        print(f"[E2E] Sending X3DH bundle with JOIN")
        
        # Send JOIN with X3DH bundle
        join_msg = {
            'type': 'join',
            'username': self.username,
            'x3dh_bundle': bundle.to_dict(),
            'protocol_version': '2.0'
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
    
    def load_trusted_keys(self):
        """Load trusted identity keys from disk (TOFU)."""
        try:
            if os.path.exists(self.trusted_keys_file):
                with open(self.trusted_keys_file, 'r') as f:
                    self.trusted_keys = json.load(f)
                print(f"[TOFU] Loaded {len(self.trusted_keys)} trusted key(s)")
        except Exception as e:
            print(f"[WARN] Could not load trusted keys: {e}")
            self.trusted_keys = {}
    
    def save_trusted_keys(self):
        """Save trusted identity keys to disk."""
        try:
            with open(self.trusted_keys_file, 'w') as f:
                json.dump(self.trusted_keys, f, indent=2)
        except Exception as e:
            print(f"[WARN] Could not save trusted keys: {e}")
    
    def verify_identity_key(self, username: str, identity_key: bytes) -> bool:
        """
        Verify identity key using TOFU (Trust-on-First-Use).
        
        Args:
            username: Peer username
            identity_key: Peer's identity public key
        
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
                
                # Encrypt with ratchet
                ciphertext, header = ratchet.ratchet_encrypt(plaintext.encode())
                
                # Include X3DH ephemeral key in first message if this is the initiator
                if hasattr(ratchet, 'x3dh_ephemeral_pub'):
                    header['x3dh_ephemeral'] = ratchet.x3dh_ephemeral_pub.hex()
                    # Remove it after first use
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
        
        self.ratchet_states[peer_username] = ratchet
        
        print(f"[E2E] Initialized ratchet with {peer_username} (initiator)")
    
    def _initialize_ratchet_as_responder(self, sender: str, alice_ephemeral_pub: bytes):
        """
        Initialize Double Ratchet when receiving first message (Bob's role).
        """
        # Get bundle with lock
        with self.bundles_lock:
            sender_bundle = self.peer_bundles.get(sender)
        
        if not sender_bundle:
            raise Exception(f"No bundle for {sender}")
        
        # Perform X3DH as responder
        shared_secret = x3dh_respond(
            self.x3dh_manager.identity_keypair,
            self.x3dh_manager.signed_prekey_pair,
            None,  # One-time key tracking not implemented yet
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
                    bundle = X3DHPreKeyBundle.from_dict(bundle_dict)
                    
                    # TOFU: Verify identity key
                    if not self.verify_identity_key(username, bundle.identity_key):
                        print(f"[SECURITY] Rejected bundle from {username} - key verification failed")
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
                bundle = X3DHPreKeyBundle.from_dict(bundle_dict)
                
                # TOFU: Verify identity key
                if not self.verify_identity_key(username, bundle.identity_key):
                    print(f"[SECURITY] Rejected bundle from {username} - key verification failed")
                    return
                
                with self.bundles_lock:
                    self.peer_bundles[username] = bundle
                    self.keys_initialized = True
                print(f"[E2E] Received bundle for {username}")
        
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
                    
                    self._initialize_ratchet_as_responder(sender, alice_ephemeral)
                
                ratchet = self.ratchet_states[sender]
            
            # Decrypt
            plaintext = ratchet.ratchet_decrypt(ciphertext, header)
            
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
            
            sys.stdout.flush()
            print(f"{self.username}> ", end='', flush=True)
            
        except Exception as e:
            print(f"\n[ERROR] Decryption failed from {sender}: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
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
        
    except KeyboardInterrupt:
        print("\n\nCancelled.")
        return
    except ValueError:
        print("[ERROR] Invalid port number", file=sys.stderr)
        return
    
    client = ChatClient(server, port, username, verify_cert=False)
    
    try:
        client.start()
    except KeyboardInterrupt:
        print("\n\nDisconnecting...")
    finally:
        client.stop()


if __name__ == '__main__':
    main()
