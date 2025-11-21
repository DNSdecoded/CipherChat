# -*- coding: utf-8 -*-
"""
Encrypted Dual-Stack Chat Client
Terminal-based chat client with TLS/SSL encryption over IPv4 and IPv6.
"""

import socket
import ssl
import threading
import json
import sys

# Configure stdout for UTF-8 on Windows
if sys.platform == 'win32':
    import codecs
    if hasattr(sys.stdout, 'buffer'):
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

from datetime import datetime

import config

# E2E Encryption imports
if config.E2E_ENABLED:
    from crypto_utils import E2EKeyManager, MessageEncryptor, generate_fingerprint


class ChatClient:
    """Encrypted chat client with async message handling and dual-stack support."""
    
    def __init__(self, server_host, server_port, username, verify_cert=False):
        self.server_host = server_host
        self.server_port = server_port
        self.username = username
        self.verify_cert = verify_cert
        self.socket = None
        self.running = False
        self.address_family = None  # Will be determined by detect_address_family()
        
        # E2E Encryption
        self.e2e_enabled = config.E2E_ENABLED
        if self.e2e_enabled:
            self.key_manager = E2EKeyManager(key_size=config.RSA_KEY_SIZE)
            self.encryptor = MessageEncryptor()
            self.public_key_pem = None
            self.private_key_pem = None
            self.peer_public_keys = {}  # {username: public_key_pem}
            self.peer_keys_lock = threading.Lock()
            self.keys_initialized = False  # Track if we've received peer keys
    
    def detect_address_family(self):
        """Detect whether to use IPv4 or IPv6 based on the server address."""
        # Handle special case for 'localhost'
        if self.server_host.lower() == 'localhost':
            # Try IPv6 first, then IPv4
            return socket.AF_INET6, '::1'
        
        # Try to determine address family from the address format
        try:
            # Try to parse as IPv4 or IPv6 address
            addr_info = socket.getaddrinfo(
                self.server_host, 
                self.server_port, 
                socket.AF_UNSPEC,  # Accept both IPv4 and IPv6
                socket.SOCK_STREAM
            )
            
            if addr_info:
                # Use the first result
                family = addr_info[0][0]
                sockaddr = addr_info[0][4]
                host = sockaddr[0]
                return family, host
        except socket.gaierror:
            pass
        
        # Default to IPv4 if detection fails
        return socket.AF_INET, self.server_host
    
    def create_ssl_context(self):
        """Create SSL context for client connection."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        if self.verify_cert:
            # Verify server certificate (requires CA cert)
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(config.SERVER_CERT)
        else:
            # Skip certificate verification (for self-signed certs)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        
        return context
    
    def connect(self):
        """Connect to the chat server."""
        # Detect address family and resolve address
        family, resolved_host = self.detect_address_family()
        self.address_family = family
        protocol_name = "IPv6" if family == socket.AF_INET6 else "IPv4"
        
        try:
            # Create socket with detected family
            raw_socket = socket.socket(family, socket.SOCK_STREAM)
            raw_socket.settimeout(config.CLIENT_TIMEOUT)
            
            print(f"Connecting to {resolved_host}:{self.server_port} using {protocol_name}...")
            raw_socket.connect((resolved_host, self.server_port))
            
            # Wrap with SSL
            ssl_context = self.create_ssl_context()
            self.socket = ssl_context.wrap_socket(
                raw_socket,
                server_hostname=None  # Skip hostname check for IP addresses
            )
            
            print(f"✓ Connected successfully via {protocol_name}")
            print(f"✓ TLS encryption enabled ({self.socket.version()})")
            print("=" * 60)
            
            # Disable Nagle's algorithm to send messages immediately (no buffering)
            # This ensures messages are sent in real-time, not delayed until disconnect
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            
            # Remove timeout for message handling
            self.socket.settimeout(None)
            
            return True
            
        except socket.timeout:
            print(f"✗ Connection timeout - server not responding", file=sys.stderr)
            
            # Try fallback if localhost
            if self.server_host.lower() == 'localhost' and family == socket.AF_INET6:
                print(f"Trying IPv4 fallback...", file=sys.stderr)
                return self.connect_with_fallback()
            return False
            
        except ConnectionRefusedError:
            print(f"✗ Connection refused - is the server running?", file=sys.stderr)
            
            # Try fallback if localhost
            if self.server_host.lower() == 'localhost' and family == socket.AF_INET6:
                print(f"Trying IPv4 fallback...", file=sys.stderr)
                return self.connect_with_fallback()
            return False
            
        except socket.gaierror as e:
            print(f"✗ Invalid address: {e}", file=sys.stderr)
            return False
        except Exception as e:
            print(f"✗ Connection error: {e}", file=sys.stderr)
            return False
    
    def connect_with_fallback(self):
        """Fallback connection attempt using IPv4."""
        try:
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_socket.settimeout(config.CLIENT_TIMEOUT)
            
            print(f"Connecting to {config.CLIENT_LOCALHOST_IPV4}:{self.server_port} using IPv4...")
            raw_socket.connect((config.CLIENT_LOCALHOST_IPV4, self.server_port))
            
            ssl_context = self.create_ssl_context()
            self.socket = ssl_context.wrap_socket(
                raw_socket,
                server_hostname=None
            )
            
            print(f"✓ Connected successfully via IPv4")
            print(f"✓ TLS encryption enabled ({self.socket.version()})")
            print("=" * 60)
            
            # Disable Nagle's algorithm to send messages immediately
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            
            self.socket.settimeout(None)
            return True
            
        except Exception as e:
            print(f"✗ IPv4 fallback failed: {e}", file=sys.stderr)
            return False
    
    def generate_keys(self):
        """Generate RSA key pair for E2E encryption."""
        if not self.e2e_enabled:
            return
        
        print("\n[E2E] Generating RSA key pair...")
        self.public_key_pem, self.private_key_pem = self.key_manager.generate_key_pair()
        
        # Generate and display fingerprint
        fingerprint = generate_fingerprint(self.public_key_pem)
        print(f"[E2E] Key pair generated successfully")
        print(f"[E2E] Your public key fingerprint:")
        print(f"      {fingerprint}")
    
    
    def request_peer_keys(self, usernames: list):
        """Request public keys for specific users (used for edge cases/recovery)."""
        if not self.e2e_enabled or not usernames:
            return
        
        request_msg = {
            'type': 'key_request',
            'usernames': usernames
        }
        self.send_message(request_msg)
    
    def send_encrypted_message(self, plaintext: str):
        """Encrypt and send a message to all peers."""
        if not self.e2e_enabled:
            # Fallback to plaintext
            self.send_message({
                'type': 'message',
                'content': plaintext
            })
            return
        
        # Check if key exchange is initialized
        if not self.keys_initialized:
            print("\n⚠ Key exchange not yet complete. Please wait a moment and try again.")
            print("  Waiting for peer public keys from server...")
            return
        
        # Get list of recipients (all peers with known public keys)
        with self.peer_keys_lock:
            if not self.peer_public_keys:
                print("\n⚠ No other users in the chat yet.")
                print("  Your message will be sent when someone joins.")
                return
            
            recipients = self.peer_public_keys.copy()
        
        try:
            # Encrypt message for each recipient
            encrypted_payloads = {}
            for username, public_key_pem_str in recipients.items():
                public_key_pem = public_key_pem_str.encode('utf-8')
                encrypted_data = self.encryptor.encrypt_message(plaintext, public_key_pem)
                encrypted_payloads[username] = encrypted_data
            
            # Create message signature (sign the plaintext)
            signature = None
            if config.SIGNATURE_ENABLED:
                signature = self.encryptor.sign_message(plaintext, self.private_key_pem)
            
            # Create encrypted message
            encrypted_msg = {
                'type': 'encrypted_message',
                'sender': self.username,
                'recipients': list(recipients.keys()),
                'encrypted_payloads': encrypted_payloads,
                'signature': signature,
                'timestamp': datetime.now().isoformat()
            }
            
            self.send_message(encrypted_msg)
            
        except Exception as e:
            print(f"\n✗ Encryption failed: {e}", file=sys.stderr)
    
    def receive_encrypted_message(self, message: dict):
        """Decrypt and display an encrypted message."""
        sender = message.get('sender', 'Unknown')
        encrypted_payloads = message.get('encrypted_payloads', {})
        signature = message.get('signature')
        timestamp = message.get('timestamp', '')
        
        # Check if message is for us
        if self.username not in encrypted_payloads:
            return  # Message not for us
        
        try:
            # Decrypt message
            our_encrypted_data = encrypted_payloads[self.username]
            plaintext = self.encryptor.decrypt_message(our_encrypted_data, self.private_key_pem)
            
            # Verify signature if enabled
            signature_status = ""
            if config.SIGNATURE_ENABLED and signature:
                with self.peer_keys_lock:
                    sender_public_key = self.peer_public_keys.get(sender)
                
                if sender_public_key:
                    sender_public_key_pem = sender_public_key.encode('utf-8')
                    is_valid = self.encryptor.verify_signature(
                        plaintext, 
                        signature, 
                        sender_public_key_pem
                    )
                    signature_status = " ✓" if is_valid else " ✗INVALID SIGNATURE"
            
            # Display message
            try:
                dt = datetime.fromisoformat(timestamp)
                time_str = dt.strftime('%H:%M:%S')
            except:
                time_str = ''
            
            lock_emoji = "🔒"
            if time_str:
                print(f"\n[{time_str}] {lock_emoji} {sender}{signature_status}: {plaintext}")
            else:
                print(f"\n{lock_emoji} {sender}{signature_status}: {plaintext}")
            sys.stdout.flush()  # Force immediate display
            print(f"{self.username}> ", end='', flush=True)  # Re-print prompt
            
        except Exception as e:
            print(f"\n✗ Decryption failed for message from {sender}: {e}", file=sys.stderr)
            sys.stdout.flush()
            print(f"{self.username}> ", end='', flush=True)
    
    def send_message(self, message):
        """Send JSON message to server."""
        try:
            data = json.dumps(message).encode('utf-8')
            self.socket.sendall(data + b'\n')
        except Exception as e:
            print(f"\n✗ Error sending message: {e}", file=sys.stderr)
            self.running = False
    
    def receive_messages(self):
        """Receive and display messages from server (runs in separate thread)."""
        buffer = ""
        
        while self.running:
            try:
                data = self.socket.recv(config.BUFFER_SIZE)
                if not data:
                    print("\n✗ Connection closed by server")
                    self.running = False
                    break
                
                # Decode and split messages (newline-delimited JSON)
                buffer += data.decode('utf-8')
                
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    if line.strip():
                        try:
                            message = json.loads(line)
                            msg_type = message.get('type')
                            
                            # Handle different message types
                            if msg_type == 'key_sync':
                                # Receive all existing peer public keys at once
                                keys = message.get('keys', {})
                                with self.peer_keys_lock:
                                    self.peer_public_keys.update(keys)
                                    self.keys_initialized = True  # Mark as initialized
                                if keys:
                                    print(f"\n[E2E] Received key_sync with {len(keys)} public key(s)")
                                    for username in keys.keys():
                                        print(f"      - {username}")
                                else:
                                    # No existing keys, but still mark as initialized (we're first/only user)
                                    print("\n[E2E] Key exchange initialized (no other users yet)")
                            
                            elif msg_type == 'public_key':
                                # Receive a single new user's public key (broadcast)
                                username = message.get('username')
                                public_key = message.get('public_key')
                                if username and public_key:
                                    with self.peer_keys_lock:
                                        self.peer_public_keys[username] = public_key
                                        self.keys_initialized = True  # Mark as initialized
                                    print(f"\n[E2E] Received public key for new user: {username}")
                            
                            elif msg_type == 'key_removal':
                                # Remove a disconnected user's public key
                                username = message.get('username')
                                if username:
                                    with self.peer_keys_lock:
                                        if username in self.peer_public_keys:
                                            del self.peer_public_keys[username]
                                            print(f"\n[E2E] Removed public key for disconnected user: {username}")
                            
                            elif msg_type == 'key_response':
                                # Store peer public keys
                                keys = message.get('keys', {})
                                with self.peer_keys_lock:
                                    self.peer_public_keys.update(keys)
                                    if keys:
                                        self.keys_initialized = True
                                if keys:
                                    print(f"\n[E2E] Received {len(keys)} public key(s)")
                                    for username in keys.keys():
                                        print(f"      - {username}")
                            
                            elif msg_type == 'key_error':
                                # Handle key error messages
                                error_msg = message.get('message', 'Key request failed')
                                print(f"\n[E2E] ⚠ {error_msg}")
                            
                            elif msg_type == 'key_exchange_confirm':
                                # Key exchange confirmation (legacy)
                                pass  # Already printed in exchange_keys()
                            
                            elif msg_type == 'encrypted_message':
                                # Decrypt and display
                                self.receive_encrypted_message(message)
                            
                            elif msg_type == 'system':
                                # Display system messages
                                self.display_message(message)
                                # Note: No longer auto-requesting keys on join
                                # The key_sync and public_key broadcasts handle this
                            
                            else:
                                # Display other message types
                                self.display_message(message)
                        except json.JSONDecodeError:
                            pass
                
            except ConnectionResetError:
                print("\n✗ Connection reset by server")
                self.running = False
                break
            except Exception as e:
                if self.running:
                    print(f"\n✗ Error receiving message: {e}", file=sys.stderr)
                    self.running = False
                break
    
    def display_message(self, message):
        """Display received message in terminal."""
        msg_type = message.get('type', 'message')
        content = message.get('content', '')
        username = message.get('username', 'System')
        timestamp = message.get('timestamp', '')
        
        # Parse timestamp for display
        try:
            dt = datetime.fromisoformat(timestamp)
            time_str = dt.strftime('%H:%M:%S')
        except:
            time_str = ''
        
        # Format message based on type
        if msg_type == 'system':
            print(f"\n[SYSTEM] {content}")
            sys.stdout.flush()  # Force immediate display
        elif msg_type == 'message':
            if time_str:
                print(f"\n[{time_str}] {username}: {content}")
            else:
                print(f"\n{username}: {content}")
            sys.stdout.flush()  # Force immediate display
        
        # Re-print prompt
        print(f"{self.username}> ", end='', flush=True)
    
    def send_messages(self):
        """Send messages from user input (runs in main thread)."""
        print()
        print("Type your messages below. Press Ctrl+C to quit.")
        print("=" * 60)
        
        while self.running:
            try:
                # Get user input
                user_input = input(f"{self.username}> ")
                
                if not user_input.strip():
                    continue
                
                # Send encrypted message
                if self.e2e_enabled:
                    self.send_encrypted_message(user_input.strip())
                else:
                    # Create plaintext message
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
                print(f"\n✗ Error: {e}", file=sys.stderr)
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
        
        # Generate and exchange E2E encryption keys
        if self.e2e_enabled:
            self.generate_keys()
        
        # Send JOIN message with public key (if E2E enabled)
        join_msg = {
            'type': 'join',
            'username': self.username
        }
        
        # Include public key in JOIN message for immediate key exchange
        if self.e2e_enabled and self.public_key_pem:
            join_msg['public_key'] = self.public_key_pem.decode('utf-8')
            print("[E2E] Sending public key with JOIN message")
        
        self.send_message(join_msg)
        
        # No longer need separate exchange_keys() - it's done in JOIN
        # The server will send back a key_sync with all existing keys
        
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
    """Main entry point for chat client."""
    print("=" * 60)
    print("     Encrypted Dual-Stack Chat Client")
    print("     IPv4 + IPv6 Support")
    print("=" * 60)
    print()
    
    # Get connection details
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
        
        # Limit username length
        username = username[:config.USERNAME_MAX_LENGTH]
        
        print()
        
    except KeyboardInterrupt:
        print("\n\nCancelled.")
        return
    except ValueError:
        print("✗ Invalid port number", file=sys.stderr)
        return
    
    # Create and start client
    client = ChatClient(server, port, username, verify_cert=False)
    
    try:
        client.start()
    except KeyboardInterrupt:
        print("\n\nDisconnecting...")
    finally:
        client.stop()


if __name__ == '__main__':
    main()
