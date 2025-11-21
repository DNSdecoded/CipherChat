"""
Encrypted Dual-Stack Chat Server
Multi-client chat server with TLS/SSL encryption over IPv4 and IPv6.
"""

import socket
import ssl
import threading
import json
import logging
import sys
import select
from datetime import datetime

import config


# Configure logging
logging.basicConfig(
    format=config.LOG_FORMAT,
    level=getattr(logging, config.LOG_LEVEL),
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('server.log')
    ]
)
logger = logging.getLogger('ChatServer')


class ChatServer:
    """Encrypted chat server supporting multiple clients over IPv4 and IPv6."""
    
    PROTOCOL_VERSION = "2.0"  # Forward Secrecy protocol
    
    def __init__(self, port=config.SERVER_PORT, enable_ipv4=config.ENABLE_IPV4, enable_ipv6=config.ENABLE_IPV6):
        self.port = port
        self.enable_ipv4 = enable_ipv4
        self.enable_ipv6 = enable_ipv6
        self.clients = {}  # {connection: username}
        self.clients_lock = threading.Lock()
        self.running = False
        self.server_socket_ipv4 = None
        self.server_socket_ipv6 = None
        
        # Forward Secrecy: X3DH bundle registry
        self.client_bundles = {}  # {username: bundle_dict}
        self.bundles_lock = threading.Lock()
        
    def create_ssl_context(self):
        """Create and configure SSL context for secure connections."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        try:
            # Load server certificate and private key
            context.load_cert_chain(
                certfile=config.SERVER_CERT,
                keyfile=config.SERVER_KEY
            )
            logger.info(f"Loaded SSL certificates from {config.CERT_DIR}")
        except FileNotFoundError as e:
            logger.error(f"Certificate files not found: {e}")
            logger.error("Run 'python generate_certs.py' to create certificates")
            sys.exit(1)
        except ssl.SSLError as e:
            logger.error(f"SSL error loading certificates: {e}")
            sys.exit(1)
        
        return context
    
    def start(self):
        """Start the chat server and listen for connections."""
        logger.info("Starting Encrypted Dual-Stack Chat Server")
        logger.info("=" * 60)
        
        # Create SSL context
        ssl_context = self.create_ssl_context()
        
        # Create sockets for enabled protocols
        server_sockets = []
        
        # Create IPv4 socket
        if self.enable_ipv4:
            try:
                self.server_socket_ipv4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket_ipv4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_socket_ipv4.bind((config.SERVER_HOST_IPV4, self.port))
                self.server_socket_ipv4.listen(config.MAX_CLIENTS)
                server_sockets.append(self.server_socket_ipv4)
                logger.info(f"IPv4 server listening on {config.SERVER_HOST_IPV4}:{self.port}")
            except OSError as e:
                logger.warning(f"Failed to bind IPv4 socket: {e}")
                self.server_socket_ipv4 = None
        
        # Create IPv6 socket
        if self.enable_ipv6:
            try:
                self.server_socket_ipv6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                self.server_socket_ipv6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # Disable IPv4-mapped IPv6 addresses to avoid conflicts
                try:
                    self.server_socket_ipv6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                except (AttributeError, OSError):
                    pass  # Not all platforms support this
                self.server_socket_ipv6.bind((config.SERVER_HOST_IPV6, self.port))
                self.server_socket_ipv6.listen(config.MAX_CLIENTS)
                server_sockets.append(self.server_socket_ipv6)
                logger.info(f"IPv6 server listening on [{config.SERVER_HOST_IPV6}]:{self.port}")
            except OSError as e:
                logger.warning(f"Failed to bind IPv6 socket: {e}")
                self.server_socket_ipv6 = None
        
        # Check if at least one socket is available
        if not server_sockets:
            logger.error("Failed to bind to any address. Exiting.")
            sys.exit(1)
        
        logger.info(f"Maximum clients: {config.MAX_CLIENTS}")
        logger.info(f"TLS encryption: ENABLED (TLS 1.2+)")
        logger.info("=" * 60)
        logger.info("Waiting for client connections...")
        
        self.running = True
        
        # Accept client connections from both sockets
        try:
            while self.running:
                try:
                    # Use select to monitor all server sockets
                    readable, _, _ = select.select(server_sockets, [], [], 1.0)
                    
                    for server_socket in readable:
                        client_socket, address = server_socket.accept()
                        
                        # Determine protocol
                        protocol = "IPv4" if server_socket == self.server_socket_ipv4 else "IPv6"
                        
                        # Wrap socket with SSL
                        try:
                            secure_socket = ssl_context.wrap_socket(
                                client_socket,
                                server_side=True
                            )
                            
                            # Disable Nagle's algorithm for real-time message delivery
                            # This prevents buffering and ensures messages are sent immediately
                            secure_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                            
                            # Handle client in separate thread
                            client_thread = threading.Thread(
                                target=self.handle_client,
                                args=(secure_socket, address, protocol),
                                daemon=True
                            )
                            client_thread.start()
                            
                        except ssl.SSLError as e:
                            logger.warning(f"SSL handshake failed with {address} ({protocol}): {e}")
                            client_socket.close()
                        
                except KeyboardInterrupt:
                    logger.info("\nShutdown signal received")
                    break
                except Exception as e:
                    if self.running:
                        logger.error(f"Error accepting connection: {e}")
        
        finally:
            self.stop()
    
    def handle_client(self, client_socket, address, protocol="Unknown"):
        """Handle individual client connection."""
        username = None
        buffer = ""  # Buffer for accumulating incoming data
        
        try:
            logger.info(f"New {protocol} connection from {address}")
            
            # Send welcome message
            e2e_status = "with E2E encryption" if config.E2E_ENABLED else ""
            welcome_msg = {
                'type': 'system',
                'content': f'Welcome to Encrypted Chat {e2e_status}! Please send your username.',
                'timestamp': datetime.now().isoformat()
            }
            self.send_message(client_socket, welcome_msg)
            
            # Handle all messages from client with buffering
            while self.running:
                data = client_socket.recv(config.BUFFER_SIZE)
                if not data:
                    break
                
                # Add received data to buffer
                buffer += data.decode('utf-8')
                
                # Process all complete messages in buffer (newline-delimited)
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    if not line.strip():
                        continue
                    
                    try:
                        message = json.loads(line)
                        msg_type = message.get('type')
                        
                        # Handle JOIN message
                        if msg_type == 'join':
                            if username is None:  # Only process first JOIN
                                username = message.get('username', 'Anonymous')[:config.USERNAME_MAX_LENGTH]
                                bundle_dict = message.get('x3dh_bundle')  # Extract X3DH bundle
                                protocol_version = message.get('protocol_version', '1.0')
                                
                                # Version check
                                if protocol_version != self.PROTOCOL_VERSION:
                                    error_msg = {
                                        'type': 'error',
                                        'content': f'Please upgrade to client v{self.PROTOCOL_VERSION} (Forward Secrecy)'
                                    }
                                    self.send_message(client_socket, error_msg)
                                    logger.warning(f"Rejected client with version {protocol_version}")
                                    client_socket.close()
                                    return
                                
                                # Register client
                                with self.clients_lock:
                                    self.clients[client_socket] = username
                                
                                # Store X3DH bundle if provided
                                if bundle_dict and config.E2E_ENABLED:
                                    with self.bundles_lock:
                                        self.client_bundles[username] = bundle_dict
                                    logger.info(f"[E2E] Stored X3DH bundle for {username}")
                                
                                logger.info(f"User '{username}' joined from {address} (v{protocol_version})")
                                
                                # Send all existing bundles to the new user (bundle_sync)
                                if config.E2E_ENABLED:
                                    with self.bundles_lock:
                                        existing_bundles = {
                                            uname: bundle 
                                            for uname, bundle in self.client_bundles.items() 
                                            if uname != username
                                        }
                                    
                                    bundle_sync_msg = {
                                        'type': 'bundle_sync',
                                        'bundles': existing_bundles,
                                        'timestamp': datetime.now().isoformat()
                                    }
                                    self.send_message(client_socket, bundle_sync_msg)
                                    logger.info(f"[E2E] Sent bundle_sync with {len(existing_bundles)} bundle(s) to {username}")
                                
                                # Broadcast the new user's bundle to all existing clients
                                if bundle_dict and config.E2E_ENABLED:
                                    bundle_broadcast = {
                                        'type': 'key_bundle',
                                        'username': username,
                                        'bundle': bundle_dict,
                                        'timestamp': datetime.now().isoformat()
                                    }
                                    self.broadcast(bundle_broadcast, exclude=client_socket)
                                    logger.info(f"[E2E] Broadcast key_bundle for {username}")
                                
                                # Notify all clients about the new user
                                join_notification = {
                                    'type': 'system',
                                    'content': f'{username} joined the chat',
                                    'timestamp': datetime.now().isoformat()
                                }
                                self.broadcast(join_notification, exclude=client_socket)
                                
                                # Confirm to user
                                confirm_msg = {
                                    'type': 'system',
                                    'content': f'Welcome {username}! You are now connected.',
                                    'timestamp': datetime.now().isoformat()
                                }
                                self.send_message(client_socket, confirm_msg)
                        
                        # Handle RATCHET_MESSAGE (relay to recipient)
                        elif msg_type == 'ratchet_message':
                            if username:  # Only process if user has joined
                                recipient = message.get('recipient')
                                
                                # Find recipient socket
                                recipient_socket = None
                                with self.clients_lock:
                                    for sock, user in self.clients.items():
                                        if user == recipient:
                                            recipient_socket = sock
                                            break
                                
                                if recipient_socket:
                                    self.send_message(recipient_socket, message)
                                    logger.debug(f"Relayed ratchet message: {username} -> {recipient}")
                                else:
                                    logger.warning(f"Recipient {recipient} not online for message from {username}")
                            
                        # Handle ENCRYPTED_MESSAGE (legacy, for compatibility)
                        elif msg_type == 'encrypted_message':
                            if username:  # Only process if user has joined
                                # Route encrypted message (server cannot decrypt)
                                message['sender'] = username
                                message['timestamp'] = datetime.now().isoformat()
                                logger.info(f"[E2E] Routing encrypted message from {username}")
                                self.broadcast(message, exclude=client_socket)
                            
                        # Handle plaintext MESSAGE
                        elif msg_type == 'message':
                            if username:  # Only process if user has joined
                                # Legacy plaintext message (if E2E disabled)
                                message['username'] = username
                                message['timestamp'] = datetime.now().isoformat()
                                content = message.get('content', '')[:config.MAX_MESSAGE_LENGTH]
                                logger.info(f"[{username}]: {content}")
                                self.broadcast(message)
                        
                    except json.JSONDecodeError:
                        logger.warning(f"Invalid JSON message from {username or address}: {line[:100]}")
                    except Exception as e:
                        logger.error(f"Error processing message from {username or address}: {e}")
        
        except ConnectionResetError:
            logger.info(f"Connection reset by {username or address}")
        except Exception as e:
            logger.error(f"Error handling client {username or address}: {e}")
        
        finally:
            # Cleanup
            with self.clients_lock:
                if client_socket in self.clients:
                    username = self.clients.pop(client_socket)
            
            if username:
                logger.info(f"User '{username}' disconnected")
                
                # Remove user's X3DH bundle from server registry
                bundle_removed = False
                if config.E2E_ENABLED:
                    with self.bundles_lock:
                        if username in self.client_bundles:
                            del self.client_bundles[username]
                            bundle_removed = True
                            logger.info(f"[E2E] Removed X3DH bundle for {username}")
                
                # Notify other clients that user left
                leave_msg = {
                    'type': 'system',
                    'content': f'{username} left the chat',
                    'timestamp': datetime.now().isoformat()
                }
                self.broadcast(leave_msg)
                
                # Notify other clients to remove this user's bundle
                if bundle_removed:
                    bundle_removal_msg = {
                        'type': 'bundle_removal',
                        'username': username,
                        'timestamp': datetime.now().isoformat()
                    }
                    self.broadcast(bundle_removal_msg)
                    logger.info(f"[E2E] Broadcast bundle_removal for {username}")
            
            try:
                client_socket.close()
            except:
                pass
    
    def send_message(self, client_socket, message):
        """Send JSON message to a specific client."""
        try:
            data = json.dumps(message).encode('utf-8')
            client_socket.sendall(data + b'\n')
        except Exception as e:
            logger.error(f"Error sending message: {e}")
    
    def broadcast(self, message, exclude=None):
        """Broadcast message to all connected clients."""
        with self.clients_lock:
            dead_sockets = []
            
            for client_socket in self.clients.keys():
                if client_socket == exclude:
                    continue
                
                try:
                    self.send_message(client_socket, message)
                except Exception as e:
                    logger.error(f"Error broadcasting to client: {e}")
                    dead_sockets.append(client_socket)
            
            # Clean up dead connections
            for socket in dead_sockets:
                if socket in self.clients:
                    username = self.clients.pop(socket)
                    logger.warning(f"Removed dead connection: {username}")
                    
                    # Also remove their public key
                    if config.E2E_ENABLED:
                        with self.public_keys_lock:
                            if username in self.client_public_keys:
                                del self.client_public_keys[username]
                                logger.info(f"[E2E] Removed public key for disconnected user: {username}")
    
    def handle_key_exchange(self, username: str, message: dict):
        """Handle public key exchange from client."""
        public_key = message.get('public_key')
        if public_key:
            with self.public_keys_lock:
                self.client_public_keys[username] = public_key
            logger.info(f"[E2E] Stored public key for {username}")
            
            # Notify user
            confirm_msg = {
                'type': 'key_exchange_confirm',
                'content': 'Public key registered successfully',
                'timestamp': datetime.now().isoformat()
            }
            
            # Find client socket by username
            client_socket = None
            with self.clients_lock:
                for sock, uname in self.clients.items():
                    if uname == username:
                        client_socket = sock
                        break
            
            if client_socket:
                self.send_message(client_socket, confirm_msg)
                
                # Automatically send all OTHER users' public keys to this new user
                with self.public_keys_lock:
                    other_keys = {
                        uname: key 
                        for uname, key in self.client_public_keys.items() 
                        if uname != username  # Exclude their own key
                    }
                
                if other_keys:
                    keys_response = {
                        'type': 'key_response',
                        'keys': other_keys,
                        'timestamp': datetime.now().isoformat()
                    }
                    self.send_message(client_socket, keys_response)
                    logger.info(f"[E2E] Auto-sent {len(other_keys)} public key(s) to {username}")
    
    def handle_key_request(self, client_socket, message: dict):
        """Handle request for other clients' public keys."""
        # Support both single user request and multiple users request
        requested_username = message.get('username')  # Single user
        requested_usernames = message.get('usernames', [])  # Multiple users
        
        # Normalize to list
        if requested_username:
            requested_usernames = [requested_username]
        
        if not requested_usernames:
            logger.warning("[E2E] Key request received with no usernames")
            return
        
        keys = {}
        missing = []
        
        with self.public_keys_lock:
            for username in requested_usernames:
                if username in self.client_public_keys:
                    keys[username] = self.client_public_keys[username]
                else:
                    missing.append(username)
        
        # Send available keys
        if keys:
            response = {
                'type': 'key_response',
                'keys': keys,
                'timestamp': datetime.now().isoformat()
            }
            self.send_message(client_socket, response)
            logger.info(f"[E2E] Sent {len(keys)} public key(s) to client")
        
        # Send error for missing keys
        if missing:
            error_response = {
                'type': 'key_error',
                'missing_users': missing,
                'message': f'Public keys not available for: {", ".join(missing)}',
                'timestamp': datetime.now().isoformat()
            }
            self.send_message(client_socket, error_response)
            logger.warning(f"[E2E] Requested keys not available for: {missing}")
    
    def get_all_usernames(self) -> list:
        """Get list of all connected usernames."""
        with self.clients_lock:
            return list(self.clients.values())
    
    def get_all_public_keys(self) -> dict:
        """Get all client public keys."""
        with self.public_keys_lock:
            return self.client_public_keys.copy()
    
    def stop(self):
        """Stop the server and cleanup resources."""
        logger.info("Stopping server...")
        self.running = False
        
        # Close all client connections
        with self.clients_lock:
            for client_socket in list(self.clients.keys()):
                try:
                    client_socket.close()
                except:
                    pass
            self.clients.clear()
        
        # Close server sockets
        if self.server_socket_ipv4:
            try:
                self.server_socket_ipv4.close()
            except:
                pass
        
        if self.server_socket_ipv6:
            try:
                self.server_socket_ipv6.close()
            except:
                pass
        
        logger.info("Server stopped")


def main():
    """Main entry point for the chat server."""
    print("=" * 60)
    print("     Encrypted Dual-Stack Chat Server")
    print("     IPv4 + IPv6 Support")
    print("=" * 60)
    print()
    
    server = ChatServer()
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n\nShutting down...")
    finally:
        server.stop()


if __name__ == '__main__':
    main()
