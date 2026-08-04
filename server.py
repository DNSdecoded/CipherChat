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
    
    PROTOCOL_VERSION = "3.0"  # Ed25519-signed bundles + AEAD-bound headers

    # Cap on unparsed input held per connection. MAX_MESSAGE_LENGTH is not the
    # right bound here because key bundles are far larger than a chat line.
    # Without this a client that never sends a newline grows the buffer forever.
    MAX_BUFFER_SIZE = 64 * 1024

    def __init__(self, port=config.SERVER_PORT, enable_ipv4=config.ENABLE_IPV4, enable_ipv6=config.ENABLE_IPV6):
        self.port = port
        self.enable_ipv4 = enable_ipv4
        self.enable_ipv6 = enable_ipv6
        self.clients = {}  # {connection: username}
        self.running = False
        self.server_socket_ipv4 = None
        self.server_socket_ipv6 = None

        # Forward Secrecy: X3DH bundle registry
        self.client_bundles = {}  # {username: bundle_dict}

        # One lock guards both `clients` and `client_bundles`. They are updated
        # together on join and leave, and broadcast() needs the client list, so
        # two locks would have to nest — and broadcast-under-lock would deadlock.
        # Never hold this across a socket send; snapshot, release, then send.
        self.state_lock = threading.Lock()
        
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

                # Refuse to accumulate unbounded input from a client that never
                # sends a delimiter — otherwise this grows until the host OOMs.
                if len(buffer) > self.MAX_BUFFER_SIZE:
                    logger.warning(
                        f"Buffer limit exceeded by {username or address}; dropping connection"
                    )
                    break

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
                                
                                # Register client and publish the bundle in one
                                # critical section, so a concurrent join cannot
                                # observe a half-registered user. No sends here.
                                existing_bundles = {}
                                with self.state_lock:
                                    if username in self.clients.values():
                                        duplicate = True
                                    else:
                                        duplicate = False
                                        self.clients[client_socket] = username
                                        if bundle_dict and config.E2E_ENABLED:
                                            self.client_bundles[username] = bundle_dict
                                        if config.E2E_ENABLED:
                                            existing_bundles = {
                                                uname: bundle
                                                for uname, bundle in self.client_bundles.items()
                                                if uname != username
                                            }

                                # A duplicate name would overwrite the original's
                                # bundle and silently capture traffic meant for them.
                                if duplicate:
                                    self.send_message(client_socket, {
                                        'type': 'error',
                                        'content': f"Username '{username}' is already taken.",
                                        'timestamp': datetime.now().isoformat()
                                    })
                                    logger.warning(f"Rejected duplicate username '{username}' from {address}")
                                    return

                                if bundle_dict and config.E2E_ENABLED:
                                    logger.info(f"[E2E] Stored X3DH bundle for {username}")

                                logger.info(f"User '{username}' joined from {address} (v{protocol_version})")

                                # Send all existing bundles to the new user (bundle_sync)
                                if config.E2E_ENABLED:
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

                                # Never trust the client's own claim of who it is.
                                # The header inside the ciphertext is AEAD-bound
                                # and is what the recipient actually verifies;
                                # this keeps the envelope consistent with it.
                                message['sender'] = username

                                # Find recipient socket
                                recipient_socket = None
                                with self.state_lock:
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
                                message['content'] = content
                                # Never log message bodies. This path is plaintext
                                # by definition, so the content would otherwise be
                                # written to server.log permanently.
                                logger.info(f"[{username}] plaintext message ({len(content)} chars)")
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
            # Cleanup. Key off what was actually registered, NOT the local
            # `username` — a rejected join (duplicate name, bad version) sets
            # that variable without ever registering, and tearing down on it
            # would evict the legitimate holder of the name.
            departed = None
            bundle_removed = False
            with self.state_lock:
                if client_socket in self.clients:
                    departed = self.clients.pop(client_socket)
                    if config.E2E_ENABLED and departed in self.client_bundles:
                        del self.client_bundles[departed]
                        bundle_removed = True

            if departed:
                username = departed
                logger.info(f"User '{username}' disconnected")
                if bundle_removed:
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
        # Snapshot under the lock, then send outside it. sendall() can block on a
        # slow client, and holding the lock across that would stall every join,
        # leave, and relay in the server.
        with self.state_lock:
            targets = [sock for sock in self.clients if sock != exclude]

        for client_socket in targets:
            self.send_message(client_socket, message)
        # Dead connections are reaped by handle_client's finally block, which also
        # drops the user's X3DH bundle and notifies the remaining peers.
    
    def get_all_usernames(self) -> list:
        """Get list of all connected usernames."""
        with self.state_lock:
            return list(self.clients.values())

    def stop(self):
        """Stop the server and cleanup resources."""
        logger.info("Stopping server...")
        self.running = False
        
        # Close all client connections
        with self.state_lock:
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
