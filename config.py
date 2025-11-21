"""
Configuration Management for Encrypted Dual-Stack (IPv4/IPv6) Chat System
Centralizes all configuration parameters for server and client.
"""

import os

# Dual-Stack Configuration
ENABLE_IPV4 = True   # Enable IPv4 support
ENABLE_IPV6 = True   # Enable IPv6 support

# Server Configuration
SERVER_HOST_IPV4 = '0.0.0.0'  # IPv4 any address (listens on all interfaces)
SERVER_HOST_IPV6 = '::'        # IPv6 any address (listens on all interfaces)
SERVER_PORT = 5000
MAX_CLIENTS = 10
BUFFER_SIZE = 4096

# Certificate Configuration
CERT_DIR = 'certs'
SERVER_CERT = os.path.join(CERT_DIR, 'server.crt')
SERVER_KEY = os.path.join(CERT_DIR, 'server.key')

# TLS/SSL Configuration
TLS_VERSION = 'TLSv1_2'  # Minimum TLS version
CERT_REQUIRED = False  # For development, set to True for production

# Client Configuration
CLIENT_LOCALHOST_IPV4 = '127.0.0.1'  # IPv4 localhost
CLIENT_LOCALHOST_IPV6 = '::1'         # IPv6 localhost
CLIENT_TIMEOUT = 5.0

# Logging Configuration
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_LEVEL = 'INFO'

# Message Configuration
MAX_MESSAGE_LENGTH = 2048
USERNAME_MAX_LENGTH = 32

# End-to-End Encryption Configuration
E2E_ENABLED = True  # Enable end-to-end encryption
RSA_KEY_SIZE = 2048  # RSA key size (2048 or 4096)
AES_KEY_SIZE = 256   # AES key size in bits
SIGNATURE_ENABLED = True  # Enable digital signatures for message authentication
GROUP_ENCRYPTION_MODE = 'individual'  # 'individual' = encrypt for each recipient separately
KEY_PERSISTENCE = False  # False = keys stored in memory only (more secure)

