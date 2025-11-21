"""
Self-Signed Certificate Generator for Development
Creates RSA private key and X.509 certificate for TLS encryption.
"""

import os
import sys
from datetime import datetime, timedelta
import subprocess

import config


def generate_certificates():
    """Generate self-signed SSL certificates using OpenSSL."""
    
    # Create certs directory if it doesn't exist
    if not os.path.exists(config.CERT_DIR):
        os.makedirs(config.CERT_DIR)
        print(f"Created directory: {config.CERT_DIR}")
    
    # Check if certificates already exist
    if os.path.exists(config.SERVER_CERT) and os.path.exists(config.SERVER_KEY):
        response = input("Certificates already exist. Regenerate? (y/n): ")
        if response.lower() != 'y':
            print("Using existing certificates.")
            return
    
    print("Generating self-signed certificates...")
    print("=" * 60)
    
    # Generate private key and certificate using OpenSSL
    try:
        # Generate private key (2048-bit RSA)
        key_cmd = [
            'openssl', 'genrsa',
            '-out', config.SERVER_KEY,
            '2048'
        ]
        
        print(f"Generating private key: {config.SERVER_KEY}")
        subprocess.run(key_cmd, check=True, capture_output=True)
        
        # Generate self-signed certificate (valid for 365 days)
        cert_cmd = [
            'openssl', 'req',
            '-new', '-x509',
            '-key', config.SERVER_KEY,
            '-out', config.SERVER_CERT,
            '-days', '365',
            '-subj', '/C=US/ST=State/L=City/O=Organization/CN=localhost'
        ]
        
        print(f"Generating certificate: {config.SERVER_CERT}")
        subprocess.run(cert_cmd, check=True, capture_output=True)
        
        print("=" * 60)
        print("✓ Certificates generated successfully!")
        print(f"  Private Key: {config.SERVER_KEY}")
        print(f"  Certificate: {config.SERVER_CERT}")
        print(f"  Valid for: 365 days from {datetime.now().strftime('%Y-%m-%d')}")
        print("=" * 60)
        
    except subprocess.CalledProcessError as e:
        print(f"✗ Error generating certificates: {e}", file=sys.stderr)
        print("\nMake sure OpenSSL is installed and available in PATH.", file=sys.stderr)
        print("On Windows: Download from https://slproweb.com/products/Win32OpenSSL.html", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print("✗ OpenSSL not found in PATH.", file=sys.stderr)
        print("\nPlease install OpenSSL:", file=sys.stderr)
        print("  Windows: https://slproweb.com/products/Win32OpenSSL.html", file=sys.stderr)
        print("  Linux: sudo apt-get install openssl", file=sys.stderr)
        print("  macOS: brew install openssl", file=sys.stderr)
        sys.exit(1)


def verify_certificates():
    """Verify that certificate files exist and are readable."""
    
    if not os.path.exists(config.SERVER_CERT):
        print(f"✗ Certificate not found: {config.SERVER_CERT}", file=sys.stderr)
        return False
    
    if not os.path.exists(config.SERVER_KEY):
        print(f"✗ Private key not found: {config.SERVER_KEY}", file=sys.stderr)
        return False
    
    # Check file permissions (should be readable)
    try:
        with open(config.SERVER_CERT, 'r') as f:
            f.read(1)
        with open(config.SERVER_KEY, 'r') as f:
            f.read(1)
    except IOError as e:
        print(f"✗ Error reading certificate files: {e}", file=sys.stderr)
        return False
    
    print("✓ Certificates verified successfully!")
    return True


if __name__ == '__main__':
    print("Encrypted IPv6 Chat - Certificate Generator")
    print("=" * 60)
    generate_certificates()
    print()
    verify_certificates()
