# -*- coding: utf-8 -*-
"""
Pure Python Self-Signed Certificate Generator
Alternative certificate generator using Python's cryptography library.
Use this if OpenSSL is not available in PATH.
"""

import os
import sys

# Configure stdout for UTF-8 on Windows
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

from datetime import datetime, timedelta, timezone
import ipaddress

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

import config


def generate_certificates_python():
    """Generate self-signed SSL certificates using Python cryptography library."""
    
    if not CRYPTO_AVAILABLE:
        print("✗ cryptography library not installed", file=sys.stderr)
        print("\nPlease install it with:", file=sys.stderr)
        print("  pip install cryptography", file=sys.stderr)
        sys.exit(1)
    
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
    
    print("Generating self-signed certificates using Python...")
    print("=" * 60)
    
    # Generate private key
    print(f"Generating private key: {config.SERVER_KEY}")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Write private key to file
    with open(config.SERVER_KEY, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Generate certificate
    print(f"Generating certificate: {config.SERVER_CERT}")
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"EncryptedChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(u"localhost"),
            x509.IPAddress(ipaddress.IPv6Address(u"::1")),
            x509.IPAddress(ipaddress.IPv4Address(u"127.0.0.1")),
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    # Write certificate to file
    with open(config.SERVER_CERT, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print("=" * 60)
    print("✓ Certificates generated successfully!")
    print(f"  Private Key: {config.SERVER_KEY}")
    print(f"  Certificate: {config.SERVER_CERT}")
    print(f"  Valid for: 365 days from {datetime.now().strftime('%Y-%m-%d')}")
    print("=" * 60)


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
    print("Encrypted IPv6 Chat - Python Certificate Generator")
    print("=" * 60)
    generate_certificates_python()
    print()
    verify_certificates()
