# 🔐 CipherChat — Secure End-to-End Encrypted Messenger (Python)

CipherChat is a professional-grade encrypted chat system featuring **Signal Protocol security** (X3DH + Double Ratchet), **TLS transport encryption**, and **dual IPv4/IPv6 support**. Messages are protected with **perfect forward secrecy**, **future secrecy**, and **zero-knowledge messaging** — ensuring that even the server cannot read user messages.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Security: Signal Protocol](https://img.shields.io/badge/Security-Signal%20Protocol-green.svg)

---

## ✨ Features

### 🔐 End-to-End Encryption (Signal Protocol)
- X3DH handshake for key exchange
- Double Ratchet for per-message forward secrecy
- X25519 ECDH key agreement
- AES-256-GCM authenticated encryption

### 🛡 MITM Protection
- TOFU (Trust-On-First-Use) key pinning
- Key fingerprints & safety numbers
- Key change warnings and verification prompts

### 🌐 Network & Transport Security
- TLS 1.2+ encrypted transport layer
- Dual IPv4/IPv6 support with fallback
- Real-time delivery (TCP_NODELAY)
- Zero-knowledge server design

### 💬 Chat Features
- Multi-user secure messaging
- Broadcast encrypted messages
- Identity verification guidance
- Presence updates (join/leave)

---

## 🚀 Quick Start

### 📌 Requirements
- Python **3.8 or higher**
- OpenSSL (recommended for certificate generation)

### 📦 Install Dependencies
```bash
pip install -r requirements.txt
```

### 🔑 Generate TLS Certificates
```bash
python generate_certs.py
```

### 🖥 Start the Server
```bash
python server.py
```

### 💬 Start a Client
```bash
python client_v2.py
```

Enter:
- **Server address:** `localhost` or IP
- **Port:** `5000` (default)
- **Username:** any name

---

## 📖 Usage (Security Demonstration)

### 🔐 First Contact (TOFU Key Verification)
```
============================================================
[TOFU] First contact with Bob
============================================================
Identity fingerprint:
  SHA256:abcd1234...ef567890

Verify this fingerprint with Bob out-of-band (phone, in person)
============================================================
```

### ⚠️ Key Change Warning Example
```
⚠️  SECURITY WARNING: Bob's key changed!
Do NOT accept unless verified with Bob!
```

---

## 🧠 Architecture Overview

### 🔑 Key Exchange (X3DH)
```
Alice → Server → Bob (key bundle)
   │                   │
   └── Performs DH ops ┘
        → shared secret
```

### 🔄 Forward Secrecy (Double Ratchet)
- New keys on **every message**
- Past messages safe even if keys leak

---

## 📂 Project Structure
```
CipherChat/
 ├── server.py              # Secure chat server (TLS + bundle relay)
 ├── client_v2.py           # Signal client with TOFU + Ratchet
 ├── x3dh.py                # X3DH key agreement
 ├── double_ratchet.py      # Double Ratchet protocol
 ├── x25519_utils.py        # X25519 ECDH + fingerprints
 ├── crypto_utils.py        # AES-GCM encryption
 ├── generate_certs.py      # TLS certificate generator
 ├── config.py              # Configuration options
 └── certs/                 # 🔒 (ignored) Local TLS keys
```

---

## 🔒 Security Notes
### Protected
✔ Message content (E2E)  
✔ Transport layer (TLS)  
✔ Forward secrecy  
✔ MITM (with user verification)

### Not Protected
❌ Metadata (who talks to whom)  
❌ Timing/traffic analysis  
❌ First-contact MITM if user ignores fingerprint verification

---

## 📜 License
This project is licensed under the **MIT License**.  
See [`LICENSE`](LICENSE) for details.

---

### 🙌 Contributions
Contributions, audits, and improvements are welcome!  
Secure coding tips or vulnerability reports are especially appreciated.
