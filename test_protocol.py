# -*- coding: utf-8 -*-
"""
End-to-end protocol tests for CipherChat.

Drives a real ChatServer over loopback TLS with real clients, asserting the
security properties the protocol claims. Plain asserts, no test framework — the
repo's existing convention.

Run:  python test_protocol.py
"""

import base64
import json
import os
import socket
import ssl
import sys
import threading
import time

# Configure stdout for UTF-8 on Windows
if sys.platform == 'win32':
    import codecs
    if hasattr(sys.stdout, 'buffer'):
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')

import config
from server import ChatServer
from x3dh import (
    X3DHKeyManager, X3DHPreKeyBundle, x3dh_initiate, x3dh_respond,
    verify_prekey_bundle,
)
from double_ratchet import RatchetState, DoubleRatchet
from x25519_utils import X25519KeyPair


TEST_PORT = 5555
TIMEOUT = 5.0


class RawClient:
    """
    Minimal protocol client: TLS + newline-delimited JSON, with the crypto driven
    explicitly so tests can misbehave on purpose.
    """

    def __init__(self, username, port=TEST_PORT):
        self.username = username
        self.port = port
        self.keys = X3DHKeyManager()
        self.ratchets = {}
        self.peer_bundles = {}
        self.inbox = []
        self._buffer = ""

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(config.SERVER_CERT)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True

        raw = socket.create_connection(('127.0.0.1', port), timeout=TIMEOUT)
        self.sock = ctx.wrap_socket(raw, server_hostname='127.0.0.1')
        self.sock.settimeout(TIMEOUT)

    def send(self, message):
        self.sock.sendall(json.dumps(message).encode() + b'\n')

    def join(self, protocol_version=None):
        self.send({
            'type': 'join',
            'username': self.username,
            'x3dh_bundle': self.keys.get_prekey_bundle().to_dict(),
            'protocol_version': protocol_version or ChatServer.PROTOCOL_VERSION,
        })

    def recv_until(self, msg_type, timeout=TIMEOUT):
        """Read messages until one of msg_type arrives, or time out (returns None)."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            for i, m in enumerate(self.inbox):
                if m.get('type') == msg_type:
                    return self.inbox.pop(i)
            try:
                self.sock.settimeout(max(0.1, deadline - time.time()))
                data = self.sock.recv(8192)
            except (socket.timeout, ssl.SSLError):
                continue
            except (ConnectionResetError, OSError):
                return None
            if not data:
                return None
            self._buffer += data.decode('utf-8', errors='replace')
            while '\n' in self._buffer:
                line, self._buffer = self._buffer.split('\n', 1)
                if line.strip():
                    try:
                        self.inbox.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return None

    def absorb_bundles(self, window=1.5):
        """Consume bundle_sync / key_bundle messages into peer_bundles."""
        deadline = time.time() + window
        while time.time() < deadline:
            msg = self.recv_until('bundle_sync', timeout=0.3)
            if msg is None:
                msg = self.recv_until('key_bundle', timeout=0.3)
            if msg is None:
                continue
            if msg['type'] == 'bundle_sync':
                for name, b in msg.get('bundles', {}).items():
                    self.peer_bundles[name] = X3DHPreKeyBundle.from_dict(b)
            else:
                self.peer_bundles[msg['username']] = X3DHPreKeyBundle.from_dict(msg['bundle'])

    def start_ratchet(self, peer):
        bundle = self.peer_bundles[peer]
        secret, ephemeral = x3dh_initiate(self.keys.identity_keypair, bundle)
        ratchet = DoubleRatchet(RatchetState.initialize_alice(secret, bundle.signed_prekey))
        ratchet.x3dh_ephemeral_pub = ephemeral
        self.ratchets[peer] = ratchet
        return ratchet

    def encrypt_to(self, peer, text, sender_override=None):
        ratchet = self.ratchets.get(peer) or self.start_ratchet(peer)
        extra = {'sender': sender_override or self.username}
        first = hasattr(ratchet, 'x3dh_ephemeral_pub')
        if first:
            extra['x3dh_ephemeral'] = ratchet.x3dh_ephemeral_pub.hex()
        ciphertext, header = ratchet.ratchet_encrypt(text.encode(), extra_header=extra)
        if first:
            delattr(ratchet, 'x3dh_ephemeral_pub')
        return ciphertext, header

    def responder_ratchet(self, header, peer):
        """Derive the responder-side ratchet for a first message."""
        shared = x3dh_respond(
            self.keys.identity_keypair,
            self.keys.signed_prekey_pair,
            None,
            self.peer_bundles[peer].identity_key,
            bytes.fromhex(header['x3dh_ephemeral']),
        )
        return DoubleRatchet(
            RatchetState.initialize_bob(shared, self.keys.signed_prekey_pair)
        )

    def send_to(self, peer, text, sender_override=None, header_mutator=None):
        ciphertext, header = self.encrypt_to(peer, text, sender_override)
        if header_mutator:
            header = header_mutator(header)
        self.send({
            'type': 'ratchet_message',
            'sender': self.username,
            'recipient': peer,
            'header': header,
            'ciphertext': base64.b64encode(ciphertext).decode(),
        })
        return header

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


def start_server():
    server = ChatServer(port=TEST_PORT, enable_ipv6=False)
    threading.Thread(target=server.start, daemon=True).start()
    for _ in range(50):
        try:
            socket.create_connection(('127.0.0.1', TEST_PORT), timeout=0.2).close()
            return server
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("server failed to start")


def pair(name_a, name_b):
    """Connect two clients and exchange bundles both ways."""
    a = RawClient(name_a)
    a.join()
    a.absorb_bundles()
    b = RawClient(name_b)
    b.join()
    b.absorb_bundles()
    a.absorb_bundles()
    return a, b


def main():
    if not os.path.exists(config.SERVER_CERT):
        print(f"[SKIP] {config.SERVER_CERT} missing - run generate_certs.py first")
        return 1

    server = start_server()
    print("[OK] Test server started on", TEST_PORT)
    failures = []

    def check(name, fn):
        try:
            fn()
            print(f"[PASS] {name}")
        except Exception as e:
            print(f"[FAIL] {name}: {type(e).__name__}: {e}")
            failures.append(name)

    # --- 1. Handshake, bundle verification, message delivery ---
    def test_handshake():
        alice, bob = pair('alice', 'bob')
        assert 'bob' in alice.peer_bundles, "alice never received bob's bundle"
        assert 'alice' in bob.peer_bundles, "bob never received alice's bundle"
        assert verify_prekey_bundle(alice.peer_bundles['bob'])

        alice.send_to('bob', "hello bob")
        relayed = bob.recv_until('ratchet_message')
        assert relayed is not None, "bob received no message"
        assert relayed['sender'] == 'alice'

        header = relayed['header']
        ciphertext = base64.b64decode(relayed['ciphertext'])
        ratchet = bob.responder_ratchet(header, 'alice')
        assert ratchet.ratchet_decrypt(ciphertext, header) == b"hello bob"
        alice.close(); bob.close()

    check("handshake + message delivery", test_handshake)

    # --- 2. Tampered dh_public must not decrypt ---
    def test_tampered_header():
        alice, bob = pair('anna', 'ben')
        ciphertext, header = alice.encrypt_to('ben', "confidential")
        ratchet = bob.responder_ratchet(header, 'anna')

        tampered = dict(header, dh_public=X25519KeyPair().get_public_bytes().hex())
        try:
            ratchet.ratchet_decrypt(ciphertext, tampered)
            raise AssertionError("tampered dh_public was accepted")
        except AssertionError:
            raise
        except Exception:
            pass

        # Untouched message must still decrypt: a rejected forgery must not
        # have corrupted the ratchet state.
        assert ratchet.ratchet_decrypt(ciphertext, header) == b"confidential"
        alice.close(); bob.close()

    check("tampered dh_public rejected, state intact", test_tampered_header)

    # --- 3. Forged header sender must not decrypt ---
    def test_forged_header_sender():
        alice, bob = pair('cara', 'dan')
        ciphertext, header = alice.encrypt_to('dan', "who am i")
        ratchet = bob.responder_ratchet(header, 'cara')
        forged = dict(header, sender='administrator')
        try:
            ratchet.ratchet_decrypt(ciphertext, forged)
            raise AssertionError("forged header sender was accepted")
        except AssertionError:
            raise
        except Exception:
            pass
        alice.close(); bob.close()

    check("forged header sender rejected", test_forged_header_sender)

    # --- 4. Server overwrites a forged envelope sender ---
    def test_envelope_sender_authority():
        carol, dave = pair('carol', 'dave')
        ciphertext, header = carol.encrypt_to('dave', "spoofed")
        carol.send({
            'type': 'ratchet_message',
            'sender': 'administrator',       # forged
            'recipient': 'dave',
            'header': header,
            'ciphertext': base64.b64encode(ciphertext).decode(),
        })
        got = dave.recv_until('ratchet_message')
        assert got is not None, "message was not relayed"
        assert got['sender'] == 'carol', f"server relayed forged sender: {got['sender']}"
        carol.close(); dave.close()

    check("server overwrites forged envelope sender", test_envelope_sender_authority)

    # --- 5. Duplicate username rejected, original survives ---
    def test_duplicate_username():
        first = RawClient('dupe')
        first.join()
        first.absorb_bundles()

        second = RawClient('dupe')
        second.join()
        err = second.recv_until('error')
        assert err is not None, "duplicate username was accepted"
        assert 'taken' in err.get('content', '').lower()

        third = RawClient('bystander')
        third.join()
        third.absorb_bundles()
        assert 'dupe' in third.peer_bundles, "original user was evicted by the duplicate"
        first.close(); second.close(); third.close()

    check("duplicate username rejected, original survives", test_duplicate_username)

    # --- 6. Protocol version gate ---
    def test_version_gate():
        old = RawClient('oldclient')
        old.join(protocol_version='2.0')
        err = old.recv_until('error')
        assert err is not None, "outdated protocol version was accepted"
        old.close()

    check("outdated protocol version rejected", test_version_gate)

    # --- 7. Buffer bound drops a flooding connection ---
    def test_buffer_bound():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(config.SERVER_CERT)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        raw = socket.create_connection(('127.0.0.1', TEST_PORT), timeout=TIMEOUT)
        sock = ctx.wrap_socket(raw, server_hostname='127.0.0.1')
        sock.settimeout(TIMEOUT)

        # No newline, ever. Server must cut us off rather than buffer forever.
        chunk = b'A' * 8192
        dropped = False
        try:
            for _ in range(64):  # 512 KB, well past the 64 KB cap
                sock.sendall(chunk)
                time.sleep(0.01)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError, OSError):
            dropped = True
        if not dropped:
            try:
                sock.settimeout(2.0)
                dropped = sock.recv(1) == b''
            except (ConnectionResetError, ssl.SSLError, OSError, socket.timeout):
                dropped = True
        assert dropped, "server accepted unbounded input without a delimiter"
        sock.close()

    check("unbounded buffer flood is dropped", test_buffer_bound)

    server.stop()
    print()
    if failures:
        print(f"[FAIL] {len(failures)} test(s) failed: {', '.join(failures)}")
        return 1
    print("[PASS] All protocol tests passed!")
    return 0


if __name__ == '__main__':
    sys.exit(main())
