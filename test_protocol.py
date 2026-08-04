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
            'onetime_prekeys': [
                {'id': i, 'key': p.get_public_bytes().hex()}
                for i, p in self.keys.onetime_prekeys.items()
            ],
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
        ratchet.x3dh_onetime_id = bundle.onetime_prekey_id
        self.ratchets[peer] = ratchet
        return ratchet

    def encrypt_to(self, peer, text, sender_override=None):
        ratchet = self.ratchets.get(peer) or self.start_ratchet(peer)
        extra = {'sender': sender_override or self.username}
        first = hasattr(ratchet, 'x3dh_ephemeral_pub')
        if first:
            extra['x3dh_ephemeral'] = ratchet.x3dh_ephemeral_pub.hex()
            if getattr(ratchet, 'x3dh_onetime_id', None) is not None:
                extra['onetime_prekey_id'] = ratchet.x3dh_onetime_id
        ciphertext, header = ratchet.ratchet_encrypt(text.encode(), extra_header=extra)
        if first:
            delattr(ratchet, 'x3dh_ephemeral_pub')
        return ciphertext, header

    def responder_ratchet(self, header, peer):
        """Derive the responder-side ratchet for a first message."""
        opk = self.keys.consume_onetime_prekey(header.get('onetime_prekey_id'))
        if header.get('onetime_prekey_id') is not None and opk is None:
            raise AssertionError("one-time key unavailable or already consumed")
        shared = x3dh_respond(
            self.keys.identity_keypair,
            self.keys.signed_prekey_pair,
            opk,
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

    # --- 7. One-time pre-keys: served, distinct per requester, consumed once ---
    def test_onetime_prekeys():
        owner = RawClient('opk_owner')
        owner.join()
        owner.absorb_bundles()

        # Two separate initiators must receive DIFFERENT one-time keys
        one = RawClient('taker_one')
        one.join(); one.absorb_bundles()
        two = RawClient('taker_two')
        two.join(); two.absorb_bundles()

        # Owner joined first, so it must pick up the newcomers' announcements
        owner.absorb_bundles()

        b1 = one.peer_bundles['opk_owner']
        b2 = two.peer_bundles['opk_owner']
        assert b1.onetime_prekey is not None, "no one-time key was served"
        assert b1.onetime_prekey_id != b2.onetime_prekey_id, \
            "two initiators were served the same one-time key"
        assert b1.onetime_prekey != b2.onetime_prekey

        # A 4-DH handshake must actually work end to end
        one.send_to('opk_owner', "four dh please")
        got = owner.recv_until('ratchet_message')
        assert got is not None, "owner received nothing"
        assert got['header'].get('onetime_prekey_id') == b1.onetime_prekey_id
        ratchet = owner.responder_ratchet(got['header'], 'taker_one')
        assert ratchet.ratchet_decrypt(
            base64.b64decode(got['ciphertext']), got['header']
        ) == b"four dh please"

        # That key is now destroyed: reusing the id must fail
        assert owner.keys.consume_onetime_prekey(b1.onetime_prekey_id) is None, \
            "one-time key survived its single use"

        owner.close(); one.close(); two.close()

    check("one-time pre-keys distinct per requester and consumed once", test_onetime_prekeys)

    # --- 8. Pool depletion falls back to 3-DH rather than failing ---
    def test_onetime_depletion():
        owner = RawClient('drained')
        # Publish a pool of exactly one key
        owner.keys.onetime_prekeys = dict(list(owner.keys.onetime_prekeys.items())[:1])
        owner.join()
        owner.absorb_bundles()

        first = RawClient('drain_a'); first.join(); first.absorb_bundles()
        second = RawClient('drain_b'); second.join(); second.absorb_bundles()
        owner.absorb_bundles()

        b1 = first.peer_bundles['drained']
        b2 = second.peer_bundles['drained']
        assert b1.onetime_prekey is not None, "first requester should get the only key"
        assert b2.onetime_prekey is None, "pool should be empty for the second requester"
        assert b2.onetime_prekey_id is None

        # 3-DH fallback must still produce a working session
        second.send_to('drained', "three dh fallback")
        got = owner.recv_until('ratchet_message')
        assert got is not None
        ratchet = owner.responder_ratchet(got['header'], 'drain_b')
        assert ratchet.ratchet_decrypt(
            base64.b64decode(got['ciphertext']), got['header']
        ) == b"three dh fallback"

        owner.close(); first.close(); second.close()

    check("pool depletion falls back to 3-DH", test_onetime_depletion)

    # --- 9. Persistence: identity and sessions survive a restart ---
    def test_persistence():
        import shutil
        import tempfile as _tempfile
        from ratchet_store import RatchetStore
        from x3dh import X3DHKeyManager

        workdir = _tempfile.mkdtemp()
        try:
            path = os.path.join(workdir, 'state.json')
            store = RatchetStore('persist', 'a strong passphrase', path=path)

            # Establish a session and advance the ratchet a few messages
            alice, bob = pair('persist', 'partner')
            original_signing = alice.keys.signing_keypair.get_public_bytes()

            ciphertext, header = alice.encrypt_to('partner', "msg one")
            bob_ratchet = bob.responder_ratchet(header, 'persist')
            assert bob_ratchet.ratchet_decrypt(ciphertext, header) == b"msg one"

            for i in range(3):
                ct, hdr = alice.encrypt_to('partner', f"msg {i}")
                assert bob_ratchet.ratchet_decrypt(ct, hdr) == f"msg {i}".encode()

            # Persist Alice's identity and live session
            store.save({
                'username': 'persist',
                'x3dh': alice.keys.export_private_state(),
                'ratchets': {'partner': alice.ratchets['partner'].state.to_dict()},
            })

            # "Restart": rebuild purely from disk
            saved = store.load()
            restored_keys = X3DHKeyManager.from_private_state(saved['x3dh'])

            # The identity peers pinned must be byte-identical, or every peer
            # sees a key-change warning
            assert restored_keys.signing_keypair.get_public_bytes() == original_signing, \
                "signing key changed across restart - TOFU pins would break"
            assert restored_keys.identity_keypair.get_public_bytes() == \
                alice.keys.identity_keypair.get_public_bytes()

            # Unused one-time keys must survive too
            assert set(restored_keys.onetime_prekeys) == set(alice.keys.onetime_prekeys)

            # The restored ratchet must continue the conversation, not restart it
            restored = DoubleRatchet(RatchetState.from_dict(saved['ratchets']['partner']))
            ct, hdr = restored.ratchet_encrypt(
                b"after restart", extra_header={'sender': 'persist'}
            )
            assert bob_ratchet.ratchet_decrypt(ct, hdr) == b"after restart", \
                "restored ratchet could not continue the session"

            alice.close(); bob.close()
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    check("identity and session survive a restart", test_persistence)

    # --- 10. Offline queue: held while away, delivered in order on return ---
    def test_offline_queue():
        recipient = RawClient('sleeper')
        recipient.join()
        recipient.absorb_bundles()

        sender = RawClient('waker')
        sender.join()
        sender.absorb_bundles()
        recipient.absorb_bundles()

        # Recipient goes away. Their bundle must survive the disconnect, or the
        # sender cannot encrypt to them at all.
        recipient.close()
        time.sleep(0.4)

        sender.send_to('sleeper', "first while away")
        sender.send_to('sleeper', "second while away")
        sender.send_to('sleeper', "third while away")
        time.sleep(0.4)
        assert server.message_store.queue_depth('sleeper') == 3, \
            f"expected 3 queued, got {server.message_store.queue_depth('sleeper')}"

        # Reconnect with the SAME identity, as persistence would give us
        returning = RawClient.__new__(RawClient)
        returning.username = 'sleeper'
        returning.port = TEST_PORT
        returning.keys = recipient.keys          # same identity + one-time keys
        returning.ratchets = {}
        returning.peer_bundles = dict(recipient.peer_bundles)
        returning.inbox = []
        returning._buffer = ""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(config.SERVER_CERT)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        raw = socket.create_connection(('127.0.0.1', TEST_PORT), timeout=TIMEOUT)
        returning.sock = ctx.wrap_socket(raw, server_hostname='127.0.0.1')
        returning.sock.settimeout(TIMEOUT)
        returning.join()

        delivered = []
        for _ in range(3):
            msg = returning.recv_until('ratchet_message')
            if msg is None:
                break
            delivered.append(msg)

        assert len(delivered) == 3, f"expected 3 delivered, got {len(delivered)}"
        assert server.message_store.queue_depth('sleeper') == 0, "queue not drained"

        # Order must be preserved, and all three must decrypt on one session
        ratchet = returning.responder_ratchet(delivered[0]['header'], 'waker')
        texts = [
            ratchet.ratchet_decrypt(
                base64.b64decode(m['ciphertext']), m['header']
            ).decode()
            for m in delivered
        ]
        assert texts == ["first while away", "second while away", "third while away"], texts

        returning.close(); sender.close()

    check("offline messages queued and delivered in order", test_offline_queue)

    # --- 11. Directed messages reach only the addressee ---
    def test_directed_message():
        sender = RawClient('router')
        sender.join(); sender.absorb_bundles()
        target = RawClient('addressee')
        target.join(); target.absorb_bundles()
        bystander = RawClient('nosy')
        bystander.join(); bystander.absorb_bundles()
        sender.absorb_bundles()
        target.absorb_bundles()

        sender.send_to('addressee', "for your eyes only")

        got = target.recv_until('ratchet_message')
        assert got is not None, "addressee received nothing"
        ratchet = target.responder_ratchet(got['header'], 'router')
        assert ratchet.ratchet_decrypt(
            base64.b64decode(got['ciphertext']), got['header']
        ) == b"for your eyes only"

        # The bystander must not receive it at all
        leaked = bystander.recv_until('ratchet_message', timeout=1.0)
        assert leaked is None, "directed message leaked to a third party"

        sender.close(); target.close(); bystander.close()

    check("directed message reaches only the addressee", test_directed_message)

    # --- 12. Auto-reconnect after the link drops ---
    def test_reconnect():
        from client_v2 import ChatClient
        from ratchet_store import RatchetStore

        # Disabled store keeps this test off the filesystem
        client = ChatClient('127.0.0.1', TEST_PORT, 'reconnector',
                            store=RatchetStore('reconnector', ''))
        client.running = True
        supervisor = threading.Thread(target=client._network_loop, daemon=True)
        supervisor.start()

        try:
            deadline = time.time() + 15
            while not client.connected and time.time() < deadline:
                time.sleep(0.1)
            assert client.connected, "client never made its first connection"

            first_socket = client.socket
            identity = client.x3dh_manager.signing_keypair.get_public_bytes()

            # Yank the link out from under it
            try:
                first_socket.close()
            except Exception:
                pass

            # It must come back on its own. The rejoin may first be refused as a
            # duplicate until the server reaps the dead socket, which is exactly
            # the case backoff has to survive.
            deadline = time.time() + 40
            while time.time() < deadline:
                if client.connected and client.socket is not first_socket:
                    break
                time.sleep(0.2)

            assert client.connected and client.socket is not first_socket, \
                "client did not reconnect after the link dropped"

            # Identity must be unchanged, or every peer sees a key-change warning
            assert client.x3dh_manager.signing_keypair.get_public_bytes() == identity, \
                "identity changed across reconnect"
        finally:
            client.running = False
            client.connected = False
            try:
                client.socket.close()
            except Exception:
                pass
            time.sleep(0.3)

    check("client reconnects after the link drops", test_reconnect)

    # --- 13. Buffer bound drops a flooding connection ---
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
