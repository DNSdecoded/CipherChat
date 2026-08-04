# -*- coding: utf-8 -*-
"""
Encrypted at-rest storage for ratchet and identity state.

Without this, every client restart regenerates the identity key and discards all
ratchet state. That is not merely inconvenient: peers pin the signing key via
TOFU, so a fresh identity on every launch looks exactly like a man-in-the-middle
attack, and users get trained to click through the warning.

Persisting long-lived secrets to disk trades some forward secrecy for usability.
The passphrase-derived key is what bounds that exposure, which is why an empty
passphrase disables the store entirely rather than writing plaintext.

File layout (outer JSON is cleartext; it holds only KDF parameters):

    {
      "version": 1,
      "kdf": {"name": "scrypt", "salt": "<hex>", "n": 16384, "r": 8, "p": 1},
      "blob": "<base64 of nonce||ciphertext||tag>"
    }

The decrypted blob is JSON:

    {
      "username": "alice",
      "x3dh": {...},              # X3DHKeyManager.export_private_state()
      "ratchets": {"bob": {...}}  # RatchetState.to_dict() per peer
    }
"""

import base64
import json
import os
import tempfile

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from crypto_utils import MessageEncryptor


# Scrypt cost parameters. n=2^14 keeps unlocking near-instant on a laptop while
# making offline guessing meaningfully expensive. Stored in the file so the
# parameters can be raised later without orphaning existing files.
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LENGTH = 32
SALT_LENGTH = 16

STORE_VERSION = 1


class RatchetStoreError(Exception):
    """Raised when a store exists but cannot be read (wrong passphrase, corrupt)."""


def _derive_key(passphrase: str, salt: bytes,
                n: int = SCRYPT_N, r: int = SCRYPT_R, p: int = SCRYPT_P) -> bytes:
    """
    Derive the file encryption key from a passphrase.

    Args:
        passphrase: User-supplied passphrase
        salt: Per-file random salt
        n, r, p: Scrypt cost parameters

    Returns:
        32-byte key
    """
    kdf = Scrypt(salt=salt, length=KEY_LENGTH, n=n, r=r, p=p)
    return kdf.derive(passphrase.encode('utf-8'))


class RatchetStore:
    """
    Passphrase-encrypted state file for one user.

    An empty passphrase means "do not persist": load() returns None and save() is
    a no-op, which preserves the original memory-only behaviour.
    """

    def __init__(self, username: str, passphrase: str, path: str = None):
        """
        Args:
            username: Owner, used to derive the default filename
            passphrase: Empty string disables persistence entirely
            path: Override the state file location
        """
        self.username = username
        self.passphrase = passphrase or ""
        self.path = path or f"ratchet_state_{username}.json"
        self._encryptor = MessageEncryptor()

    @property
    def enabled(self) -> bool:
        """True if this store will actually read and write a file."""
        return bool(self.passphrase)

    def exists(self) -> bool:
        """True if a state file is present on disk."""
        return self.enabled and os.path.exists(self.path)

    def load(self) -> dict:
        """
        Read and decrypt the stored state.

        Returns:
            The stored payload dict, or None if persistence is off or no file exists

        Raises:
            RatchetStoreError: wrong passphrase, corrupt file, or unknown version
        """
        if not self.exists():
            return None

        try:
            with open(self.path, 'r', encoding='utf-8') as f:
                envelope = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            raise RatchetStoreError(f"Could not read {self.path}: {e}")

        if envelope.get('version') != STORE_VERSION:
            raise RatchetStoreError(
                f"{self.path} has unsupported version {envelope.get('version')}"
            )

        try:
            kdf = envelope['kdf']
            key = _derive_key(
                self.passphrase,
                bytes.fromhex(kdf['salt']),
                kdf.get('n', SCRYPT_N),
                kdf.get('r', SCRYPT_R),
                kdf.get('p', SCRYPT_P),
            )
            blob = base64.b64decode(envelope['blob'])
        except (KeyError, ValueError, TypeError) as e:
            raise RatchetStoreError(f"{self.path} is malformed: {e}")

        try:
            plaintext = self._encryptor.aes_gcm_decrypt(blob, key)
        except Exception:
            # AES-GCM authentication covers both a wrong passphrase and tampering.
            # They are indistinguishable here, and should be: reporting which one
            # it was would confirm a guess to anyone probing the file.
            raise RatchetStoreError(
                "Could not decrypt state - wrong passphrase, or the file was modified."
            )

        try:
            return json.loads(plaintext.decode('utf-8'))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise RatchetStoreError(f"Decrypted state is not valid JSON: {e}")

    def save(self, payload: dict):
        """
        Encrypt and write the state, atomically.

        A fresh salt (and therefore a fresh key and nonce) is generated on every
        write, so no AES-GCM nonce is ever reused under a given key.

        Args:
            payload: JSON-serializable state to store
        """
        if not self.enabled:
            return

        salt = os.urandom(SALT_LENGTH)
        key = _derive_key(self.passphrase, salt)
        blob = self._encryptor.aes_gcm_encrypt(
            json.dumps(payload).encode('utf-8'), key
        )

        envelope = {
            'version': STORE_VERSION,
            'kdf': {
                'name': 'scrypt',
                'salt': salt.hex(),
                'n': SCRYPT_N,
                'r': SCRYPT_R,
                'p': SCRYPT_P,
            },
            'blob': base64.b64encode(blob).decode('ascii'),
        }

        directory = os.path.dirname(os.path.abspath(self.path))
        fd, temp_path = tempfile.mkstemp(dir=directory, prefix='.ratchet-', suffix='.tmp')
        try:
            os.chmod(temp_path, 0o600)  # no-op on Windows, matters on POSIX
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(envelope, f)
                f.flush()
                os.fsync(f.fileno())
            # Atomic replace: a crash mid-write must not leave a truncated file,
            # which would cost the user every session they have established.
            os.replace(temp_path, self.path)
        except Exception:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
            raise


if __name__ == "__main__":
    import shutil

    print("Testing RatchetStore...")
    workdir = tempfile.mkdtemp()
    path = os.path.join(workdir, "state.json")

    try:
        payload = {
            'username': 'alice',
            'x3dh': {'identity_private': 'aa' * 32},
            'ratchets': {'bob': {'message_number_send': 7}},
        }

        store = RatchetStore('alice', 'correct horse battery staple', path=path)
        assert store.enabled
        assert store.load() is None, "empty store should load as None"

        store.save(payload)
        print("[OK] State written")

        assert store.load() == payload
        print("[OK] Round-trip preserves payload")

        # The file must not contain the secret in the clear
        raw = open(path, 'r', encoding='utf-8').read()
        assert 'aa' * 32 not in raw, "private key leaked in cleartext!"
        assert 'bob' not in raw, "peer name leaked in cleartext!"
        print("[OK] Secrets are not readable in the file")

        # Wrong passphrase must fail, and must not say why
        try:
            RatchetStore('alice', 'wrong passphrase', path=path).load()
            raise AssertionError("wrong passphrase was accepted!")
        except RatchetStoreError as e:
            assert 'wrong passphrase, or the file was modified' in str(e)
        print("[OK] Wrong passphrase rejected")

        # Tampering must be detected
        envelope = json.load(open(path, encoding='utf-8'))
        blob = bytearray(base64.b64decode(envelope['blob']))
        blob[-1] ^= 0x01
        envelope['blob'] = base64.b64encode(bytes(blob)).decode()
        json.dump(envelope, open(path, 'w', encoding='utf-8'))
        try:
            store.load()
            raise AssertionError("tampered blob was accepted!")
        except RatchetStoreError:
            pass
        print("[OK] Tampered file rejected")

        # Each save must use a fresh salt, so keys and nonces never repeat
        store.save(payload)
        first = json.load(open(path, encoding='utf-8'))
        store.save(payload)
        second = json.load(open(path, encoding='utf-8'))
        assert first['kdf']['salt'] != second['kdf']['salt']
        assert first['blob'] != second['blob']
        print("[OK] Fresh salt per write")

        # Empty passphrase disables persistence
        none_path = os.path.join(workdir, 'none.json')
        disabled = RatchetStore('alice', '', path=none_path)
        assert not disabled.enabled
        disabled.save(payload)
        assert disabled.load() is None
        assert not os.path.exists(none_path)
        print("[OK] Empty passphrase persists nothing")

        print("\n[PASS] All RatchetStore tests passed!")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
