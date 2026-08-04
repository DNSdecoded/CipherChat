# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
pip install -r requirements.txt      # only dep: cryptography
python generate_certs.py             # TLS certs into certs/ (needs openssl on PATH)
python generate_certs_python.py      # pure-Python fallback if openssl missing
python server.py                     # listens :5000 on IPv4 + IPv6, logs to server.log
python client_v2.py                  # v2 client (X3DH + Double Ratchet) — the one to use
```

No test framework, no linter, no CI. Tests are `if __name__ == "__main__"` self-check blocks with
`assert`s in the crypto modules — run one module at a time:

```bash
python x25519_utils.py     # DH agreement, KDFs, Ed25519 sign/verify, safety number
python x3dh.py             # bundle gen + signature verification, initiate/respond
python double_ratchet.py   # round trips, AEAD header binding, tamper rejection
```

End-to-end protocol tests drive a real server and real clients over loopback TLS:

```bash
python test_protocol.py    # binds port 5555; needs certs/ to exist
```

Manual integration test = run `server.py` in one terminal and two `client_v2.py` in others.

## Architecture

Zero-knowledge relay. The server never holds a decryption key: it stores/forwards X3DH prekey
bundles and blindly relays `ratchet_message` payloads.

Wire protocol: newline-delimited JSON over TLS 1.2+. Both server and client accumulate a `buffer`
string and split on `\n` — a single `recv` may hold several messages or a partial one, so any new
send path must terminate with `b'\n'` and go through `send_message`. Both sides cap the unparsed
buffer at `MAX_BUFFER_SIZE` (64 KB) and drop the connection past it; `config.MAX_MESSAGE_LENGTH`
(2048) is the wrong bound here because key bundles are much larger than a chat line.

`server.py` uses a single `state_lock` for both `clients` and `client_bundles`. They change together
on join and leave, and `broadcast()` needs the client list — two locks would have to nest, and
broadcasting while holding them would deadlock. Never hold `state_lock` across a socket send:
`broadcast()` snapshots the target list, releases, then sends. Connection teardown in
`handle_client`'s `finally` must key off the username actually popped from `clients`, never the local
`username` variable — a rejected join (duplicate name, bad version) sets that variable without ever
registering, and tearing down on it evicts the legitimate holder of the name.

Message types (`type` field): `join` (carries `x3dh_bundle` + `protocol_version`), `bundle_sync`
(server sends all known peers' bundles to a joiner), `key_bundle` (broadcast of a new joiner's
bundle), `bundle_removal` (peer left), `ratchet_message` (unicast, relayed by recipient username),
`system`, `message` (plaintext fallback), `error`.

`PROTOCOL_VERSION = "3.0"` is asserted on both `server.py` and `client_v2.py`. The server hard-rejects
any other version at JOIN, which is why `client.py` (v1, RSA-hybrid, no forward secrecy) can no longer
connect — it is kept as reference only. Bumping the constant requires changing both files, and the
client's JOIN message must send `self.PROTOCOL_VERSION` rather than a literal.

Crypto layering, bottom up:
- `x25519_utils.py` — `X25519KeyPair` (raw 32-byte encode/decode + `dh()`), `Ed25519KeyPair`
  (sign/verify; `verify` is static and returns `False` rather than raising), `kdf_rk` (HKDF-SHA256,
  root key ratchet), `kdf_ck` (HMAC-SHA256 with `0x01`/`0x02`, chain ratchet), fingerprints,
  Signal-style safety numbers.
- `crypto_utils.py` — `MessageEncryptor.aes_gcm_encrypt/decrypt` is the AEAD used by the ratchet; wire
  format is `nonce(12) || ciphertext || tag(16)`. The rest of the file (`E2EKeyManager`, RSA-OAEP
  hybrid `encrypt_message`, PSS signing) belongs to the v1 client only.
- `x3dh.py` — `X3DHKeyManager` holds the X25519 identity, the Ed25519 signing key, and the signed
  prekey; `x3dh_initiate` / `x3dh_respond` do DH1..DH3 and HKDF into a 32-byte shared secret.
  `verify_prekey_bundle()` checks the Ed25519 signature over `prekey_signing_payload(identity_key,
  signed_prekey)`. That proves the bundle is self-consistent, **not** that it belongs to the right
  person — the TOFU pin is what establishes that. Both checks are required.
- `double_ratchet.py` — `RatchetState` (dataclass, serializable) + `DoubleRatchet.ratchet_encrypt/decrypt`,
  `_dh_ratchet`, `_skip_message_keys` (MAX_SKIP=1000, out-of-order handling). `_header_ad()`
  canonicalizes the header (`sort_keys`, no whitespace) into AES-GCM associated data, so the header
  cannot be edited in flight. `ratchet_decrypt` works on a `deepcopy` of the state and commits only
  after the tag verifies — a rejected forgery must not desynchronize the session.
- `client_v2.py` — session glue: per-peer `ratchet_states` and `peer_bundles` (each behind its own lock,
  `ratchet_lock` / `bundles_lock`), TOFU trust store, send/receive threads.

Session flow: client generates a bundle plus a one-time key pool and sends both with JOIN → server
stores them and cross-announces bundles, attaching a distinct one-time key per recipient → first send
to a peer calls `_initialize_ratchet_with_peer` (Alice role), which puts `x3dh_ephemeral` and
`onetime_prekey_id` in the first header → the receiver sees an unknown sender, reads those fields, and
calls `_initialize_ratchet_as_responder` (Bob role), which consumes that exact one-time key. Bob's ratchet is seeded from his *signed prekey pair*, so
Alice's `RatchetState.initialize_alice` must be given `bundle.signed_prekey` as the peer DH key — these
two must stay in agreement or the first decrypt fails.

The header must be complete **before** `ratchet_encrypt` is called — it is bound into the AEAD tag, so
adding a field afterwards (as the pre-3.0 code did with `x3dh_ephemeral`) makes every message fail to
decrypt. Pass extras via `extra_header=`; ratchet-owned fields are rejected. Nothing between sender and
receiver, including the server, may modify the header.

A "broadcast" message is actually N unicast ratchet messages, one per peer, encrypted separately.

Sender identity is enforced twice: the server overwrites the envelope `sender` with the authenticated
username, and the receiver checks the AEAD-bound header `sender` against the ratchet that decrypted the
message. The header check is the load-bearing one — the server-side overwrite is defence in depth.

TOFU lives client-side in `trusted_keys.json`, format `{"version": 2, "keys": {user: ed25519_hex}}`,
written `0600`. It pins the **Ed25519 signing key**, not the X25519 identity key. A v1 file (flat dict
of X25519 keys) is discarded, not migrated — migrating would pin a key that is never verified against.
A changed key prompts the user interactively; rejection drops that peer's bundle.

## Repo state worth knowing

- `certs/server.key`, `certs/server.crt`, and `__pycache__/*.pyc` were committed before `.gitignore`
  existed, so they are still tracked and ignore rules do not apply to them. Untrack with
  `git rm -r --cached certs __pycache__`. Treat the committed key as compromised — regenerate with
  `generate_certs.py` and never reuse it.
- One-time pre-keys are live. The client publishes a pool with JOIN; the **server** owns handout and
  attaches a distinct key per requester (`_serve_bundle_locked`, which must be called under
  `state_lock` — a racy pop would serve the same key twice). Depletion is not an error: X3DH falls
  back to 3-DH. The server asks for a top-up via `opk_replenish` below `ONETIME_PREKEY_LOW_WATER`,
  answered with `opk_upload`, and caps the pool at `MAX_ONETIME_PREKEYS`. Because each recipient needs
  a different key, `key_bundle` announcements are sent per-socket rather than through `broadcast()`.
  OPKs are deliberately not covered by the pre-key signature (as in Signal): substituting one is a
  denial of service, not a compromise, since DH1..DH3 still involve keys the attacker cannot compute.
- A replayed **first** message (the one carrying `x3dh_ephemeral`) still establishes a session at a
  client that holds no ratchet for that sender. AEAD binding prevents modification, not replay;
  closing this needs a seen-ephemeral cache. Known open gap.
- `config.py` keys `RSA_KEY_SIZE`, `SIGNATURE_ENABLED`, `GROUP_ENCRYPTION_MODE`, `KEY_PERSISTENCE`
  only affect the v1 client. `CERT_REQUIRED` is unused — v2 clients always pin and always verify.
- TLS is authenticated by **pinning** `certs/server.crt` via `load_verify_locations`, with
  `check_hostname = True`. Both generators emit SANs for `localhost`, `127.0.0.1`, `::1`; a cert
  without SANs will fail verification outright. Operators must distribute `server.crt` to clients
  out-of-band. `wrap_socket` must pass a `server_hostname` matching the address actually dialled —
  the IPv4 fallback path dials `127.0.0.1`, not the original hostname.
- Ratchet state is memory-only, so every client restart forces a fresh X3DH with every peer, and
  messages to offline users are dropped rather than queued.
- Client resolves `localhost` to IPv6 first and falls back to IPv4 only for the literal string
  `localhost`; other hosts get no fallback.
