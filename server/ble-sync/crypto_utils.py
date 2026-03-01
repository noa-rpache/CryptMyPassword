"""
ECDH session-key encryption: X25519 + HKDF-SHA256 + AES-256-GCM.
Requires: pip install cryptography

No pre-shared or persistent keys are needed.
The server generates a fresh X25519 keypair on every startup, publishes the
public half via a BLE GATT characteristic, and the client derives the same
AES session key on the fly using its own ephemeral keypair.

Wire format produced by encrypt_payload():
  [32 bytes: client ephemeral public key]
  [12 bytes: AES-GCM nonce]
  [ N bytes: ciphertext + 16-byte GCM tag]
"""
import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
)


# ─── Key Generation ───────────────────────────────────────────────────────────

def generate_keypair() -> tuple[bytes, bytes]:
    """Return (private_key_raw_bytes, public_key_raw_bytes) — both 32 bytes."""
    priv = X25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_bytes  = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv_bytes, pub_bytes


# ─── HKDF Key Derivation ─────────────────────────────────────────────────────

def _derive_aes_key(shared_secret: bytes, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from a DH shared secret via HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        info=b"ble-password-vault-v1",
    )
    return hkdf.derive(shared_secret)


# ─── Encrypt (Client side) ────────────────────────────────────────────────────

def encrypt_payload(plaintext: bytes, server_eph_pub_bytes: bytes) -> bytes:
    """
    Encrypt *plaintext* using an ECDH-derived session key.

    Steps:
      1. Generate a client-side ephemeral X25519 keypair.
      2. Compute DH shared secret with the server's ephemeral public key.
      3. Derive a 256-bit AES key: HKDF(shared, salt=cli_pub‖srv_pub).
      4. Encrypt with AES-256-GCM (random 12-byte nonce).
      5. Serialise: cli_pub(32) | nonce(12) | ciphertext+tag.

    Args:
        plaintext: raw bytes to encrypt.
        server_eph_pub_bytes: 32-byte X25519 public key read from the server's
                              PUBKEY GATT characteristic.
    """
    # 1. Client ephemeral keypair
    cli_priv_bytes, cli_pub_bytes = generate_keypair()

    # 2. DH shared secret
    cli_priv = X25519PrivateKey.from_private_bytes(cli_priv_bytes)
    srv_pub  = X25519PublicKey.from_public_bytes(server_eph_pub_bytes)
    shared   = cli_priv.exchange(srv_pub)

    # 3. Derive AES key — salt binds both public keys for domain separation
    aes_key = _derive_aes_key(shared, salt=cli_pub_bytes + server_eph_pub_bytes)

    # 4. Encrypt
    nonce      = os.urandom(12)
    aesgcm     = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=cli_pub_bytes)

    # 5. Serialise: cli_pub | nonce | ciphertext+tag
    return cli_pub_bytes + nonce + ciphertext


# ─── Decrypt (Server side) ────────────────────────────────────────────────────

def decrypt_payload(data: bytes, server_eph_priv_bytes: bytes) -> bytes:
    """
    Decrypt a payload produced by *encrypt_payload*.

    The server's ephemeral private key is held in memory only (never written to
    disk), so no pre-shared key file is required.

    Raises:
        ValueError: if the GCM tag verification fails (tampered / MitM data).
    """
    # 1. Unpack fixed-size fields
    cli_pub_bytes = data[:32]
    nonce         = data[32:44]
    ciphertext    = data[44:]

    # 2. DH shared secret
    srv_priv = X25519PrivateKey.from_private_bytes(server_eph_priv_bytes)
    cli_pub  = X25519PublicKey.from_public_bytes(cli_pub_bytes)
    shared   = srv_priv.exchange(cli_pub)

    # 3. Derive AES key — same salt as the client used
    srv_pub_bytes = srv_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    aes_key = _derive_aes_key(shared, salt=cli_pub_bytes + srv_pub_bytes)

    # 4. Decrypt + verify GCM tag
    aesgcm = AESGCM(aes_key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, associated_data=cli_pub_bytes)
    except Exception as exc:
        raise ValueError("GCM authentication failed — data may be tampered") from exc
