import os
import uuid
import time
import json
import socket
import threading
from hashlib import sha256
from typing import List

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type
# -------------------------------
# UTILIDADES CRIPTO
# -------------------------------
class CryptoUtils:
    @staticmethod
    def generate_ephemeral_dh_keys():
        """Genera par de claves X25519 efímeras (priv, pub) - Instantáneo, sin inicialización"""
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def dh_shared_secret(private_key, peer_public_key):
        """Calcula SharedSecret usando DH real: DH(priv_A, pub_B) = DH(priv_B, pub_A)"""
        shared_secret = private_key.exchange(peer_public_key)
        return shared_secret

    @staticmethod
    def serialize_dh_public_key(public_key):
        """Serializa clave pública X25519 a bytes para transmisión"""
        return public_key.public_bytes_raw()

    @staticmethod
    def deserialize_dh_public_key(public_key_bytes):
        """Deserializa clave pública X25519 desde bytes"""
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        return X25519PublicKey.from_public_bytes(public_key_bytes)

    @staticmethod
    def hkdf(shared_secret, info=b""):
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
        ).derive(shared_secret)

    @staticmethod
    def aes_gcm_encrypt(key, plaintext: str):
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
        return {"nonce": nonce.hex(), "ciphertext": ct.hex()}

    @staticmethod
    def aes_gcm_decrypt(key, enc_data):
        aesgcm = AESGCM(key)
        nonce = bytes.fromhex(enc_data["nonce"])
        ciphertext = bytes.fromhex(enc_data["ciphertext"])
        pt = aesgcm.decrypt(nonce, ciphertext, None)
        return pt.decode()


# -------------------------------
# STRUCTURAS DE DATOS
# -------------------------------
class VaultEntry:
    def __init__(self, site, user, password, state="activo", timestamp_mod=None):
        self.site = site
        self.user = user
        self.password = password
        self.state = state
        self.timestamp_mod = timestamp_mod if timestamp_mod is not None else int(time.time())

    def to_dict(self):
        return {
            "site": self.site,
            "user": self.user,
            "password": self.password,
            "state": self.state,
            "timestamp_mod": self.timestamp_mod
        }

class Vault:
    def __init__(self, device_id):
        self.device_id = device_id
        self.version = 0
        self.timestamp = int(time.time())
        self.entries: List[VaultEntry] = []

    def add_entry(self, entry: VaultEntry):
        self.entries.append(entry)
        self.version += 1
        self.timestamp = int(time.time())

    def to_json(self):
        return json.dumps({
            "device_id": self.device_id,
            "version": self.version,
            "timestamp": self.timestamp,
            "entries": [e.to_dict() for e in self.entries]
        })

    def hash(self):
        """Hash basado SOLO en version + entries (sin device_id) para consistencia entre dispositivos"""
        # Ordenar entries por (site, user) para garantizar hash determinista
        sorted_entries = sorted(
            [e.to_dict() for e in self.entries],
            key=lambda x: (x['site'], x['user'])
        )
        vault_content = json.dumps({
            "version": self.version,
            "entries": sorted_entries
        })
        return sha256(vault_content.encode()).hexdigest()
