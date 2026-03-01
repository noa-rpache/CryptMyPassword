import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


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
