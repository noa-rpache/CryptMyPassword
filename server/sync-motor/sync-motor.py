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

# -------------------------------
# CLIENTE P2P
# -------------------------------
class P2PClient:
    def __init__(self, device_id, master_password, listen_port=5000):
        self.device_id = device_id
        self.master_password = master_password
        self.vault = Vault(device_id)

        # Claves Ed25519
        self.device_priv = Ed25519PrivateKey.generate()
        self.device_pub = self.device_priv.public_key()

        # Mapa peers: device_id -> Ed25519PublicKey
        self.peers_pub_keys = {}

        # Pre-inicializar parámetros DH (2048-bit) - esto tarda ~10-20s en la primera llamada
        # Se hace aquí para evitar bloqueo durante la comunicación
# No requiere inicialización con X25519 (instantáneo)
        print(f"[{self.device_id}] ✅ Criptografía X25519 lista (instantáneo)")

        # Configuración P2P
        self.listen_port = listen_port
        self.server_thread = threading.Thread(target=self.listen_peer)
        self.server_thread.daemon = True
        self.server_thread.start()

    # -------------------
    # Anuncio periódico de presencia
    # -------------------
    def broadcast_announcement(self):
        """
        Aquí simulamos el anuncio en LAN; en producción podrías usar UDP broadcast.
        Devuelve dict que otros nodos deberían recibir.
        """
        announcement = {
            "device_id": self.device_id,
            "device_pub_bytes": self.device_pub.public_bytes_raw().hex(),
            "timestamp": int(time.time())
        }
        return announcement

    # -------------------
    # Recibir anuncio de otro peer
    # -------------------
    def receive_announcement(self, announcement):
        device_id = announcement["device_id"]
        pub_bytes = bytes.fromhex(announcement["device_pub_bytes"])
        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        self.peers_pub_keys[device_id] = pub_key

    # -------------------
    # Generación de contraseña (vacío)
    # -------------------
    def generate_password(self):
        return "PLACEHOLDER_PASSWORD"
    

    def add_new_password(self, site: str, user: str):
        """
        1️⃣ Genera la nueva contraseña
        2️⃣ Crea la entrada en el vault con timestamp_mod
        3️⃣ Actualiza metadata global (version + timestamp)
        4️⃣ Cifra el vault con VaultKey derivada de MasterPassword + salt
        5️⃣ Firma la metadata global
        """
        # 1️⃣ Generar contraseña
        password = self.generate_password()

        # 2️⃣ Crear entrada
        entry = VaultEntry(site, user, password)
        self.vault.entries.append(entry)        # se agrega la nueva entrada
        self.vault.version += 1                  # incrementa la versión global
        self.vault.timestamp = int(time.time())  # timestamp global actualizado

        # 3️⃣ Salt aleatorio (si no existe)
        if not hasattr(self, "vault_salt"):
            self.vault_salt = os.urandom(16)

        # 4️⃣ Derivar VaultKey usando Argon2id
        vault_key = hash_secret_raw(
            secret=self.master_password.encode(),
            salt=self.vault_salt,
            time_cost=2,
            memory_cost=2**16,
            parallelism=2,
            hash_len=32,
            type=Type.ID
        )

        # 5️⃣ Cifrar vault completo
        vault_json = self.vault.to_json()
        self.vault_encrypted = CryptoUtils.aes_gcm_encrypt(vault_key, vault_json)

        # 6️⃣ Metadata global y firma
        vault_hash = sha256(json.dumps(self.vault_encrypted).encode()).hexdigest()
        message = (str(self.vault.version) + vault_hash).encode()
        self.vault_signature = self.device_priv.sign(message)

        print(f"[{self.device_id}] Nueva contraseña agregada para {site}:{user}")
        return entry.password

    def delete_password(self, site: str, user: str):
        """
        Marca una contraseña como borrada (soft delete)
        1️⃣ Busca la entrada por site y user
        2️⃣ Cambia su estado de "activo" a "borrado"
        3️⃣ Actualiza timestamp_mod de esa entrada
        4️⃣ Actualiza metadata global (version + timestamp)
        5️⃣ Cifra el vault
        6️⃣ Firma la metadata global
        """
        # 1️⃣ Buscar la entrada
        entry = next((e for e in self.vault.entries if e.site == site and e.user == user), None)
        
        if not entry:
            print(f"[{self.device_id}] ❌ No se encontró contraseña para {site}:{user}")
            return False
        
        # 2️⃣ Cambiar estado a borrado
        entry.state = "borrado"
        entry.timestamp_mod = int(time.time())
        
        # 3️⃣ Actualizar metadata global
        self.vault.version += 1
        self.vault.timestamp = int(time.time())
        
        # 4️⃣ Salt aleatorio (si no existe)
        if not hasattr(self, "vault_salt"):
            self.vault_salt = os.urandom(16)
        
        # 5️⃣ Derivar VaultKey usando Argon2id
        vault_key = hash_secret_raw(
            secret=self.master_password.encode(),
            salt=self.vault_salt,
            time_cost=2,
            memory_cost=2**16,
            parallelism=2,
            hash_len=32,
            type=Type.ID
        )
        
        # 6️⃣ Cifrar vault completo
        vault_json = self.vault.to_json()
        self.vault_encrypted = CryptoUtils.aes_gcm_encrypt(vault_key, vault_json)
        
        # 7️⃣ Metadata global y firma
        vault_hash = sha256(json.dumps(self.vault_encrypted).encode()).hexdigest()
        message = (str(self.vault.version) + vault_hash).encode()
        self.vault_signature = self.device_priv.sign(message)
        
        print(f"[{self.device_id}] ✅ Contraseña marcada como borrada: {site}:{user}")
        return True