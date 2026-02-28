import os
import uuid
import time
import json
import socket
import threading
from hashlib import sha256

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from argon2.low_level import hash_secret_raw, Type

from crypto_utils import CryptoUtils
from vault import Vault, VaultEntry

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
    
    # -------------------
    # Vault cifrado / descifrado
    # -------------------
    def encrypt_vault(self):
        vault_json = self.vault.to_json()
        key = sha256(self.master_password.encode()).digest()
        return CryptoUtils.aes_gcm_encrypt(key, vault_json)

    def decrypt_vault(self, vault_encrypted):
        key = sha256(self.master_password.encode()).digest()
        vault_json = CryptoUtils.aes_gcm_decrypt(key, vault_encrypted)
        vault_data = json.loads(vault_json)
        self.vault.version = vault_data["version"]
        self.vault.timestamp = vault_data["timestamp"]
        self.vault.entries = [VaultEntry(**e) for e in vault_data["entries"]]

    # -------------------
    # Token temporal
    # -------------------
    def generate_auth_token(self):
        token = str(uuid.uuid4())
        nonce = str(uuid.uuid4())
        expiration = int(time.time()) + 120
        message = (token + nonce).encode()
        signature = self.device_priv.sign(message)
        return {
            "token": token,
            "nonce": nonce,
            "expiration": expiration,
            "signature": signature.hex(),  # Convertir bytes a hex para JSON
            "device_id": self.device_id
        }

    def validate_auth_token(self, token_data):
        device_id = token_data["device_id"]
        if device_id not in self.peers_pub_keys:
            print(f"No se tiene la clave pública para {device_id}")
            return False
        pub_key = self.peers_pub_keys[device_id]
        if int(time.time()) > token_data["expiration"]:
            print("Token expirado")
            return False
        message = (token_data["token"] + token_data["nonce"]).encode()
        try:
            signature = bytes.fromhex(token_data["signature"])  # Convertir hex a bytes
            pub_key.verify(signature, message)
            print("Token válido")
            return True
        except Exception as e:
            print(f"Firma inválida: {e}")
            return False

# -------------------
    # Merge
    # -------------------

    def merge_vaults(self, peer_vault_encrypted):
        """Descifra vault del peer (cifrado con master_password) y hace merge"""
        key = sha256(self.master_password.encode()).digest()
        peer_vault_json = CryptoUtils.aes_gcm_decrypt(key, peer_vault_encrypted)
        peer_vault_data = json.loads(peer_vault_json)
        print("vault que recibimos para el clonado " + peer_vault_json)
        for entry in peer_vault_data["entries"]:
            match = next((e for e in self.vault.entries if e.site == entry["site"] and e.user == entry["user"]), None)
            if match:
                if entry["timestamp_mod"] > match.timestamp_mod:
                    match.password = entry["password"]
                    match.state = entry["state"]
                    match.timestamp_mod = entry["timestamp_mod"]
            else:
                new_entry = VaultEntry(entry["site"], entry["user"], entry["password"], entry["state"])
                new_entry.timestamp_mod = entry["timestamp_mod"]
                self.vault.entries.append(new_entry)
        
        # Actualizar versión y timestamp
        if peer_vault_data["version"] > self.vault.version:
            # El peer ya hizo merge primero, copia su versión (es la "canónica")
            self.vault.version = peer_vault_data["version"]
            self.vault.timestamp = peer_vault_data["timestamp"]
        else:
            # Nosotros hacemos merge primero, incrementar versión
            self.vault.version = self.vault.version + 1
            self.vault.timestamp = int(time.time())
# -------------------
    # Comunicación P2P simple con sockets TCP
    # -------------------
    def listen_peer(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("0.0.0.0", self.listen_port))
        server.listen(5)
        print(f"[{self.device_id}] Escuchando en puerto {self.listen_port}")
        while True:
            client_sock, addr = server.accept()
            threading.Thread(target=self.handle_peer_connection, args=(client_sock, addr)).start()

    def handle_peer_connection(self, client_sock, addr):
        """
        Protocolo de sincronización P2P:
        1. Recibe token (autenticación)
        2. Establece canal seguro (DH)
        3. Recibe metadata del peer
        4. Compara metadatas
        5. Decide si enviar/recibir vault
        6. Realiza merge si es necesario
        """
        try:
            # 1️⃣ Recibir primer mensaje: autenticación y metadata
            data = client_sock.recv(65536)
            msg = json.loads(data.decode())
            
            # Validar token
            if not self.validate_auth_token(msg["auth_token"]):
                print(f"[{self.device_id}] ❌ Token inválido de {addr}")
                client_sock.close()
                return
            
            # 2️⃣ Establecer canal seguro (X25519 efímero REAL)
            peer_ephemeral_pub_bytes = bytes.fromhex(msg["ephemeral_pub"])
            shared_secret, my_ephemeral_pub_bytes = self.establish_secure_channel(peer_ephemeral_pub_bytes)
            print(f"[{self.device_id}] 🔐 Canal seguro X25519 establecido (servidor)")
            print(f"[{self.device_id}] SharedSecret (hex): {shared_secret.hex()[:16]}...")
            
            # Derivar SessionKey: HKDF(SharedSecret, Token || Version || Timestamp)
            auth_token_str = msg["auth_token"]["token"]
            peer_version = msg.get("version", 0)
            peer_timestamp = msg.get("timestamp", int(time.time()))
            info = (auth_token_str + str(peer_version) + str(peer_timestamp)).encode()
            session_key = CryptoUtils.hkdf(shared_secret, info)
            print(f"[{self.device_id}] 🔑 SessionKey derivada: HKDF(SS, Token||Version||Timestamp)")
            print(f"[{self.device_id}] SessionKey (hex): {session_key.hex()[:16]}...")
            
            # Enviar nuestra clave efímera X25519 pública
            response_auth = {
                "status": "authenticated",
                "ephemeral_pub": my_ephemeral_pub_bytes.hex()
            }
            client_sock.send(json.dumps(response_auth).encode())
            print(f"[{self.device_id}] 📤 Enviada clave efímera X25519 pública (hex)")
            
            # 3️⃣ Recibir metadata del peer (CIFRADA con SessionKey)
            print(f"[{self.device_id}] ⏳ Esperando metadata cifrada del peer...")
            data_metadata_enc = client_sock.recv(65536)
            print(f"[{self.device_id}] 📥 Recibidos {len(data_metadata_enc)} bytes de metadata")
            data_metadata_enc_dict = json.loads(data_metadata_enc.decode())
            metadata_json = CryptoUtils.aes_gcm_decrypt(session_key, data_metadata_enc_dict)
            peer_metadata = json.loads(metadata_json)
            
            print(f"\n[{self.device_id}] 📨 Recibida metadata de {peer_metadata['device_id']} (CIFRADA)")
            print(f"  - Version peer: {peer_metadata['version']}")
            print(f"  - Timestamp peer: {peer_metadata['timestamp']}")
            
            # 4️⃣ Obtener nuestra metadata
            my_metadata = self.get_metadata()
            print(f"[{self.device_id}] 📊 Comparando metadatas:")
            print(f"  - Mi version: {my_metadata['version']}")
            print(f"  - Mi timestamp: {my_metadata['timestamp']}")
            
            # 5️⃣ Comparar hashes y versiones
            if peer_metadata["hash"] == my_metadata["hash"] and peer_metadata["version"] == my_metadata["version"]:
                print(f"[{self.device_id}] ✅ Vaults sincronizados (hash = version igual)")
                response_sync = {"status": "synchronized", "action": "nothing"}
                client_sock.send(json.dumps(response_sync).encode())
                client_sock.close()
                return
            
            print(f"[{self.device_id}] ⚠️  Vaults diferentes → necesario merge")
            
            # 6️⃣ Comparar timestamps para decidir quién envía el vault
            if my_metadata["timestamp"] > peer_metadata["timestamp"]:
                # Mi timestamp es mayor → Le pido que envíe su vault
                print(f"[{self.device_id}] 📥 Mi timestamp es mayor → Recibiendo vault de {peer_metadata['device_id']}")
                response_sync = {"status": "merge_needed", "action": "send_vault"}
                # Cifrar respuesta con SessionKey
                response_sync_enc = CryptoUtils.aes_gcm_encrypt(session_key, json.dumps(response_sync))
                client_sock.send(json.dumps(response_sync_enc).encode())
                
                # Recibir vault cifrado del peer (viene dentro de mensaje cifrado con SessionKey)
                data_vault_enc = client_sock.recv(65536)
                data_vault_enc_dict = json.loads(data_vault_enc.decode())
                vault_json = CryptoUtils.aes_gcm_decrypt(session_key, data_vault_enc_dict)
                response_vault = json.loads(vault_json)
                peer_vault_enc = response_vault["vault_encrypted"]  # Dict con {nonce, ciphertext} - cifrado con master_password
                
                # Hacer el merge
                print(f"[{self.device_id}] 🔀 Realizando merge...")
                self.merge_vaults(peer_vault_enc)
                
                # Obtener metadata actualizada después del merge
                merged_metadata = self.get_metadata()
                
                # Enviar vault mezclado de vuelta (CIFRADO con SessionKey)
                my_vault_merged = self.encrypt_vault()
                response_merged = {
                    "status": "merge_complete",
                    "vault_encrypted": my_vault_merged,
                    "metadata": merged_metadata
                }
                response_merged_enc = CryptoUtils.aes_gcm_encrypt(session_key, json.dumps(response_merged, default=str))
                client_sock.send(json.dumps(response_merged_enc).encode())
                print(f"[{self.device_id}] ✅ Merge completado y vault enviado de vuelta")
            else:
                # Mi timestamp es menor → Le envío mi vault EN LA MISMA RESPUESTA
                print(f"[{self.device_id}] 📤 Mi timestamp es menor → Enviando vault a {peer_metadata['device_id']}")
                
                # Obtener mi vault cifrado
                my_vault_enc = self.encrypt_vault()
                
                # Enviar respuesta + vault en UN ÚNICO mensaje (CIFRADO con SessionKey)
                response_sync = {
                    "status": "merge_needed", 
                    "action": "receive_vault",
                    "vault_encrypted": my_vault_enc
                }
                response_sync_enc = CryptoUtils.aes_gcm_encrypt(session_key, json.dumps(response_sync))
                client_sock.send(json.dumps(response_sync_enc).encode())
                
                # Recibir vault mezclado (CIFRADO con SessionKey)
                data_merged_enc = client_sock.recv(65536)
                data_merged_enc_dict = json.loads(data_merged_enc.decode())
                merged_json = CryptoUtils.aes_gcm_decrypt(session_key, data_merged_enc_dict)
                merged_response = json.loads(merged_json)
                
                # Actualizar con el vault mezclado
                self.decrypt_vault(merged_response["vault_encrypted"])
                print(f"[{self.device_id}] ✅ Vault mezclado recibido y actualizado")
                
        except Exception as e:
            print(f"[{self.device_id}] ❌ Error en conexión: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            client_sock.close()

def synchronize_with_peer(self, peer_ip, peer_port):
        """
        Protocolo de sincronización P2P (cliente):
        1. Genera token temporal y clave efímera
        2. Envía token para autenticación
        3. Establece canal seguro (DH)
        4. Envía metadata
        5. Recibe respuesta indicando si debe enviar/recibir vault
        6. Realiza merge según corresponda
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((peer_ip, peer_port))
            print(f"\n[{self.device_id}] 🔗 Conectado a {peer_ip}:{peer_port}")
            
            # 1️⃣ Generar token y clave efímera X25519
            auth_token = self.generate_auth_token()
            my_ephemeral_priv, my_ephemeral_pub = CryptoUtils.generate_ephemeral_dh_keys()
            my_ephemeral_pub_bytes = CryptoUtils.serialize_dh_public_key(my_ephemeral_pub)
            
            # 2️⃣ Enviar autenticación + metadata
            my_metadata = self.get_metadata()
            msg_auth = {
                "auth_token": auth_token,
                "ephemeral_pub": my_ephemeral_pub_bytes.hex(),
                "device_id": self.device_id,
                "version": my_metadata["version"],
                "timestamp": my_metadata["timestamp"]
            }
            sock.send(json.dumps(msg_auth, default=str).encode())
            print(f"[{self.device_id}] 📤 Enviado: token + clave efímera X25519 (hex)")
            
            # 3️⃣ Recibir respuesta de autenticación y establecer canal seguro X25519
            data_auth = sock.recv(65536)
            auth_response = json.loads(data_auth.decode())
            peer_ephemeral_pub_bytes = bytes.fromhex(auth_response["ephemeral_pub"])
            peer_ephemeral_pub = CryptoUtils.deserialize_dh_public_key(peer_ephemeral_pub_bytes)
            
            # Calcular SharedSecret: X25519(priv_mio, pub_peer)
            shared_secret = CryptoUtils.dh_shared_secret(my_ephemeral_priv, peer_ephemeral_pub)
            print(f"[{self.device_id}] 🔐 Canal seguro X25519 establecido (cliente)")
            print(f"[{self.device_id}] SharedSecret (hex): {shared_secret.hex()[:16]}...")
            
            # Derivar SessionKey: HKDF(SharedSecret, Token || Version || Timestamp)
            info = (auth_token["token"] + str(my_metadata["version"]) + str(my_metadata["timestamp"])).encode()
            session_key = CryptoUtils.hkdf(shared_secret, info)
            print(f"[{self.device_id}] 🔑 SessionKey derivada: HKDF(SS, Token||Version||Timestamp)")
            print(f"[{self.device_id}] SessionKey (hex): {session_key.hex()[:16]}...")
            
            metadata_enc = CryptoUtils.aes_gcm_encrypt(session_key, json.dumps(my_metadata, default=str))
            sock.send(json.dumps(metadata_enc).encode())
            print(f"[{self.device_id}] 📤 Enviada metadata CIFRADA (version: {my_metadata['version']})")
            
            # 5️⃣ Recibir respuesta según comparación de metadata (CIFRADA con SessionKey)
            data_sync_enc = sock.recv(65536)
            data_sync_enc_dict = json.loads(data_sync_enc.decode())
            sync_json = CryptoUtils.aes_gcm_decrypt(session_key, data_sync_enc_dict)
            sync_response = json.loads(sync_json)
            
            if sync_response["status"] == "synchronized":
                print(f"[{self.device_id}] ✅ Vaults ya sincronizados (sin cambios)")
                sock.close()
                return
            
            # 6️⃣ Procesar merge según acción del peer
            if sync_response["action"] == "send_vault":
                # El peer tiene timestamp mayor → Debo enviar mi vault
                print(f"[{self.device_id}] 📤 Peer tiene timestamp mayor → Enviando vault...")
                my_vault_enc = self.encrypt_vault()
                
                # Enviar vault JUNTO CON la acción en UN ÚNICO mensaje (CIFRADO con SessionKey)
                response_with_vault = {
                    "status": "merge_needed",
                    "action": "send_vault",
                    "vault_encrypted": my_vault_enc
                }
                response_with_vault_enc = CryptoUtils.aes_gcm_encrypt(session_key, json.dumps(response_with_vault))
                sock.send(json.dumps(response_with_vault_enc).encode())
                
                # Recibir vault mezclado (CIFRADO con SessionKey)
                data_merged_enc = sock.recv(65536)
                data_merged_enc_dict = json.loads(data_merged_enc.decode())
                merged_json = CryptoUtils.aes_gcm_decrypt(session_key, data_merged_enc_dict)
                merged_response = json.loads(merged_json)
                
                # Actualizar con vault mezclado
                self.merge_vaults(merged_response["vault_encrypted"])
                print(f"[{self.device_id}] ✅ Sincronización completada (yo envié, peer hizo merge)")
                
            elif sync_response["action"] == "receive_vault":
                # El peer tiene timestamp menor → Recibiré su vault en esta misma respuesta
                print(f"[{self.device_id}] 📥 Peer tiene timestamp menor → Recibiendo vault...")
                
                # El vault ya viene en la respuesta (cifrada con SessionKey)
                peer_vault_enc = sync_response["vault_encrypted"]
                
                # Hacer el merge
                self.merge_vaults(peer_vault_enc)
                
                # Enviar vault mezclado de vuelta (CIFRADO con SessionKey)
                merged_vault = self.encrypt_vault()
                merged_metadata = self.get_metadata()
                response_merged = {
                    "status": "merge_complete",
                    "vault_encrypted": merged_vault,
                    "metadata": merged_metadata
                }
                response_merged_enc = CryptoUtils.aes_gcm_encrypt(session_key, json.dumps(response_merged, default=str))
                sock.send(json.dumps(response_merged_enc).encode())
                print(f"[{self.device_id}] ✅ Sincronización completada (yo recibí y hacé merge)")
            
        except Exception as e:
            print(f"[{self.device_id}] ❌ Error sincronización: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            sock.close()


if __name__ == "__main__":
    print("="*70)
    print("🔐 SISTEMA P2P DE SINCRONIZACIÓN DE CONTRASEÑAS")
    print("="*70 + "\n")
    
    # Crear dos dispositivos con la misma contraseña maestra
    master_password = "mi_master_password"
    device_a = P2PClient("DeviceA", master_password, listen_port=5001)
    device_b = P2PClient("DeviceB", master_password, listen_port=5002)
    
    # Darles tiempo para que inicien los hilos de escucha
    time.sleep(1)
    
    print("\n" + "="*70)
    print("1️⃣  INTERCAMBIANDO CLAVES PÚBLICAS ENTRE DISPOSITIVOS")
    print("="*70 + "\n")
    
    # DeviceA anuncia su clave pública
    announcement_a = device_a.broadcast_announcement()
    device_b.receive_announcement(announcement_a)
    print(f"✅ DeviceB recibió clave pública de DeviceA")
    
    # DeviceB anuncia su clave pública
    announcement_b = device_b.broadcast_announcement()
    device_a.receive_announcement(announcement_b)
    print(f"✅ DeviceA recibió clave pública de DeviceB\n")
    
    time.sleep(1)
    
    print("="*70)
    print("2️⃣  DEVICEA AGREGA UNA CONTRASEÑA (gmail.com)")
    print("="*70 + "\n")
    
    pwd_a = device_a.add_new_password("gmail.com", "juan@example.com")
    print(f"✅ DeviceA agregó: gmail.com\n")
    
    print("="*70)
    print("3️⃣  DEVICEB AGREGA OTRA CONTRASEÑA (github.com)")
    print("="*70 + "\n")
    
    pwd_b = device_b.add_new_password("github.com", "juan_github")
    print(f"✅ DeviceB agregó: github.com\n")
    
    # Mostrar estado antes de sincronizar
    print("="*70)
    print("📋 ESTADO ANTES DE SINCRONIZAR")
    print("="*70 + "\n")
    
    print("📋 DEVICEA (ANTES):")
    metadata_a = device_a.get_metadata()
    vault_a = json.loads(device_a.vault.to_json())
    print(f"  - Version: {metadata_a['version']}")
    print(f"  - Timestamp: {vault_a['timestamp']}")
    print(f"  - Contraseñas: {len(vault_a['entries'])}")
    print(f"  - Hash: {metadata_a['hash']}")
    for entry in vault_a['entries']:
        print(f"\n    Site: {entry['site']}")
        print(f"    User: {entry['user']}")
        print(f"    Password: {entry['password']}")
        print(f"    State: {entry['state']}")
        print(f"    Timestamp Mod: {entry['timestamp_mod']}")
    
    print("\n📋 DEVICEB (ANTES):")
    metadata_b = device_b.get_metadata()
    vault_b = json.loads(device_b.vault.to_json())
    print(f"  - Version: {metadata_b['version']}")
    print(f"  - Timestamp: {vault_b['timestamp']}")
    print(f"  - Contraseñas: {len(vault_b['entries'])}")
    print(f"  - Hash: {metadata_b['hash']}")
    for entry in vault_b['entries']:
        print(f"\n    Site: {entry['site']}")
        print(f"    User: {entry['user']}")
        print(f"    Password: {entry['password']}")
        print(f"    State: {entry['state']}")
        print(f"    Timestamp Mod: {entry['timestamp_mod']}")
    
    time.sleep(1)
    
    print("\n" + "="*70)
    print("4️⃣  SINCRONIZANDO: DEVICEA → DEVICEB")
    print("="*70 + "\n")
    
    device_a.synchronize_with_peer("127.0.0.1", 5002)
    time.sleep(1)
    
    print("\n" + "="*70)
    print("✅ ESTADO FINAL DESPUÉS DE SINCRONIZACIÓN")
    print("="*70 + "\n")
    
    print("📋 DEVICEA (DESPUÉS):")
    metadata_a_final = device_a.get_metadata()
    vault_a_final = json.loads(device_a.vault.to_json())
    print(f"  - Version: {metadata_a_final['version']}")
    print(f"  - Timestamp: {vault_a_final['timestamp']}")
    print(f"  - Contraseñas: {len(vault_a_final['entries'])}")
    print(f"  - Hash: {metadata_a_final['hash']}")
    for entry in vault_a_final['entries']:
        print(f"\n    Site: {entry['site']}")
        print(f"    User: {entry['user']}")
        print(f"    Password: {entry['password']}")
        print(f"    State: {entry['state']}")
        print(f"    Timestamp Mod: {entry['timestamp_mod']}")
    
    print("\n📋 DEVICEB (DESPUÉS):")
    metadata_b_final = device_b.get_metadata()
    vault_b_final = json.loads(device_b.vault.to_json())
    print(f"  - Version: {metadata_b_final['version']}")
    print(f"  - Timestamp: {vault_b_final['timestamp']}")
    print(f"  - Contraseñas: {len(vault_b_final['entries'])}")
    print(f"  - Hash: {metadata_b_final['hash']}")
    for entry in vault_b_final['entries']:
        print(f"\n    Site: {entry['site']}")
        print(f"    User: {entry['user']}")
        print(f"    Password: {entry['password']}")
        print(f"    State: {entry['state']}")
        print(f"    Timestamp Mod: {entry['timestamp_mod']}")
    
    # Verificar sincronización
    print("\n" + "="*70)
    print("🔍 VERIFICACIÓN DE SINCRONIZACIÓN")
    print("="*70)
    
    devicea_sites = {e['site'] for e in vault_a_final['entries']}
    deviceb_sites = {e['site'] for e in vault_b_final['entries']}
    
    if devicea_sites == deviceb_sites and len(devicea_sites) == 2:
        print("✅ ¡SINCRONIZACIÓN EXITOSA!")
        print(f"   Ambos dispositivos tienen las mismas contraseñas:")
        for site in sorted(devicea_sites):
            print(f"   • {site}")
        print(f"   Hashes coinciden: {metadata_a_final['hash'] == metadata_b_final['hash']}")
        print(f"   Versiones iguales: {metadata_a_final['version'] == metadata_b_final['version']}")
    else:
        print("❌ Error: Las contraseñas no se sincronizaron correctamente")
        print(f"   DeviceA sites: {devicea_sites}")
        print(f"   DeviceB sites: {deviceb_sites}")
    
    time.sleep(1)
    
    print("\n" + "="*70)
    print("5️⃣  DEVICEB BORRA UNA CONTRASEÑA (github.com)")
    print("="*70 + "\n")
    
    device_b.delete_password("github.com", "juan_github")
    print(f"✅ DeviceB marcó como borrada: github.com\n")
    
    # Mostrar estado antes de segunda sincronización
    print("="*70)
    print("📋 ESTADO ANTES DE SEGUNDA SINCRONIZACIÓN")
    print("="*70 + "\n")
    
    print("📋 DEVICEA (ANTES):")
    metadata_a2 = device_a.get_metadata()
    vault_a2 = json.loads(device_a.vault.to_json())
    print(f"  - Version: {metadata_a2['version']}")
    print(f"  - Timestamp: {vault_a2['timestamp']}")
    print(f"  - Contraseñas: {len(vault_a2['entries'])}")
    print(f"  - Hash: {metadata_a2['hash']}")
    for entry in vault_a2['entries']:
        print(f"\n    Site: {entry['site']}")
        print(f"    State: {entry['state']}")
        print(f"    Timestamp Mod: {entry['timestamp_mod']}")
    
    print("\n📋 DEVICEB (ANTES):")
    metadata_b2 = device_b.get_metadata()
    vault_b2 = json.loads(device_b.vault.to_json())
    print(f"  - Version: {metadata_b2['version']}")
    print(f"  - Timestamp: {vault_b2['timestamp']}")
    print(f"  - Contraseñas: {len(vault_b2['entries'])}")
    print(f"  - Hash: {metadata_b2['hash']}")
    for entry in vault_b2['entries']:
        print(f"\n    Site: {entry['site']}")
        print(f"    State: {entry['state']}")
        print(f"    Timestamp Mod: {entry['timestamp_mod']}")
    
    time.sleep(1)
    
    print("\n" + "="*70)
    print("6️⃣  SEGUNDA SINCRONIZACIÓN: DEVICEA → DEVICEB")
    print("="*70 + "\n")
    
    device_a.synchronize_with_peer("127.0.0.1", 5002)
    time.sleep(1)
    
    print("\n" + "="*70)
    print("✅ ESTADO FINAL DESPUÉS DE SEGUNDA SINCRONIZACIÓN")
    print("="*70 + "\n")
    
    print("📋 DEVICEA (DESPUÉS):")
    metadata_a2_final = device_a.get_metadata()
    vault_a2_final = json.loads(device_a.vault.to_json())
    print(f"  - Version: {metadata_a2_final['version']}")
    print(f"  - Timestamp: {vault_a2_final['timestamp']}")
    print(f"  - Contraseñas: {len(vault_a2_final['entries'])}")
    print(f"  - Hash: {metadata_a2_final['hash']}")
    for entry in vault_a2_final['entries']:
        print(f"\n    Site: {entry['site']}")
        print(f"    State: {entry['state']}")
        print(f"    Timestamp Mod: {entry['timestamp_mod']}")
    
    print("\n📋 DEVICEB (DESPUÉS):")
    metadata_b2_final = device_b.get_metadata()
    vault_b2_final = json.loads(device_b.vault.to_json())
    print(f"  - Version: {metadata_b2_final['version']}")
    print(f"  - Timestamp: {vault_b2_final['timestamp']}")
    print(f"  - Contraseñas: {len(vault_b2_final['entries'])}")
    print(f"  - Hash: {metadata_b2_final['hash']}")
    for entry in vault_b2_final['entries']:
        print(f"\n    Site: {entry['site']}")
        print(f"    State: {entry['state']}")
        print(f"    Timestamp Mod: {entry['timestamp_mod']}")
    
    # Verificar segunda sincronización
    print("\n" + "="*70)
    print("🔍 VERIFICACIÓN DE SEGUNDA SINCRONIZACIÓN")
    print("="*70)
    
    devicea_entries = {(e['site'], e['state']) for e in vault_a2_final['entries']}
    deviceb_entries = {(e['site'], e['state']) for e in vault_b2_final['entries']}
    
    if devicea_entries == deviceb_entries:
        print("✅ ¡SEGUNDA SINCRONIZACIÓN EXITOSA!")
        print(f"   Ambos dispositivos tienen el mismo estado:")
        for site, state in sorted(devicea_entries):
            print(f"   • {site}: {state}")
        print(f"   Hashes coinciden: {metadata_a2_final['hash'] == metadata_b2_final['hash']}")
        print(f"   Versiones iguales: {metadata_a2_final['version'] == metadata_b2_final['version']}")
        print(f"   El soft delete se propagó correctamente: ✅")
    else:
        print("❌ Error: Los estados no coinciden")
        print(f"   DeviceA: {devicea_entries}")
        print(f"   DeviceB: {deviceb_entries}")