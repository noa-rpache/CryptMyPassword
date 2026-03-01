import os
import uuid
import time
import json
import socket
import struct
import threading
import fcntl
from hashlib import sha256

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from argon2.low_level import hash_secret_raw, Type

from crypto_utils import CryptoUtils
from vault import Vault, VaultEntry
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# -------------------------------
# CLIENTE P2P
# -------------------------------
class P2PClient:
    def __init__(self, device_id, master_password, listen_port=5000, announcement_port=6000, known_peers=None, mongo_collection=None, encryption_key=None):
        self.device_id = device_id
        self.master_password = master_password
        self.mongo_collection = mongo_collection
        self.vault = Vault(device_id, mongo_collection=mongo_collection)

        # Derivar clave de cifrado de contraseñas con Argon2id
        if encryption_key:
            self._entry_key = hash_secret_raw(
                secret=encryption_key.encode(),
                salt=b"CryptMyPassword_v1_salt",
                time_cost=2,
                memory_cost=2**16,
                parallelism=2,
                hash_len=32,
                type=Type.ID
            )
            print(f"[{self.device_id}] \U0001f512 Clave de cifrado de contraseñas derivada con Argon2id")
        else:
            self._entry_key = None

        # Claves Ed25519
        self.device_priv = Ed25519PrivateKey.generate()
        self.device_pub = self.device_priv.public_key()

        # Mapa peers: device_id -> Ed25519PublicKey
        self.peers_pub_keys = {}
        
        # Mapa peers activos: device_id -> {"ip": ip, "port": port, "last_seen": timestamp}
        self.active_peers = {}
        
        # Lista de peers conocidos: [(device_id, ip, announcement_port), ...]
        # En modo multicast ya no se usa (el multicast descubre automáticamente)
        self.known_peers = known_peers if known_peers is not None else []
        
        # Flag para controlar threads
        self.running = True

        # Configuración multicast
        self.multicast_group = "239.255.0.42"  # Grupo multicast privado (rango 239.0.0.0/8 = admin-scoped)
        self.multicast_port = 6003  # Puerto multicast para anuncios
        
        # Pre-inicializar parámetros DH (2048-bit) - esto tarda ~10-20s en la primera llamada
        # Se hace aquí para evitar bloqueo durante la comunicación
# No requiere inicialización con X25519 (instantáneo)
        print(f"[{self.device_id}] ✅ Criptografía X25519 lista (instantáneo)")

        # Configuración P2P
        self.listen_port = listen_port
        self.announcement_port = announcement_port
        
        # Thread para servidor de sincronización
        self.server_thread = threading.Thread(target=self.listen_peer)
        self.server_thread.daemon = True
        self.server_thread.start()
        
        # Thread para escuchar multicast (anuncios de claves públicas)
        self.multicast_listener_thread = threading.Thread(target=self.listen_multicast_announcements)
        self.multicast_listener_thread.daemon = True
        self.multicast_listener_thread.start()
        
        # Thread para enviar anuncios periódicos por multicast
        self.multicast_broadcast_thread = threading.Thread(target=self.broadcast_announcements_via_multicast)
        self.multicast_broadcast_thread.daemon = True
        self.multicast_broadcast_thread.start()

    # -------------------
    # Cifrado/descifrado de contraseñas individuales (AES-GCM + Argon2id)
    # -------------------
    def _encrypt_password(self, plaintext: str) -> str:
        """Cifra una contraseña con AES-GCM. Si no hay clave, devuelve tal cual."""
        if not self._entry_key:
            return plaintext
        aesgcm = AESGCM(self._entry_key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
        return f"ENC:{nonce.hex()}:{ct.hex()}"

    def _decrypt_password(self, encrypted: str) -> str:
        """Descifra una contraseña. Si no está cifrada o no hay clave, devuelve tal cual."""
        if not self._entry_key or not encrypted or not encrypted.startswith("ENC:"):
            return encrypted
        parts = encrypted.split(":", 2)
        nonce = bytes.fromhex(parts[1])
        ct = bytes.fromhex(parts[2])
        aesgcm = AESGCM(self._entry_key)
        return aesgcm.decrypt(nonce, ct, None).decode()

    # -------------------
    # Utilidades de red
    # -------------------
    def _get_local_ips(self):
        """Obtiene una lista de IPs locales (IPv4, no loopback) de todas las interfaces activas."""
        ips = []
        try:
            # Método 1: usando socket.getaddrinfo con hostname
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
                ip = info[4][0]
                if not ip.startswith("127."):
                    ips.append(ip)
        except Exception:
            pass
        
        # Método 2: usando /proc/net en Linux (más fiable)
        try:
            import netifaces
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        ip = addr['addr']
                        if not ip.startswith("127."):
                            ips.append(ip)
        except ImportError:
            # Fallback: leer IPs de los sockets activos
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                s.close()
                if ip not in ips and not ip.startswith("127."):
                    ips.append(ip)
            except Exception:
                pass
        
        # Deduplicar
        seen = set()
        result = []
        for ip in ips:
            if ip not in seen:
                seen.add(ip)
                result.append(ip)
        
        # Fallback último: al menos 0.0.0.0
        if not result:
            result = ["0.0.0.0"]
        
        return result

    # -------------------
    # Anuncio de presencia vía MULTICAST (cada 20 segundos)
    # -------------------
    def broadcast_announcement(self):
        """
        Crea un anuncio de presencia con la clave pública
        Se envía por multicast (no TCP unicast)
        """
        announcement = {
            "device_id": self.device_id,
            "device_pub_bytes": self.device_pub.public_bytes_raw().hex(),
            "timestamp": int(time.time())
        }
        return announcement

    def send_announcement_via_multicast(self):
        """
        Envía un anuncio a demanda al grupo multicast
        """
        try:
            announcement = self.broadcast_announcement()
            payload = json.dumps(announcement).encode()
            
            # Enviar por TODAS las interfaces de red disponibles
            interfaces = self._get_local_ips()
            for iface_ip in interfaces:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(iface_ip))
                    sock.settimeout(2)
                    sock.sendto(payload, (self.multicast_group, self.multicast_port))
                    sock.close()
                except Exception:
                    pass
            
            print(f"[{self.device_id}] 📡 Anuncio multicast enviado por {len(interfaces)} interfaces: {interfaces}")
            return True
        except Exception as e:
            print(f"[{self.device_id}] ⚠️  Error enviando anuncio multicast: {type(e).__name__}: {e}")
            return False

    def broadcast_announcements_via_multicast(self):
        """
        Envía anuncios periódicos (cada 20 segundos) al grupo multicast
        """
        print(f"[{self.device_id}] 📢 Iniciando broadcast periódico de anuncios vía MULTICAST (cada 20s)")
        while self.running:
            try:
                self.send_announcement_via_multicast()
                # Esperar 20 segundos antes del próximo anuncio
                time.sleep(20)
            except Exception as e:
                print(f"[{self.device_id}] ❌ Error en broadcast multicast: {e}")
                time.sleep(5)

    def listen_multicast_announcements(self):
        """
        Escucha anuncios de otros peers en el grupo multicast
        Captura sus IPs y las almacena como peers activos
        """
        try:
            # Crear socket UDP para escuchar multicast
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind al puerto multicast
            sock.bind(("", self.multicast_port))
            
            # Unirse al grupo multicast en TODAS las interfaces disponibles
            for iface_ip in self._get_local_ips():
                try:
                    mreq = socket.inet_aton(self.multicast_group) + socket.inet_aton(iface_ip)
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                    print(f"[{self.device_id}] 📻 Multicast join en interfaz {iface_ip}")
                except Exception as e:
                    print(f"[{self.device_id}] ⚠️  No se pudo join multicast en {iface_ip}: {e}")
            
            print(f"[{self.device_id}] 📻 Escuchando anuncios en grupo multicast {self.multicast_group}:{self.multicast_port}")
            
            while self.running:
                try:
                    data, addr = sock.recvfrom(4096)
                    announcement = json.loads(data.decode())
                    
                    # Procesar el anuncio
                    device_id = announcement["device_id"]
                    peer_ip = addr[0]
                    peer_port = addr[1]
                    
                    # No procesar anuncios propios
                    if device_id == self.device_id:
                        continue
                    
                    pub_bytes = bytes.fromhex(announcement["device_pub_bytes"])
                    pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
                    
                    # Guardar/actualizar la clave pública del peer
                    self.peers_pub_keys[device_id] = pub_key
                    
                    # Guardar/actualizar información del peer activo
                    self.active_peers[device_id] = {
                        "ip": peer_ip,
                        "port": peer_port,
                        "last_seen": int(time.time())
                    }
                    
                    print(f"[{self.device_id}] 📨 Anuncio multicast recibido de {device_id} desde {peer_ip}:{peer_port} - Clave pública y IP actualizadas ✅")
                    
                except Exception as e:
                    if self.running:
                        print(f"[{self.device_id}] ⚠️  Error procesando anuncio multicast: {type(e).__name__}")
        except Exception as e:
            print(f"[{self.device_id}] ❌ Error en listen_multicast_announcements: {e}")

    def get_active_peers(self):
        """
        Retorna la lista de peers activos: device_id -> {"ip": ip, "port": port, "last_seen": timestamp}
        """
        return self.active_peers.copy()

    def get_active_peers_list(self):
        """
        Retorna una lista formateada de peers activos
        """
        active_list = []
        for device_id, info in self.active_peers.items():
            active_list.append({
                "device_id": device_id,
                "ip": info["ip"],
                "port": info["port"],
                "last_seen": info["last_seen"],
                "last_seen_ago_seconds": int(time.time()) - info["last_seen"]
            })
        return active_list

    def print_active_peers(self):
        """
        Imprime un resumen de los peers activos
        """
        peers = self.get_active_peers_list()
        if not peers:
            print(f"[{self.device_id}] ℹ️  No hay peers activos conocidos")
            return
        
        print(f"\n[{self.device_id}] 🟢 Peers activos en el grupo multicast:")
        for peer in peers:
            print(f"  • {peer['device_id']:<15} | IP: {peer['ip']:<15} | Puerto: {peer['port']:<5} | Visto hace {peer['last_seen_ago_seconds']}s")
        print()

    def send_announcement_to_peer(self, peer_ip, peer_announcement_port, peer_device_id="unknown"):
        """
        Envía un anuncio a demanda al grupo multicast
        """
        return self.send_announcement_via_multicast()

    # -------------------
    # Generación de contraseña (vacío)
    # -------------------
    def generate_password(self):
        return "PLACEHOLDER_PASSWORD"
    
    def add_new_password(self, site: str, user: str, password: str = None, _already_encrypted: bool = False):
        """
        Agrega una nueva contraseña al vault (MongoDB).
        Si no se proporciona password, se genera una.
        """
        # 1️⃣ Generar contraseña si no se proporcionó
        if password is None:
            password = self.generate_password()

        # 2️⃣ Cifrar y crear entrada, agregarla al vault (escribe en Mongo)
        encrypted_pwd = password if _already_encrypted else self._encrypt_password(password)
        entry = VaultEntry(site, user, encrypted_pwd)
        self.vault.add_entry(entry)

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
        return password

    def delete_password(self, site: str, user: str):
        """
        Marca una contraseña como borrada (soft delete).
        Opera directamente sobre MongoDB a través del Vault.
        """
        # 1️⃣ Buscar la entrada
        entry = self.vault.get_entry(site, user)
        
        if not entry:
            print(f"[{self.device_id}] ❌ No se encontró contraseña para {site}:{user}")
            return False
        
        # 2️⃣ Cambiar estado a borrado en Mongo
        now = int(time.time())
        self.vault.update_entry(site, user, {
            "state": "borrado",
            "timestamp_mod": now
        })
        
        # 3️⃣ Actualizar metadata global
        self.vault.version += 1
        self.vault.timestamp = now
        self.vault._sync_metadata()
        
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
    # Consultas de contraseñas (leen de MongoDB)
    # -------------------
    def get_all_passwords(self):
        """Devuelve todas las contraseñas activas del vault (descifradas)."""
        return [
            {"domain": e.site, "user": e.user, "password": self._decrypt_password(e.password)}
            for e in self.vault.get_all_active_entries()
        ]

    def get_password_by_domain(self, domain: str):
        """Busca una contraseña activa por dominio (descifrada)."""
        for e in self.vault.get_all_active_entries():
            if e.site == domain:
                return {"user": e.user, "password": self._decrypt_password(e.password)}
        return None

    def save_password(self, domain: str, user: str, password: str):
        """
        Guarda o actualiza una contraseña (cifrada). Si ya existe para ese dominio+user, la actualiza.
        Si no existe, la crea.
        """
        encrypted_pwd = self._encrypt_password(password)
        existing = self.vault.get_entry(domain, user)
        if existing:
            now = int(time.time())
            self.vault.update_entry(domain, user, {
                "password": encrypted_pwd,
                "state": "activo",
                "timestamp_mod": now
            })
            self.vault.version += 1
            self.vault.timestamp = now
            self.vault._sync_metadata()
            print(f"[{self.device_id}] Contraseña actualizada para {domain}:{user}")
            return password
        else:
            return self.add_new_password(domain, user, password=encrypted_pwd, _already_encrypted=True)

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
        self.vault._sync_metadata()

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
    # DH efímero
    # -------------------
    def establish_secure_channel(self, peer_public_key_bytes):
        """
        Establece canal seguro DH:
        1. Genera nuestro par DH efímero
        2. Deserializa clave pública del peer
        3. Calcula SharedSecret: DH(priv_mio, pub_peer)
        4. Devuelve (SharedSecret, pub_mia_serializada)
        """
        my_ephemeral_priv, my_ephemeral_pub = CryptoUtils.generate_ephemeral_dh_keys()
        peer_ephemeral_pub = CryptoUtils.deserialize_dh_public_key(peer_public_key_bytes)
        shared_secret = CryptoUtils.dh_shared_secret(my_ephemeral_priv, peer_ephemeral_pub)
        my_pub_serialized = CryptoUtils.serialize_dh_public_key(my_ephemeral_pub)
        return shared_secret, my_pub_serialized

    # -------------------
    # Metadata
    # -------------------
    def get_metadata(self):
        vault_hash = self.vault.hash()
        message = (str(self.vault.version) + vault_hash).encode()
        signature = self.device_priv.sign(message)
        return {
            "device_id": self.device_id,
            "version": self.vault.version,
            "timestamp": self.vault.timestamp,
            "hash": vault_hash,
            "signature": signature
        }

    def validate_metadata(self, metadata, peer_pub: Ed25519PublicKey):
        message = (str(metadata["version"]) + metadata["hash"]).encode()
        try:
            peer_pub.verify(metadata["signature"], message)
            return True
        except:
            return False

    # -------------------
    # Merge
    # -------------------

    def merge_vaults(self, peer_vault_encrypted):
        """Descifra vault del peer (cifrado con master_password) y hace merge.
        Escribe el resultado en MongoDB a través del Vault."""
        key = sha256(self.master_password.encode()).digest()
        peer_vault_json = CryptoUtils.aes_gcm_decrypt(key, peer_vault_encrypted)
        peer_vault_data = json.loads(peer_vault_json)
        print("vault que recibimos para el clonado " + peer_vault_json)

        # Cargar entries actuales
        current_entries = self.vault.entries

        for entry in peer_vault_data["entries"]:
            match = next((e for e in current_entries if e.site == entry["site"] and e.user == entry["user"]), None)
            if match:
                if entry["timestamp_mod"] > match.timestamp_mod:
                    self.vault.update_entry(entry["site"], entry["user"], {
                        "password": entry["password"],
                        "state": entry["state"],
                        "timestamp_mod": entry["timestamp_mod"]
                    })
            else:
                new_entry = VaultEntry(entry["site"], entry["user"], entry["password"], entry["state"])
                new_entry.timestamp_mod = entry["timestamp_mod"]
                # Añadir sin incrementar version (lo hacemos abajo)
                if self.vault._collection is not None:
                    self.vault._collection.update_one(
                        {"_id": self.vault.device_id},
                        {"$push": {"entries": new_entry.to_dict()}}
                    )
                else:
                    self.vault._local_entries.append(new_entry)

        # Actualizar versión y timestamp
        if peer_vault_data["version"] > self.vault.version:
            self.vault.version = peer_vault_data["version"]
            self.vault.timestamp = peer_vault_data["timestamp"]
        else:
            self.vault.version = self.vault.version + 1
            self.vault.timestamp = int(time.time())
        self.vault._sync_metadata()

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
            if not data:
                client_sock.close()
                return
            try:
                msg = json.loads(data.decode())
            except (json.JSONDecodeError, UnicodeDecodeError):
                print(f"[{self.device_id}] ⚠️ Datos no válidos recibidos de {addr}, ignorando")
                client_sock.close()
                return
            
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
    device_a = P2PClient("DeviceA", master_password, listen_port=5001, announcement_port=6001)
    device_b = P2PClient("DeviceB", master_password, listen_port=5002, announcement_port=6002)
    
    # Esperar a que inicien los hilos (listener + broadcaster multicast)
    print("\n⏳ Esperando que los dispositivos se descubran vía MULTICAST...")
    time.sleep(3)
    
    print("\n" + "="*70)
    print("1️⃣  INTERCAMBIANDO CLAVES PÚBLICAS VÍA MULTICAST")
    print("="*70 + "\n")
    
    # Enviar anuncios a demanda para acelerar el descubrimiento
    print("📡 DeviceA publicando su clave pública en MULTICAST...")
    device_a.send_announcement_via_multicast()
    time.sleep(0.5)
    
    print("📡 DeviceB publicando su clave pública en MULTICAST...")
    device_b.send_announcement_via_multicast()
    time.sleep(0.5)
    
    # Segundo anuncio para garantizar entrega
    print("📡 DeviceA publicando su clave pública nuevamente en MULTICAST...")
    device_a.send_announcement_via_multicast()
    time.sleep(0.5)
    
    print("📡 DeviceB publicando su clave pública nuevamente en MULTICAST...")
    device_b.send_announcement_via_multicast()
    time.sleep(1)
    
    # Verificar que se descubrieron mutuamente
    print("\n✅ Estado de descubrimiento de peers:")
    print(f"   DeviceA conoce a: {list(device_a.peers_pub_keys.keys())}")
    print(f"   DeviceB conoce a: {list(device_b.peers_pub_keys.keys())}")
    
    # Mostrar peers activos con sus IPs
    print("\n" + "="*70)
    print("📡 PEERS ACTIVOS EN EL GRUPO MULTICAST")
    print("="*70)
    device_a.print_active_peers()
    device_b.print_active_peers()
    
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