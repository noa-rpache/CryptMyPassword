import os
import sys
import random
import subprocess
import signal
import importlib.util
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent / ".env")

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic.main import BaseModel
from pymongo import MongoClient

from .auth import API_KEY, verify_api_key

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "gen_password"))
from entropy_engine import (  # noqa: E402
    _get_mongo_collection,
    is_quantum_worker_alive,
    start_quantum_refresh_worker,
)
from password_manager import check_hibp, generate_secure_password  # noqa: E402

# Importar el cliente P2P desde sync-motor.py
sync_motor_dir = os.path.join(os.path.dirname(__file__), "sync-motor")
sys.path.insert(0, sync_motor_dir)
sync_motor_path = os.path.join(sync_motor_dir, "sync-motor.py")
spec = importlib.util.spec_from_file_location("sync_motor_module", sync_motor_path)
sync_motor_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync_motor_module)
P2PClient = sync_motor_module.P2PClient

##### MODEL


class FullItem(BaseModel):
    password: str
    user: str
    domain: str


class Device(BaseModel):
    password: str


class SyncRequest(BaseModel):
    peer_ip: str
    peer_port: int


##### MONGODB CONFIG

MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")

client = MongoClient(MONGO_URL)
db = client["password_manager"]
collection = db["passwords"]

##### P2P CLIENT CONFIG

# Instancia global del cliente P2P
p2p_client = None

# Proceso BLE server (recibir)
ble_server_process = None

# Configuración del cliente P2P (puertos fijos)
DEVICE_ID = os.getenv("DEVICE_ID", f"Node{random.randint(10000, 99999)}")
MASTER_PASSWORD = os.getenv("MASTER_PASSWORD", "default_master_password")
P2P_LISTEN_PORT = 5000  # Puerto fijo para sincronización TCP
P2P_ANNOUNCEMENT_PORT = 6000  # Puerto fijo para anuncios multicast

##### API Config


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan: run startup logic before serving requests."""
    global p2p_client
    
    # Iniciar quantum refresh worker
    start_quantum_refresh_worker()
    print(f"[*] ANU quantum refresh worker alive: {is_quantum_worker_alive()}")
    
    # Inicializar cliente P2P (con MongoDB)
    print(f"[*] Iniciando cliente P2P: {DEVICE_ID}")
    p2p_client = P2PClient(
        device_id=DEVICE_ID,
        master_password=MASTER_PASSWORD,
        listen_port=P2P_LISTEN_PORT,
        announcement_port=P2P_ANNOUNCEMENT_PORT,
        mongo_collection=collection,
        encryption_key=API_KEY
    )
    print(f"[*] Cliente P2P iniciado exitosamente")
    
    yield
    
    # Shutdown: detener cliente P2P
    if p2p_client:
        p2p_client.running = False
        print(f"[*] Cliente P2P detenido")
    
    # Shutdown: detener BLE server si estaba corriendo
    global ble_server_process
    if ble_server_process and ble_server_process.poll() is None:
        ble_server_process.terminate()
        ble_server_process = None
        print("[*] BLE server detenido")


app = FastAPI(lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


#### API requests


## PASSWORD CRUD
"""
Generar una contraseña
"""


@app.post("/password")
async def generate_password(api_key: str = Depends(verify_api_key)):
    password = generate_secure_password(24)
    return {"password": password}


"""
Recuperar todas las contraseñas almacenadas de la forma:
    {
        "domain": dominio,
        "password": contraseña,
        "user": usuario
    }
"""


@app.get("/password")
async def retrieve_passwords(api_key: str = Depends(verify_api_key)):
    if not p2p_client:
        return {"error": "Cliente P2P no inicializado"}
    return p2p_client.get_all_passwords()


"""
Comprueba todas las contraseñas almacenadas contra la base de datos de Have I Been Pwned.

Devuelve la lista de dominios con contraseñas comprometidas:
    [
        {"domain": "example.com", "user": "test", "breaches": 143},
        ...
    ]
"""


@app.get("/audit")
async def audit_passwords(api_key: str = Depends(verify_api_key)):
    if not p2p_client:
        return {"error": "Cliente P2P no inicializado"}
    
    results = []
    for entry in p2p_client.get_all_passwords():
        is_pwned, count = check_hibp(entry["password"])
        if is_pwned:
            results.append(
                {
                    "domain": entry["domain"],
                    "user": entry["user"],
                    "breaches": count,
                }
            )
    return results


"""
Recuperar la información para un dominio `domain`.

Si no hay información asociada al dominio se devuelve `null`.

Si hay información se devuelve:
    {"user": "test", "password": "random"}

"""


@app.get("/password/{domain}")
async def get_info_of_domain(domain: str, api_key: str = Depends(verify_api_key)):
    if not p2p_client:
        return {"error": "Cliente P2P no inicializado"}
    return p2p_client.get_password_by_domain(domain)


"""
Almacenar o actualizar una clave. Solo puede haber un par usuario-contraseña por cada dominio.

El cuerpo debe tener el siguiente formato:

    {
        "domain": "test.com",
        "user": "test",
        "password": "random"
    }

"""


@app.post("/password/save")
async def save_password(content: FullItem, api_key: str = Depends(verify_api_key)):
    if not p2p_client:
        return {"error": "Cliente P2P no inicializado"}
    
    print(f"/password/save {content}")
    p2p_client.save_password(content.domain, content.user, content.password)

    return {
        "domain": content.domain,
        "user": content.user,
        "password": content.password,
    }


"""
Eliminar una contraseña guardada para un dominio específico.

El parámetro debe ser el dominio a eliminar.

Ejemplo: DELETE /password/www.gmail.com

"""


@app.delete("/password/{domain}")
async def delete_password(domain: str, api_key: str = Depends(verify_api_key)):
    if not p2p_client:
        return {"error": "Cliente P2P no inicializado"}
    
    print(f"/password/delete {domain}")
    
    # Buscar la entrada para obtener el user
    entry_info = p2p_client.get_password_by_domain(domain)
    if not entry_info:
        return {
            "success": False,
            "message": f"No se encontró contraseña para el dominio: {domain}",
            "domain": domain,
        }
    
    result = p2p_client.delete_password(domain, entry_info["user"])
    
    if not result:
        return {
            "success": False,
            "message": f"Error al eliminar contraseña para el dominio: {domain}",
            "domain": domain,
        }

    return {
        "success": True,
        "message": f"Contraseña eliminada para el dominio: {domain}",
        "domain": domain,
    }


## SYNCHRONISATION

"""
Te devuelve los dispositivos activos con los que te puedes sincronizar
"""


@app.get("/synchronise")
async def get_devices(api_key: str = Depends(verify_api_key)):
    if not p2p_client:
        return {"error": "Cliente P2P no inicializado"}
    
    active_peers = p2p_client.get_active_peers_list()
    vault_info = p2p_client.get_metadata()
    
    return {
        "device_id": p2p_client.device_id,
        "vault_version": vault_info["version"],
        "vault_hash": vault_info["hash"],
        "active_peers": active_peers,
        "total_peers": len(active_peers)
    }


"""
Realiza la sincronización con un dispositivo específico (peer)

Cuerpo:
{
    "peer_ip": "192.168.1.100",
    "peer_port": 5002
}
"""


@app.post("/synchronise")
async def link_device(sync_req: SyncRequest, api_key: str = Depends(verify_api_key)):
    if not p2p_client:
        return {"error": "Cliente P2P no inicializado"}
    
    try:
        # Iniciar sincronización con el peer
        p2p_client.synchronize_with_peer(sync_req.peer_ip, sync_req.peer_port)
        
        # Obtener info actualizada después de sincronizar
        vault_info = p2p_client.get_metadata()
        vault_data = p2p_client.vault.to_json()
        
        return {
            "success": True,
            "message": f"Sincronización completada con {sync_req.peer_ip}:{sync_req.peer_port}",
            "vault_version": vault_info["version"],
            "vault_hash": vault_info["hash"],
            "vault_entries_count": len(p2p_client.vault.entries)
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Error durante sincronización: {str(e)}"
        }


## BLUETOOTH LOW ENERGY

BLE_DIR = os.path.join(os.path.dirname(__file__), "ble-sync")


@app.post("/ble/receive")
async def ble_receive_start(api_key: str = Depends(verify_api_key)):
    """
    Inicia el servidor BLE (modo recepción) como subproceso.
    El dispositivo se anuncia por Bluetooth y espera que otro envíe contraseñas.
    """
    global ble_server_process

    # Si ya hay uno corriendo, informar
    if ble_server_process and ble_server_process.poll() is None:
        return {
            "success": True,
            "message": "El servidor BLE ya está en ejecución. Esperando conexiones...",
            "already_running": True,
        }

    script = os.path.join(BLE_DIR, "ble-server.py")
    if not os.path.isfile(script):
        return {"success": False, "error": "No se encontró ble-server.py"}

    try:
        ble_server_process = subprocess.Popen(
            [sys.executable, script],
            cwd=BLE_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        return {
            "success": True,
            "message": "Servidor BLE iniciado. Anunciando como 'PasswordVault-BLE'...",
            "pid": ble_server_process.pid,
        }
    except Exception as e:
        return {"success": False, "error": f"Error al iniciar servidor BLE: {str(e)}"}


@app.post("/ble/stop")
async def ble_receive_stop(api_key: str = Depends(verify_api_key)):
    """Detiene el servidor BLE si está corriendo."""
    global ble_server_process

    if ble_server_process and ble_server_process.poll() is None:
        ble_server_process.terminate()
        try:
            ble_server_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            ble_server_process.kill()
        ble_server_process = None
        return {"success": True, "message": "Servidor BLE detenido."}

    ble_server_process = None
    return {"success": True, "message": "No había servidor BLE en ejecución."}


@app.post("/ble/send")
async def ble_send(api_key: str = Depends(verify_api_key)):
    """
    Ejecuta el cliente BLE: escanea un servidor BLE cercano y envía
    todas las contraseñas del vault.
    Se ejecuta de forma síncrona (bloquea hasta que termina) y devuelve el resultado.
    """
    if not p2p_client:
        return {"success": False, "error": "Cliente P2P no inicializado"}

    # Obtener contraseñas actuales del vault
    passwords = p2p_client.get_all_passwords()
    if not passwords:
        return {"success": False, "error": "No hay contraseñas para enviar."}

    # Convertir al formato que espera el cliente BLE
    ble_entries = []
    for pw in passwords:
        ble_entries.append({
            "service": pw["domain"],
            "username": pw["user"],
            "password": pw["password"],
        })

    script = os.path.join(BLE_DIR, "ble-client.py")
    if not os.path.isfile(script):
        return {"success": False, "error": "No se encontró ble-client.py"}

    # Pasar contraseñas al cliente BLE via stdin como JSON
    import json as _json
    payload = _json.dumps(ble_entries)

    try:
        proc = subprocess.run(
            [sys.executable, script, "--stdin"],
            input=payload,
            capture_output=True,
            text=True,
            timeout=120,
            cwd=BLE_DIR,
        )

        if proc.returncode == 0:
            return {
                "success": True,
                "message": f"Contraseñas enviadas por Bluetooth ({len(ble_entries)} entradas).",
                "entries_sent": len(ble_entries),
                "output": proc.stdout[-500:] if proc.stdout else "",
            }
        else:
            return {
                "success": False,
                "error": f"El cliente BLE falló (código {proc.returncode})",
                "output": (proc.stdout or "")[-500:] + (proc.stderr or "")[-500:],
            }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Timeout: no se encontró servidor BLE en 120 segundos."}
    except Exception as e:
        return {"success": False, "error": f"Error ejecutando cliente BLE: {str(e)}"}
