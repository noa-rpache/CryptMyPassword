import os
import sys
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic.main import BaseModel
from pymongo import MongoClient

from .auth import API_KEY, verify_api_key

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "gen_password"))
print(f"[*] API_KEY configurada: {API_KEY}")
from entropy_engine import (  # noqa: E402
    _get_mongo_collection,
    is_quantum_worker_alive,
    start_quantum_refresh_worker,
)
from password_manager import check_hibp, generate_secure_password  # noqa: E402

##### MODEL


class FullItem(BaseModel):
    password: str
    user: str
    domain: str


class Device(BaseModel):
    password: str


##### MONGODB CONFIG

MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")

client = MongoClient(MONGO_URL)
db = client["password_manager"]
collection = db["passwords"]

##### API Config


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan: run startup logic before serving requests."""
    start_quantum_refresh_worker()
    print(f"[*] ANU quantum refresh worker alive: {is_quantum_worker_alive()}")
    yield
    # Shutdown: daemon thread dies automatically with the process.


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
    items = []

    for doc in collection.find():
        items.append(
            {"domain": doc["_id"], "user": doc["user"], "password": doc["password"]}
        )

    return items
    # return [{"domain": "test.com", "user": "test", "password": "random"}]


"""
Comprueba todas las contraseñas almacenadas contra la base de datos de Have I Been Pwned.

Devuelve la lista de dominios con contraseñas comprometidas:
    [
        {"domain": "example.com", "user": "test", "breaches": 143},
        ...
    ]
"""


@app.get("/password/audit")
async def audit_passwords(api_key: str = Depends(verify_api_key)):
    results = []

    for doc in collection.find():
        is_pwned, count = check_hibp(doc["password"])
        if is_pwned:
            results.append(
                {
                    "domain": doc["_id"],
                    "user": doc["user"],
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
    doc = collection.find_one({"_id": domain})

    if not doc:
        return None

    return {"user": doc["user"], "password": doc["password"]}
    # return {"user": "test", "password": "random"}


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
    print(f"/password/save {content}")
    collection.update_one(
        {"_id": content.domain},
        {"$set": {"user": content.user, "password": content.password}},
        upsert=True,
    )

    return {
        "domain": content.domain,
        "user": content.user,
        "password": content.password,
    }
    # return {"user": content.user, "password": content.password}


"""
Eliminar una contraseña guardada para un dominio específico.

El parámetro debe ser el dominio a eliminar.

Ejemplo: DELETE /password/www.gmail.com

"""


@app.delete("/password/{domain}")
async def delete_password(domain: str, api_key: str = Depends(verify_api_key)):
    print(f"/password/delete {domain}")

    result = collection.delete_one({"_id": domain})

    if result.deleted_count == 0:
        return {
            "success": False,
            "message": f"No se encontró contraseña para el dominio: {domain}",
            "domain": domain,
        }

    return {
        "success": True,
        "message": f"Contraseña eliminada para el dominio: {domain}",
        "domain": domain,
    }


## SYNCHRONISATION

"""
Te devuelve los dispositivos a los que te puedes sincronizar

"""


@app.get("/synchronise")
async def get_devices(api_key: str = Depends(verify_api_key)):
    return [{"device": "device"}]


"""
Realiza la sincronización con el dispositivo
"""


@app.post("/synchronise")
async def link_device(device: Device, api_key: str = Depends(verify_api_key)):
    return {"password": "test"}
