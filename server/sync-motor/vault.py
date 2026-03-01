# SPDX-FileCopyrightText: 2026 Noa Rodríguez noa.rpache@gmail.com  Pablo Diz pablo.diz.edu@gmail.com  Hugo Freire hugo.freire@udc.es  Eloy Sastre elhoyyy@gmail.com
#
# SPDX-License-Identifier: Apache-2.0

import json
import time
from hashlib import sha256
from typing import List


class VaultEntry:
    def __init__(self, site, user, password, state="activo", timestamp_mod=None):
        self.site = site
        self.user = user
        self.password = password
        self.state = state
        self.timestamp_mod = (
            timestamp_mod if timestamp_mod is not None else int(time.time())
        )

    def to_dict(self):
        return {
            "site": self.site,
            "user": self.user,
            "password": self.password,
            "state": self.state,
            "timestamp_mod": self.timestamp_mod,
        }


class Vault:
    """
    Vault respaldado por MongoDB.
    - El documento en Mongo tiene _id = device_id y contiene version, timestamp y entries.
    - Cada operación lee/escribe directamente en la colección.
    - Si no se pasa mongo_collection, funciona en memoria (modo test/standalone).
    """

    def __init__(self, device_id, mongo_collection=None):
        self.device_id = device_id
        self._collection = mongo_collection

        # Intentar cargar desde Mongo; si no existe, inicializar valores por defecto
        if self._collection is not None:
            doc = self._collection.find_one({"_id": self.device_id})
            if doc:
                self.version = doc.get("version", 0)
                self.timestamp = doc.get("timestamp", int(time.time()))
                # No mantenemos lista local; las entries viven en Mongo
            else:
                self.version = 0
                self.timestamp = int(time.time())
                self._collection.insert_one(
                    {
                        "_id": self.device_id,
                        "version": self.version,
                        "timestamp": self.timestamp,
                        "entries": [],
                    }
                )
        else:
            # Modo sin Mongo (local / test)
            self.version = 0
            self.timestamp = int(time.time())
            self._local_entries: List[VaultEntry] = []

    # ------------------------------------------------------------------
    # Propiedades: entries transparente (Mongo o local)
    # ------------------------------------------------------------------
    @property
    def entries(self) -> List[VaultEntry]:
        if self._collection is not None:
            doc = self._collection.find_one({"_id": self.device_id})
            if doc and "entries" in doc:
                return [VaultEntry(**e) for e in doc["entries"]]
            return []
        return self._local_entries

    @entries.setter
    def entries(self, value: List[VaultEntry]):
        if self._collection is not None:
            entries_dicts = [
                e.to_dict() if isinstance(e, VaultEntry) else e for e in value
            ]
            self._collection.update_one(
                {"_id": self.device_id}, {"$set": {"entries": entries_dicts}}
            )
        else:
            self._local_entries = value

    # ------------------------------------------------------------------
    # Operaciones
    # ------------------------------------------------------------------
    def add_entry(self, entry: VaultEntry):
        if self._collection is not None:
            self._collection.update_one(
                {"_id": self.device_id}, {"$push": {"entries": entry.to_dict()}}
            )
        else:
            self._local_entries.append(entry)
        self.version += 1
        self.timestamp = int(time.time())
        self._sync_metadata()

    def update_entry(self, site: str, user: str, updates: dict):
        """Actualiza campos de una entrada específica en Mongo o local."""
        if self._collection is not None:
            set_fields = {f"entries.$.{k}": v for k, v in updates.items()}
            self._collection.update_one(
                {"_id": self.device_id, "entries.site": site, "entries.user": user},
                {"$set": set_fields},
            )
        else:
            for e in self._local_entries:
                if e.site == site and e.user == user:
                    for k, v in updates.items():
                        setattr(e, k, v)
                    break

    def get_entry(self, site: str, user: str):
        """Busca una entrada por site + user."""
        for e in self.entries:
            if e.site == site and e.user == user:
                return e
        return None

    def get_all_active_entries(self) -> List[VaultEntry]:
        """Devuelve solo las entries con estado 'activo'."""
        return [e for e in self.entries if e.state == "activo"]

    def _sync_metadata(self):
        """Sincroniza version y timestamp en Mongo."""
        if self._collection is not None:
            self._collection.update_one(
                {"_id": self.device_id},
                {"$set": {"version": self.version, "timestamp": self.timestamp}},
            )

    def to_json(self):
        return json.dumps(
            {
                "device_id": self.device_id,
                "version": self.version,
                "timestamp": self.timestamp,
                "entries": [e.to_dict() for e in self.entries],
            }
        )

    def hash(self):
        """Hash basado SOLO en version + entries (sin device_id) para consistencia entre dispositivos"""
        sorted_entries = sorted(
            [e.to_dict() for e in self.entries], key=lambda x: (x["site"], x["user"])
        )
        vault_content = json.dumps({"version": self.version, "entries": sorted_entries})
        return sha256(vault_content.encode()).hexdigest()
