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
