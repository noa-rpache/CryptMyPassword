import asyncio
import json
import logging
from datetime import datetime, timezone
 
from bleak import BleakError
from bleak.backends.characteristic import BleakGATTCharacteristic
from bless import BlessServer, BlessGATTCharacteristic, GATTCharacteristicProperties, GATTAttributePermissions
from pymongo import MongoClient, errors as mongo_errors
 
 
# ─── Configuration ────────────────────────────────────────────────────────────
 
MONGO_URI        = "mongodb://user:password@localhost:27017/?directConnection=true&authSource=admin"
MONGO_DB         = "password_manager"
MONGO_COLLECTION = "passwords"
 
# Custom BLE UUIDs (generate your own if needed)
SERVICE_UUID     = "12345678-1234-5678-1234-56789abcdef0"
CHAR_RX_UUID     = "12345678-1234-5678-1234-56789abcdef1"
CHAR_STATUS_UUID = "12345678-1234-5678-1234-56789abcdef2"
 
CHUNK_DELIMITER = b"<<END>>"
 
 
# ─── Logging ──────────────────────────────────────────────────────────────────
 
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("BLE-Server")
 
 
# ─── MongoDB Helper ───────────────────────────────────────────────────────────
 
class PasswordStore:
    def __init__(self):
        self.client = None
        self.collection = None
 
    def connect(self):
        try:
            self.client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
            self.client.admin.command("ping")  # Verify connection
            db = self.client[MONGO_DB]
            self.collection = db[MONGO_COLLECTION]
 
            # Unique index on (service, username)
            self.collection.create_index(
                [("service", 1), ("username", 1)],
                unique=True,
                name="service_username_unique"
            )
 
            log.info(f"MongoDB connected → {MONGO_DB}.{MONGO_COLLECTION}")
 
        except mongo_errors.ServerSelectionTimeoutError as e:
            log.error(f"Could not connect to MongoDB: {e}")
            raise
 
    def upsert_passwords(self, entries: list[dict]) -> dict:
        """
        Insert or update password entries.
        Required fields: service, username, password
        """
        inserted, updated, errors = 0, 0, 0
 
        for entry in entries:
            if not all(k in entry for k in ("service", "username", "password")):
                log.warning(f"Invalid entry (missing fields): {entry}")
                errors += 1
                continue
 
            doc = {
                "service":    entry["service"].strip().lower(),
                "username":   entry["username"].strip(),
                "password":   entry["password"],
                "notes":      entry.get("notes", ""),
                "updated_at": datetime.now(timezone.utc),
            }
 
            try:
                result = self.collection.update_one(
                    filter={"service": doc["service"], "username": doc["username"]},
                    update={
                        "$set": doc,
                        "$setOnInsert": {"created_at": datetime.now(timezone.utc)}
                    },
                    upsert=True
                )
 
                if result.upserted_id:
                    inserted += 1
                    log.info(f"Inserted: {doc['service']} / {doc['username']}")
                else:
                    updated += 1
                    log.info(f"Updated: {doc['service']} / {doc['username']}")
 
            except mongo_errors.DuplicateKeyError:
                errors += 1
            except Exception as e:
                log.error(f"Error saving {entry}: {e}")
                errors += 1
 
        return {"inserted": inserted, "updated": updated, "errors": errors}
 
    def close(self):
        if self.client:
            self.client.close()
 
 
# ─── BLE Server ───────────────────────────────────────────────────────────────
 
class BLEPasswordServer:
    def __init__(self):
        self.store = PasswordStore()
        self.server: BlessServer = None
        self._buffer = bytearray()
        self._loop = None
 
    # Called whenever the client writes to RX characteristic
    def on_write(self, characteristic: BlessGATTCharacteristic, value: bytearray, **kwargs):
        self._buffer.extend(value)
 
        if CHUNK_DELIMITER in self._buffer:
            raw, remainder = self._buffer.split(CHUNK_DELIMITER, 1)
            self._buffer = bytearray(remainder)
            self._loop.create_task(self._process_payload(bytes(raw)))
 
    async def _process_payload(self, raw: bytes):
        log.info(f"Full payload received ({len(raw)} bytes)")
        status_msg = {}
 
        try:
            payload = json.loads(raw.decode("utf-8"))
            entries = payload.get("passwords", [])
            sender  = payload.get("device_id", "unknown")
 
            result = self.store.upsert_passwords(entries)
            status_msg = {"ok": True, "sender": sender, **result}
 
        except json.JSONDecodeError:
            log.error("Invalid JSON received")
            status_msg = {"ok": False, "error": "invalid_json"}
        except Exception as e:
            log.error(f"Processing error: {e}")
            status_msg = {"ok": False, "error": str(e)}
 
        await self._notify_status(status_msg)
 
    async def _notify_status(self, msg: dict):
        try:
            data = json.dumps(msg).encode("utf-8")
            char = self.server.get_characteristic(CHAR_STATUS_UUID)
            char.value = data
            self.server.update_value(SERVICE_UUID, CHAR_STATUS_UUID)
            log.info(f"Status sent to client: {msg}")
        except Exception as e:
            log.warning(f"Could not notify status: {e}")
 
    async def start(self):
        self._loop = asyncio.get_running_loop()
        self.store.connect()
 
        self.server = BlessServer(name="PasswordVault-BLE", loop=self._loop)
        self.server.read_request_func  = None
        self.server.write_request_func = self.on_write
 
        await self.server.add_new_service(SERVICE_UUID)
 
        await self.server.add_new_characteristic(
            SERVICE_UUID,
            CHAR_RX_UUID,
            GATTCharacteristicProperties.write | GATTCharacteristicProperties.write_without_response,
            None,
            GATTAttributePermissions.writeable
        )
 
        await self.server.add_new_characteristic(
            SERVICE_UUID,
            CHAR_STATUS_UUID,
            GATTCharacteristicProperties.notify | GATTCharacteristicProperties.read,
            None,
            GATTAttributePermissions.readable
        )
 
        await self.server.start()
        log.info("BLE Server started → advertising as 'PasswordVault-BLE'")
        log.info("Waiting for connections... (Ctrl+C to exit)")
 
        try:
            await asyncio.Event().wait()
        except (KeyboardInterrupt, asyncio.CancelledError):
            log.info("Stopping server...")
        finally:
            await self.server.stop()
            self.store.close()
            log.info("Server stopped cleanly.")
 
 
# ─── Entry Point ──────────────────────────────────────────────────────────────
 
if __name__ == "__main__":
    server = BLEPasswordServer()
    try:
        asyncio.run(server.start())
    except BleakError as e:
        log.error(f"Bluetooth error: {e}")
        log.error("Make sure the BLE adapter is enabled: sudo hciconfig hci0 up")