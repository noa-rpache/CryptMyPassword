

import asyncio
import json
import logging
from datetime import datetime, timezone

import aiohttp
from bleak import BleakError
from bleak.backends.characteristic import BleakGATTCharacteristic
from bless import BlessServer, BlessGATTCharacteristic, GATTCharacteristicProperties, GATTAttributePermissions


# ─── Configuration ────────────────────────────────────────────────────────────

API_URL = "http://127.0.0.1:8000"
API_KEY = "my_secret_api_key"

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


# ─── API Helper ───────────────────────────────────────────────────────────────

class PasswordAPI:
    """Saves passwords by calling POST /password/save on the main FastAPI server."""

    def __init__(self, base_url: str = API_URL, api_key: str = API_KEY):
        self.base_url = base_url
        self.headers = {
            "X-API-Key": api_key,
            "Content-Type": "application/json",
        }
        self._session: aiohttp.ClientSession | None = None

    async def open(self):
        self._session = aiohttp.ClientSession(
            base_url=self.base_url,
            headers=self.headers,
            timeout=aiohttp.ClientTimeout(total=10),
        )
        # Quick health check
        try:
            async with self._session.get("/password") as resp:
                if resp.status == 200:
                    log.info(f"API reachable at {self.base_url}")
                else:
                    log.warning(f"API returned {resp.status} on health check")
        except Exception as e:
            log.error(f"Cannot reach API at {self.base_url}: {e}")
            raise

    async def save_password(self, domain: str, user: str, password: str) -> dict:
        """POST /password/save  →  {domain, user, password}"""
        body = {"domain": domain, "user": user, "password": password}
        async with self._session.post("/password/save", json=body) as resp:
            data = await resp.json()
            if resp.status == 200:
                log.info(f"Saved via API: {domain} / {user}")
                return {"ok": True, **data}
            else:
                log.error(f"API error {resp.status}: {data}")
                return {"ok": False, "status": resp.status, "detail": data}

    async def save_batch(self, entries: list[dict]) -> dict:
        """Save a list of entries. Each entry must have service/username/password."""
        saved, errors = 0, 0
        for entry in entries:
            domain   = entry.get("service", entry.get("domain", "")).strip().lower()
            user     = entry.get("username", entry.get("user", "")).strip()
            password = entry.get("password", "")

            if not domain or not user or not password:
                log.warning(f"Skipping invalid entry (missing fields): {entry}")
                errors += 1
                continue

            try:
                result = await self.save_password(domain, user, password)
                if result.get("ok"):
                    saved += 1
                else:
                    errors += 1
            except Exception as e:
                log.error(f"Error saving {domain}/{user}: {e}")
                errors += 1

        return {"saved": saved, "errors": errors}

    async def close(self):
        if self._session:
            await self._session.close()


# ─── BLE Server ───────────────────────────────────────────────────────────────

class BLEPasswordServer:
    def __init__(self):
        self.api = PasswordAPI()
        self.server: BlessServer = None
        self._buffer = bytearray()
        self._loop = None  # Set in start()

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

            result = await self.api.save_batch(entries)
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
        await self.api.open()

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
            await self.api.close()
            log.info("Server stopped cleanly.")


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    server = BLEPasswordServer()
    try:
        asyncio.run(server.start())
    except BleakError as e:
        log.error(f"Bluetooth error: {e}")
        log.error("Make sure the BLE adapter is enabled: sudo hciconfig hci0 up")