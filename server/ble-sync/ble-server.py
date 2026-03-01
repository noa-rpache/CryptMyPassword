# SPDX-FileCopyrightText: 2026 Noa Rodríguez noa.rpache@gmail.com  Pablo Diz pablo.diz@gmailcom  Hugo Freire hugo.freire@udc.es  Eloy Sastre elhoyyy@gmail.com
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

import aiohttp
from bleak import BleakError
from bleak.backends.characteristic import BleakGATTCharacteristic
from bless import (
    BlessGATTCharacteristic,
    BlessServer,
    GATTAttributePermissions,
    GATTCharacteristicProperties,
)
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

# ─── Configuration ────────────────────────────────────────────────────────────

API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
API_KEY = os.getenv("API_KEY", "default-api-key-change-in-production")

# Custom BLE UUIDs
SERVICE_UUID = "12345678-1234-5678-1234-56789abcdef0"
CHAR_RX_UUID = "12345678-1234-5678-1234-56789abcdef1"
CHAR_STATUS_UUID = "12345678-1234-5678-1234-56789abcdef2"

CHUNK_DELIMITER = b"<<END>>"


# ─── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("BLE-Server")


# ─── API Helper ───────────────────────────────────────────────────────────────


class PasswordAPIClient:
    """Sends received passwords to the FastAPI /password/save endpoint."""

    def __init__(self):
        self.url = f"{API_BASE_URL}/password/save"
        self.headers = {
            "X-API-Key": API_KEY,
            "Content-Type": "application/json",
        }
        self._session: aiohttp.ClientSession | None = None

    async def open(self):
        self._session = aiohttp.ClientSession()
        log.info(f"API client ready → {self.url}")

    async def save_passwords(self, entries: list[dict]) -> dict:
        """
        Send each entry to POST /password/save.
        Expected entry fields: service (→ domain), username (→ user), password.
        """
        saved, errors = 0, 0

        for entry in entries:
            if not all(k in entry for k in ("service", "username", "password")):
                log.warning(f"Invalid entry (missing fields): {entry}")
                errors += 1
                continue

            body = {
                "domain": entry["service"].strip().lower(),
                "user": entry["username"].strip(),
                "password": entry["password"],
            }

            try:
                async with self._session.post(
                    self.url, json=body, headers=self.headers
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        saved += 1
                        log.info(f"Saved via API: {data['domain']} / {data['user']}")
                    else:
                        text = await resp.text()
                        log.error(
                            f"API error {resp.status} for {body['domain']}: {text}"
                        )
                        errors += 1
            except Exception as e:
                log.error(f"Request failed for {body['domain']}: {e}")
                errors += 1

        return {"saved": saved, "errors": errors}

    async def close(self):
        if self._session:
            await self._session.close()


# ─── BLE Server ───────────────────────────────────────────────────────────────


class BLEPasswordServer:
    def __init__(self):
        self.api_client = PasswordAPIClient()
        self.server: BlessServer = None
        self._buffer = bytearray()
        self._loop = None

    # Called whenever the client writes to RX characteristic
    def on_write(
        self, characteristic: BlessGATTCharacteristic, value: bytearray, **kwargs
    ):
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
            sender = payload.get("device_id", "unknown")

            result = await self.api_client.save_passwords(entries)
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
        await self.api_client.open()

        self.server = BlessServer(name="PasswordVault-BLE", loop=self._loop)
        self.server.read_request_func = None
        self.server.write_request_func = self.on_write

        await self.server.add_new_service(SERVICE_UUID)

        await self.server.add_new_characteristic(
            SERVICE_UUID,
            CHAR_RX_UUID,
            GATTCharacteristicProperties.write
            | GATTCharacteristicProperties.write_without_response,
            None,
            GATTAttributePermissions.writeable,
        )

        await self.server.add_new_characteristic(
            SERVICE_UUID,
            CHAR_STATUS_UUID,
            GATTCharacteristicProperties.notify | GATTCharacteristicProperties.read,
            None,
            GATTAttributePermissions.readable,
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
            await self.api_client.close()
            log.info("Server stopped cleanly.")


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    server = BLEPasswordServer()
    try:
        asyncio.run(server.start())
    except BleakError as e:
        log.error(f"Bluetooth error: {e}")
        log.error("Make sure the BLE adapter is enabled: sudo hciconfig hci0 up")
