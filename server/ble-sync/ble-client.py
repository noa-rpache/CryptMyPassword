# SPDX-FileCopyrightText: 2026 Noa Rodríguez noa.rpache@gmail.com  Pablo Diz pablo.diz@gmailcom  Hugo Freire hugo.freire@udc.es  Eloy Sastre elhoyyy@gmail.com
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import json
import logging
from datetime import datetime, timezone

from bleak import BleakClient, BleakError, BleakScanner

# ─── UUIDs (must match the server exactly) ────────────────────────────────────
SERVICE_UUID = "12345678-1234-5678-1234-56789abcdef0"
CHAR_RX_UUID = "12345678-1234-5678-1234-56789abcdef1"
CHAR_STATUS_UUID = "12345678-1234-5678-1234-56789abcdef2"

SERVER_NAME = "PasswordVault-BLE"
CHUNK_DELIMITER = b"<<END>>"
DEVICE_ID = "client-laptop-01"


# ─── Robustness Parameters ────────────────────────────────────────────────────
SCAN_TIMEOUT_BASE = 8.0
SCAN_MAX_ATTEMPTS = 4
CONNECT_MAX_RETRIES = 5
CONNECT_BACKOFF_BASE = 1.5
CHUNK_INTER_DELAY = 0.02
CHUNK_RETRY_MAX = 3
STATUS_TIMEOUT = 15.0


# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("BLE-Client")


# FIXME ─── Sample Data (replace in production) ─────────────────────────────────────
SAMPLE_PASSWORDS = [
    {
        "service": "github.com",
        "username": "usuario@email.com",
        "password": "SuperSecreta123!",
        "notes": "Cuenta principal",
    },
    {
        "service": "gmail.com",
        "username": "usuario@gmail.com",
        "password": "OtraContraseña456#",
        "notes": "",
    },
    {
        "service": "netflix.com",
        "username": "perfil_familia",
        "password": "Netflix2024$",
        "notes": "Plan familiar",
    },
    {
        "service": "banco.es",
        "username": "usuario_banco_42",
        "password": "PinBancoSeguro789",
        "notes": "No compartir",
    },
]


# ─── BLE Client ───────────────────────────────────────────────────────────────


class BLEPasswordClient:
    def __init__(self):
        self._status_event = asyncio.Event()
        self._last_status: dict = {}
        self._disconnected = asyncio.Event()

    def _on_disconnect(self, client: BleakClient):
        log.warning(f"Unexpectedly disconnected from {client.address}")
        self._disconnected.set()

    async def find_server(self) -> str | None:
        """
        Multi-step discovery strategy:
          1. Direct name lookup
          2. Full discovery + filter by name or service UUID
          3. Partial name match (case-insensitive)
        """
        for attempt in range(1, SCAN_MAX_ATTEMPTS + 1):
            timeout = SCAN_TIMEOUT_BASE + (attempt - 1) * 4.0
            log.info(
                f"Scanning attempt {attempt}/{SCAN_MAX_ATTEMPTS} "
                f"(timeout={timeout:.0f}s)..."
            )

            try:
                device = await BleakScanner.find_device_by_name(
                    SERVER_NAME, timeout=timeout
                )
                if device:
                    log.info(f"Found (strategy 1): {device.name} [{device.address}]")
                    return device.address
            except BleakError:
                pass

            try:
                devices = await BleakScanner.discover(
                    timeout=timeout,
                    return_adv=True,
                )
                for addr, (dev, adv_data) in devices.items():
                    name = dev.name or ""
                    service_uuids = [str(u).lower() for u in adv_data.service_uuids]

                    if (
                        name == SERVER_NAME
                        or SERVICE_UUID.lower() in service_uuids
                        or SERVER_NAME.lower() in name.lower()
                    ):
                        log.info(f"Found (strategy 2): {name} [{addr}]")
                        return addr

                log.warning(f"Server not found (visible devices: {len(devices)})")
            except BleakError as e:
                log.warning(f"Discovery error: {e}")

            if attempt < SCAN_MAX_ATTEMPTS:
                await asyncio.sleep(2.0 * attempt)

        log.error(
            f"Server '{SERVER_NAME}' not found after {SCAN_MAX_ATTEMPTS} attempts"
        )
        return None

    async def connect_with_retry(self, address: str) -> BleakClient | None:
        for attempt in range(1, CONNECT_MAX_RETRIES + 1):
            log.info(f"Connection attempt {attempt}/{CONNECT_MAX_RETRIES} → {address}")
            try:
                client = BleakClient(
                    address,
                    disconnected_callback=self._on_disconnect,
                    timeout=15.0,
                )
                await client.connect()
                if client.is_connected:
                    log.info(f"Connected (MTU={client.mtu_size} bytes)")
                    return client
            except Exception as e:
                log.warning(f"Connection attempt failed: {e}")

            if attempt < CONNECT_MAX_RETRIES:
                backoff = CONNECT_BACKOFF_BASE * (2 ** (attempt - 1))
                await asyncio.sleep(backoff)

        log.error(f"Could not connect to {address}")
        return None

    def _on_status_notify(self, sender, data: bytearray):
        try:
            self._last_status = json.loads(data.decode("utf-8"))
            log.info(f"Server status: {self._last_status}")
        except Exception:
            log.warning("Failed to parse server status")
        finally:
            self._status_event.set()

    def build_payload(self, passwords: list[dict]) -> bytes:
        payload = {
            "device_id": DEVICE_ID,
            "sent_at": datetime.now(timezone.utc).isoformat(),
            "count": len(passwords),
            "passwords": passwords,
        }
        return json.dumps(payload, ensure_ascii=False).encode("utf-8")

    async def send_chunked(self, client: BleakClient, data: bytes) -> bool:
        effective_mtu = max(20, client.mtu_size - 3)
        chunk_size = min(effective_mtu, 512)

        full_data = data + CHUNK_DELIMITER
        total_chunks = (len(full_data) + chunk_size - 1) // chunk_size

        log.info(f"Sending {len(data)} bytes in {total_chunks} chunk(s)")

        for i in range(0, len(full_data), chunk_size):
            chunk = full_data[i : i + chunk_size]

            if not client.is_connected or self._disconnected.is_set():
                log.error("Connection lost during transfer")
                return False

            sent = False
            for retry in range(CHUNK_RETRY_MAX):
                try:
                    await client.write_gatt_char(
                        CHAR_RX_UUID,
                        chunk,
                        response=False,
                    )
                    sent = True
                    break
                except BleakError:
                    await asyncio.sleep(0.1 * (retry + 1))

            if not sent:
                log.error("Chunk failed after retries")
                return False

            await asyncio.sleep(CHUNK_INTER_DELAY)

        log.info("All chunks sent successfully")
        return True

    async def verify_services(self, client: BleakClient) -> bool:
        try:
            services = client.services
            service = services.get_service(SERVICE_UUID)
            if service is None:
                log.error("Service UUID not found on server")
                return False

            if not service.get_characteristic(
                CHAR_RX_UUID
            ) or not service.get_characteristic(CHAR_STATUS_UUID):
                log.error("Required GATT characteristics not found")
                return False

            log.info("GATT services verified")
            return True
        except Exception as e:
            log.error(f"Service verification error: {e}")
            return False

    async def sync(self, passwords: list[dict] = None):
        if passwords is None:
            passwords = SAMPLE_PASSWORDS

        self._status_event.clear()
        self._disconnected.clear()
        self._last_status = {}

        address = await self.find_server()
        if not address:
            return False

        client = await self.connect_with_retry(address)
        if client is None:
            return False

        try:
            if not await self.verify_services(client):
                return False

            await client.start_notify(CHAR_STATUS_UUID, self._on_status_notify)

            payload = self.build_payload(passwords)
            ok = await self.send_chunked(client, payload)
            if not ok:
                return False

            try:
                done, _ = await asyncio.wait(
                    [
                        asyncio.ensure_future(self._status_event.wait()),
                        asyncio.ensure_future(self._disconnected.wait()),
                    ],
                    timeout=STATUS_TIMEOUT,
                    return_when=asyncio.FIRST_COMPLETED,
                )

                if self._disconnected.is_set():
                    log.error("Server disconnected before confirmation")
                    return False

                if self._status_event.is_set():
                    status = self._last_status
                    if status.get("ok"):
                        log.info("Sync successful")
                        return True
                    else:
                        log.error(f"Server error: {status.get('error')}")
                        return False

                log.warning("Timeout waiting for server response")
                return False

            except Exception as e:
                log.error(f"Unexpected error while waiting for response: {e}")
                return False

        finally:
            try:
                if client.is_connected:
                    await client.stop_notify(CHAR_STATUS_UUID)
                    await client.disconnect()
            except Exception:
                pass

            log.info("Disconnected from BLE server")


# ─── Entry Point ──────────────────────────────────────────────────────────────


async def main():
    log.info("=" * 55)
    log.info("BLE Password Sync — Client")
    log.info("=" * 55)

    GLOBAL_RETRIES = 3
    for attempt in range(1, GLOBAL_RETRIES + 1):
        if attempt > 1:
            log.info(f"Global retry {attempt}/{GLOBAL_RETRIES}")

        ble_client = BLEPasswordClient()
        try:
            success = await ble_client.sync(SAMPLE_PASSWORDS)
            if success:
                break
            if attempt < GLOBAL_RETRIES:
                await asyncio.sleep(5.0)
        except BleakError as e:
            log.error(f"BLE error: {e}")
            if attempt < GLOBAL_RETRIES:
                await asyncio.sleep(5.0)
        except KeyboardInterrupt:
            log.info("Cancelled by user")
            break
    else:
        log.error("Synchronization failed after all global attempts")


if __name__ == "__main__":
    asyncio.run(main())
