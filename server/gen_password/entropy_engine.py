# SPDX-FileCopyrightText: 2026 Noa Rodríguez noa.rpache@gmail.com  Pablo Diz pablo.diz@gmailcom  Hugo Freire hugo.freire@udc.es  Eloy Sastre elhoyyy@gmail.com
#
# SPDX-License-Identifier: Apache-2.0

# -*- coding: utf-8 -*-
"""
entropy_engine.py
=================

Cryptographic entropy primitives for the secure password generator.

Purpose:
    This module is responsible for gathering high-quality entropy from three
    independent sources, mixing them into a single Input Key Material (IKM)
    buffer, deriving uniform Output Key Material (OKM) via HKDF-SHA256, and
    exposing the OKM as a consumable bitstream that drives Lemire's unbiased
    index selection.

Cryptographic primitives used:
    - os.urandom        : kernel CSPRNG (/dev/urandom on Linux, CryptGenRandom
                          on Windows). Entropy source 1.
    - ANU QRNG API      : hardware quantum random number generator operated by
                          the Australian National University. Entropy source 2.
                          Pool of 1024 bytes is cached on disk for 12 hours to
                          respect the service's rate limit.
    - Random.org API    : atmospheric-noise RNG. Entropy source 3.
    - HKDF-SHA256       : RFC 5869 key derivation. Mixes the three sources into
                          a uniform, bias-free OKM before any character mapping.
    - Lemire (2019)     : "Nearly Divisionless Random Integer Generation On
                          Various Sizes". Unbiased 64-bit word → index mapping
                          driven by the OKM bitstream.

Security notes:
    - Sensitive mutable buffers (IKM, OKM) are represented as ``bytearray``
      so that ``secure_zero`` can overwrite them in-place after use.  Plain
      ``bytes`` objects are immutable and cannot be reliably zeroed in CPython
      because the interpreter may hold additional references internally.
    - The quantum entropy cache is stored as a hex-encoded JSON file.  The
      file is not encrypted; treat it with the same care as any secret seed.

Public API:
    OKMStream
        Wraps an OKM bytearray as a readable 8-byte-word stream.  Transparently
        falls back to ``secrets.token_bytes`` when the OKM is exhausted.

    get_unbiased_index(n, stream)
        Daniel Lemire's nearly divisionless algorithm.  Returns an integer in
        [0, n) by consuming 8-byte words from *stream*.

    collect_ikm() -> bytearray
        Concatenate 32 bytes from each of the three entropy sources into a
        96-byte IKM bytearray.

    derive_okm(ikm, length) -> bytearray
        HKDF-SHA256 derivation.  Returns *length* bytes of uniform OKM.

    secure_zero(buf)
        Overwrite a bytearray in-place with null bytes.
"""

import io
import os
import secrets
import threading
import time

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pymongo import MongoClient

# ---------------------------------------------------------------------------
# Debug configuration
# ---------------------------------------------------------------------------

DEBUG: bool = os.getenv("DEBUG", "false").lower() in ("1", "true", "yes")
"""Controlled via the DEBUG environment variable. Set to '1', 'true' or 'yes' to enable."""


def dbg(msg: str) -> None:
    """Emit a debug-prefixed message with timestamp when DEBUG is True.

    Args:
        msg: Human-readable message to print.
    """
    if DEBUG:
        ts = time.strftime("%H:%M:%S", time.localtime())
        print(f"[DEBUG {ts}] {msg}")


# ---------------------------------------------------------------------------
# Memory hygiene
# ---------------------------------------------------------------------------


def secure_zero(buf: bytearray) -> None:
    """Overwrite *buf* in-place with null bytes to limit sensitive data lifetime.

    Note:
        This works reliably only for ``bytearray`` objects.  Immutable ``bytes``
        instances cannot be zeroed because CPython may keep internal copies.
        Callers should prefer ``bytearray`` for IKM and OKM buffers throughout
        the pipeline.

    Args:
        buf: Mutable byte buffer to wipe.
    """
    for i in range(len(buf)):
        buf[i] = 0


# ---------------------------------------------------------------------------
# OKM bitstream
# ---------------------------------------------------------------------------


class OKMStream:
    """Deterministic 64-bit-word stream backed by OKM, with secrets fallback.

    Wraps the OKM bytearray as a ``BytesIO`` buffer.  Each call to
    ``read_word`` consumes 8 bytes (64 bits).  When the buffer is exhausted
    the stream falls back to ``secrets.token_bytes`` so that Lemire's
    rejection loop never stalls even if the OKM is shorter than required.

    Attributes:
        _buf (io.BytesIO): Internal byte buffer backed by the OKM.
        _fallback_count (int): Number of times the secrets fallback was used.

    Example:
        >>> stream = OKMStream(okm_bytearray)
        >>> x = stream.read_word()   # int, 64-bit
    """

    def __init__(self, okm: bytearray) -> None:
        """Initialise the stream from an OKM bytearray.

        Args:
            okm: Output Key Material produced by ``derive_okm``.  The stream
                 does **not** own this buffer; the caller is responsible for
                 calling ``secure_zero`` on it afterwards.
        """
        # Copy into BytesIO so reads don't mutate the caller's buffer
        self._buf = io.BytesIO(bytes(okm))
        self._fallback_count: int = 0

    def read_word(self) -> int:
        """Return the next 64-bit unsigned integer from the stream.

        Reads 8 bytes from the OKM buffer and interprets them as a big-endian
        unsigned integer.  If fewer than 8 bytes remain, the missing bytes are
        sourced from ``secrets.token_bytes``.

        Returns:
            A 64-bit unsigned integer.
        """
        raw = self._buf.read(8)
        if len(raw) < 8:
            self._fallback_count += 1
            padding = secrets.token_bytes(8 - len(raw))
            raw = raw + padding
            dbg(
                f"OKMStream: OKM exhausted, fallback #{self._fallback_count} to secrets"
            )
        return int.from_bytes(raw, "big")


# ---------------------------------------------------------------------------
# Lemire's nearly divisionless unbiased index algorithm
# ---------------------------------------------------------------------------


def get_unbiased_index(n: int, stream: OKMStream) -> int:
    """Return an unbiased random integer in [0, n) using Lemire's algorithm.

    Implements the "nearly divisionless" rejection-sampling technique
    described by Daniel Lemire (2019) to eliminate the modulo bias that
    appears when using ``random_value % n``.  Randomness is consumed from
    *stream* so the full entropy pipeline (IKM → HKDF → OKM) drives the
    character selection.

    Algorithm:
        1. Draw a 64-bit word *x* from *stream*.
        2. Compute the 128-bit product ``m = x * n``.
        3. The candidate index is ``m >> 64`` (high 64 bits).
        4. The low 64 bits ``m & MASK`` form the "leftover" value.
        5. Fast path: if leftover >= n, the index is unbiased → return it.
        6. Slow path: leftover < n.  Compute threshold ``(2^64) % n``.
           If leftover >= threshold, the index is still unbiased → return.
           Otherwise discard and retry with a fresh word from *stream*.

    Args:
        n:      Exclusive upper bound.  Must be a positive integer.
        stream: ``OKMStream`` instance supplying 64-bit words.

    Returns:
        An unbiased integer in [0, n).
    """
    while True:
        x = stream.read_word()
        m = x * n
        m_low = m & 0xFFFFFFFFFFFFFFFF

        # Fast path: leftover >= n guarantees no bias
        if m_low >= n:
            return m >> 64

        # Slow path: check against the rejection threshold
        threshold = (1 << 64) % n
        if m_low >= threshold:
            return m >> 64
        # m_low < threshold → bias zone; discard this word and retry


# ---------------------------------------------------------------------------
# Quantum entropy MongoDB cache.
# ---------------------------------------------------------------------------

_QUANTUM_CACHE_DURATION: int = 12 * 3600  # 12 hours in seconds
_MONGO_DOC_ID: str = "quantum_pool"


def _get_mongo_collection():
    """Return the MongoDB collection used to store the quantum entropy pool.

    Connects using the same ``MONGO_URL`` environment variable as the rest of
    the server (defaults to ``mongodb://localhost:27017``).

    Returns:
        A ``pymongo.collection.Collection`` object.
    """
    url = os.getenv("MONGO_URL", "mongodb://localhost:27017")
    client = MongoClient(url)
    return client["password_manager"]["quantum_entropy_cache"]


def _load_quantum_cache() -> tuple[bytes, float]:
    """Load the quantum entropy pool from MongoDB.

    Returns:
        A (pool_bytes, unix_timestamp) tuple.  Both fields are empty / zero
        when no document exists or the read fails.
    """
    dbg("_load_quantum_cache: querying MongoDB...")
    try:
        doc = _get_mongo_collection().find_one({"_id": _MONGO_DOC_ID})
        if doc:
            pool = bytes.fromhex(doc["entropy"])
            timestamp = float(doc["timestamp"])
            age_min = (time.time() - timestamp) / 60
            dbg(
                f"_load_quantum_cache: found — {len(pool)} bytes, age {age_min:.1f} min"
            )
            return pool, timestamp
        dbg("_load_quantum_cache: no document found")
    except Exception as exc:
        print(f"[*] Could not read quantum cache from MongoDB: {exc}")
    return b"", 0.0


def _save_quantum_cache(pool: bytes) -> None:
    """Persist the quantum entropy pool to MongoDB.

    Uses ``update_one`` with ``upsert=True``, which is an atomic operation
    on a single document — the reader always sees either the old complete
    document or the new one.

    Args:
        pool: Raw entropy bytes to store.
    """
    dbg(f"_save_quantum_cache: upserting {len(pool)} bytes into MongoDB")
    try:
        _get_mongo_collection().update_one(
            {"_id": _MONGO_DOC_ID},
            {"$set": {"entropy": pool.hex(), "timestamp": time.time()}},
            upsert=True,
        )
        dbg("_save_quantum_cache: upsert complete")
    except Exception as exc:
        print(f"[*] Could not save quantum cache to MongoDB: {exc}")


# ---------------------------------------------------------------------------
# Background ANU cache refresh worker
# ---------------------------------------------------------------------------

_QUANTUM_REFRESH_INTERVAL: int = 15 * 60  # seconds between successful refreshes
_QUANTUM_RETRY_INTERVAL: int = 90  # seconds to wait after a failed fetch
"""How often the background worker tries to fetch a fresh pool from ANU."""

_worker_lock: threading.Lock = threading.Lock()
_worker_thread: threading.Thread | None = None


def _fetch_anu_pool() -> bytes | None:
    """Fetch a fresh 1024-byte quantum entropy pool from the ANU QRNG API.

    Separated from ``get_entropy_2`` so the background worker can call it
    without touching the cache read/write logic.

    Returns:
        Raw pool bytes on success, or ``None`` if the request failed or the
        API responded with a non-JSON body (rate-limit indicator).
    """
    dbg("_fetch_anu_pool: contacting ANU QRNG...")
    try:
        t0 = time.time()
        response = requests.get(
            "https://qrng.anu.edu.au/API/jsonI.php?length=1024&type=uint8",
            timeout=10,
            headers={"User-Agent": "HackUDC26-PasswordGen/1.0"},
        )
        elapsed = time.time() - t0
        dbg(
            f"_fetch_anu_pool: HTTP {response.status_code}, "
            f"{len(response.content)} bytes, {elapsed:.2f} s"
        )

        if response.status_code != 200:
            print(f"[*] ANU QRNG returned HTTP {response.status_code}.")
            return None

        try:
            payload = response.json()
        except ValueError:
            print(
                f"[*] ANU QRNG HTTP 200 but NOT JSON "
                f"(likely rate-limited): {response.text[:120]!r}"
            )
            return None

        if payload.get("success") and "data" in payload:
            pool = bytes(payload["data"])
            dbg(f"_fetch_anu_pool: OK — {len(pool)} bytes")
            return pool

        print(f"[*] ANU QRNG: unexpected payload structure: {payload}")
        return None

    except requests.Timeout:
        print("[*] ANU QRNG request timed out.")
    except requests.RequestException as exc:
        print(f"[*] Network error fetching ANU quantum entropy: {exc}")
    return None


def _quantum_refresh_loop() -> None:
    """Target function for the background ANU cache refresh daemon thread.

    Behaviour:
        - On startup, immediately fetches a fresh pool if the current cache is
          absent or older than ``_QUANTUM_REFRESH_INTERVAL``.
        - On success: sleeps ``_QUANTUM_REFRESH_INTERVAL`` (15 min) before
          the next fetch.
        - On failure: sleeps ``_QUANTUM_RETRY_INTERVAL`` (90 s) and retries,
          rather than waiting the full 15 minutes.
        - Runs as a daemon thread, so it is killed automatically when the main
          process exits.
        - Never writes to the cache directly; always uses ``_save_quantum_cache``.
    """
    dbg("quantum_refresh_loop: worker started")

    # Fetch immediately if the cache is missing or stale on first entry
    _, cached_time = _load_quantum_cache()
    if (time.time() - cached_time) >= _QUANTUM_REFRESH_INTERVAL:
        dbg("quantum_refresh_loop: initial fetch (cache absent or stale)")
        pool = _fetch_anu_pool()
        if pool:
            _save_quantum_cache(pool)

    while True:
        time.sleep(_QUANTUM_REFRESH_INTERVAL)
        dbg("quantum_refresh_loop: scheduled refresh — fetching new pool")
        pool = _fetch_anu_pool()
        if pool:
            _save_quantum_cache(pool)
        else:
            # Short retry loop: keep trying every 90 s until success,
            # then resume the normal 15-minute cadence.
            dbg(
                f"quantum_refresh_loop: fetch failed; "
                f"retrying every {_QUANTUM_RETRY_INTERVAL} s until success"
            )
            while True:
                time.sleep(_QUANTUM_RETRY_INTERVAL)
                dbg("quantum_refresh_loop: retry attempt")
                pool = _fetch_anu_pool()
                if pool:
                    _save_quantum_cache(pool)
                    dbg(
                        "quantum_refresh_loop: retry succeeded; resuming normal cadence"
                    )
                    break
                dbg("quantum_refresh_loop: retry failed; will try again")


def start_quantum_refresh_worker() -> None:
    """Start the background ANU quantum cache refresh thread (idempotent).

    Safe to call multiple times; only one worker thread is ever running.
    The thread is a daemon so it does not prevent process exit.
    """
    global _worker_thread
    with _worker_lock:
        if _worker_thread is not None and _worker_thread.is_alive():
            dbg("start_quantum_refresh_worker: worker already running")
            return
        _worker_thread = threading.Thread(
            target=_quantum_refresh_loop,
            name="anu-cache-refresher",
            daemon=True,
        )
        _worker_thread.start()
        dbg("start_quantum_refresh_worker: worker thread started")


def is_quantum_worker_alive() -> bool:
    """Return True if the background ANU cache refresh thread is running.

    Useful for server health checks and startup diagnostics.

    Returns:
        True if the daemon thread exists and is alive, False otherwise.
    """
    return _worker_thread is not None and _worker_thread.is_alive()


# ---------------------------------------------------------------------------
# Entropy source 1 — local OS CSPRNG
# ---------------------------------------------------------------------------


def get_entropy_1() -> bytes:
    """Return 32 bytes of local OS entropy via os.urandom.

    Reads from the kernel CSPRNG (``/dev/urandom`` on Linux).  Always
    succeeds and requires no network access.

    Returns:
        32 cryptographically random bytes.
    """
    dbg("get_entropy_1: fetching 32 bytes from os.urandom...")
    entropy = os.urandom(32)
    dbg(f"get_entropy_1: OK — {entropy.hex()[:16]}...")
    return entropy


# ---------------------------------------------------------------------------
# Entropy source 2 — ANU Quantum Random Number Generator
# ---------------------------------------------------------------------------


def get_entropy_2() -> bytes:
    """Return 32 bytes drawn from a quantum entropy pool (ANU QRNG API).

    Normal path (fast):
        Reads a random 32-byte slice from the on-disk cache, which is kept
        fresh by the background worker thread started at module import time.
        The worker refreshes the pool every ``_QUANTUM_REFRESH_INTERVAL``
        seconds (default 15 min) in the background, so this function never
        blocks on a network call during normal operation.

    Slow path (first ever run, or if cache disappeared):
        The background worker may not have had time to populate the cache yet.
        In that case the function calls ``_fetch_anu_pool()`` synchronously
        once, saves the result, and returns a slice.  This is the only
        scenario where the caller waits on a network round-trip.

    Fallback chain:
        1. Expired on-disk cache (random 32-byte slice) — still better than
           nothing and will be refreshed by the worker shortly.
        2. ``os.urandom(32)`` if no cache exists at all.

    Returns:
        32 bytes of quantum (or fallback) entropy.
    """
    dbg("get_entropy_2: starting ANU quantum entropy fetch...")
    cached_pool, cached_time = _load_quantum_cache()

    # Normal path: fresh cache — draw a random 32-byte slice
    if cached_pool and (time.time() - cached_time) < _QUANTUM_CACHE_DURATION:
        pool_size = len(cached_pool)
        offset = int.from_bytes(os.urandom(4), "big") % (pool_size - 31)
        dbg(f"get_entropy_2: cache hit — pool {pool_size} bytes, offset {offset}")
        return cached_pool[offset : offset + 32]

    # Slow path: no usable cache — fetch synchronously once
    dbg("get_entropy_2: no valid cache; fetching synchronously (first run)...")
    pool = _fetch_anu_pool()
    if pool:
        _save_quantum_cache(pool)
        offset = int.from_bytes(os.urandom(4), "big") % (len(pool) - 31)
        dbg(f"get_entropy_2: synchronous fetch OK — offset {offset}")
        return pool[offset : offset + 32]

    # Fallback 1 — expired cache is still better than pure CSPRNG
    if cached_pool:
        print("[*] Using expired quantum cache as fallback.")
        offset = int.from_bytes(os.urandom(4), "big") % (len(cached_pool) - 31)
        dbg(f"get_entropy_2: expired cache fallback — offset {offset}")
        return cached_pool[offset : offset + 32]

    # Fallback 2 — local CSPRNG
    print("[*] No quantum entropy available; falling back to os.urandom.")
    return os.urandom(32)


# ---------------------------------------------------------------------------
# Entropy source 3 — Random.org (atmospheric noise)
# ---------------------------------------------------------------------------


def get_entropy_3() -> bytes:
    """Return 32 bytes of atmospheric entropy from the Random.org API.

    The ``format=h`` endpoint returns space- and newline-separated hex bytes
    which are stripped before parsing.

    Fallback:
        ``os.urandom(32)`` when the request fails or the response body cannot
        be decoded as hex.

    Returns:
        32 bytes of atmospheric (or fallback) entropy.
    """
    dbg("get_entropy_3: sending request to Random.org...")
    try:
        t0 = time.time()
        response = requests.get(
            "https://www.random.org/cgi-bin/randbyte?nbytes=32&format=h",
            timeout=1.5,
            headers={"User-Agent": "HackUDC26-PasswordGen/1.0"},
        )
        elapsed = time.time() - t0
        dbg(
            f"get_entropy_3: Random.org response — HTTP {response.status_code}, "
            f"{len(response.content)} bytes, {elapsed:.2f} s"
        )
        dbg(f"get_entropy_3: raw body: {response.text[:80]!r}")

        if response.status_code != 200:
            print(f"[*] Random.org returned HTTP {response.status_code}.")
        else:
            # Strip spaces and newlines before hex-decoding
            hex_clean = response.text.strip().replace(" ", "").replace("\n", "")
            dbg(
                f"get_entropy_3: cleaned hex ({len(hex_clean)} chars): {hex_clean[:32]}..."
            )
            try:
                entropy = bytes.fromhex(hex_clean)
                dbg(f"get_entropy_3: OK — {len(entropy)} bytes obtained")
                return entropy
            except ValueError as exc:
                print(
                    f"[*] Random.org: could not parse hex response: {exc}. "
                    f"Body: {response.text[:80]!r}"
                )

    except requests.Timeout:
        print("[*] Random.org request timed out.")
    except requests.RequestException as exc:
        print(f"[*] Network error fetching atmospheric entropy: {exc}")

    print("[*] No atmospheric entropy available; falling back to os.urandom.")
    return os.urandom(32)


# ---------------------------------------------------------------------------
# IKM collection and OKM derivation
# ---------------------------------------------------------------------------


def collect_ikm() -> bytearray:
    """Gather entropy from all three sources and concatenate into IKM.

    Calls each entropy source in sequence and writes the results into a
    ``bytearray`` so that the caller can zero the buffer with
    ``secure_zero`` after the HKDF derivation step.

    Returns:
        A 96-byte mutable IKM buffer (3 × 32 bytes).
    """
    dbg("--- Source 1: local OS entropy ---")
    e_local = get_entropy_1()
    dbg("--- Source 2: quantum entropy (ANU) ---")
    e_quantum = get_entropy_2()
    dbg("--- Source 3: atmospheric entropy (Random.org) ---")
    e_random = get_entropy_3()

    ikm = bytearray(e_local + e_quantum + e_random)
    dbg(
        f"collect_ikm: IKM assembled — {len(ikm)} bytes "
        f"({len(e_local)}+{len(e_quantum)}+{len(e_random)})"
    )
    return ikm


def derive_okm(ikm: bytearray, length: int = 256) -> bytearray:
    """Derive uniform Output Key Material from IKM using HKDF-SHA256.

    Applies RFC 5869 HKDF with SHA-256 as the hash function and a fixed
    application-specific ``info`` tag.  Replace this function to swap in
    a different KDF (e.g. Argon2id, PBKDF2) without changing the rest of
    the pipeline.

    The default of 256 bytes yields 32 × 64-bit words, which is sufficient
    for passwords up to ~30 characters without triggering the secrets fallback
    in ``OKMStream`` (each character consumes ~1 word via Lemire's algorithm).

    Args:
        ikm:    Input Key Material produced by ``collect_ikm``.
        length: Number of OKM bytes to derive.  Defaults to 256.

    Returns:
        A mutable ``bytearray`` of *length* uniform bytes.
    """
    dbg("derive_okm: running HKDF-SHA256...")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=b"HackUDC26-v1-PWD",
    )
    okm = bytearray(hkdf.derive(bytes(ikm)))
    dbg(f"derive_okm: OKM ({len(okm)} bytes): {okm.hex()[:32]}...")
    return okm
