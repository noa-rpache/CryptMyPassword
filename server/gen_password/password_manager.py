# SPDX-FileCopyrightText: 2026 Noa Rodríguez noa.rpache@gmail.com  Pablo Diz pablo.diz@gmailcom  Hugo Freire hugo.freire@udc.es  Eloy Sastre elhoyyy@gmail.com
#
# SPDX-License-Identifier: Apache-2.0

# -*- coding: utf-8 -*-
"""
password_manager.py
===================

Password generation and breach-validation module.

Purpose:
    Orchestrates the full password creation pipeline by consuming the
    cryptographic primitives provided by ``entropy_engine``.  Characters
    are selected by feeding the HKDF-derived Output Key Material (OKM)
    directly into Lemire's unbiased mapping, so every bit of collected
    entropy influences the final output.

    An optional Have I Been Pwned (HIBP) k-anonymity check validates the
    generated password against a corpus of known breach datasets before it
    is returned to the caller.

Pipeline:
    collect_ikm()          ← three independent entropy sources (96 bytes)
        │
    derive_okm()           ← HKDF-SHA256 (RFC 5869), 64-byte OKM
        │
    OKMStream              ← deterministic 64-bit-word stream; secrets fallback
        │
    lemire_unbiased_mapping← Daniel Lemire (2019) bias-free index selection
        │
    check_hibp()           ← k-anonymity SHA-1 prefix query to HIBP API
        │
    secure_zero()          ← IKM and OKM buffers overwritten with null bytes

Security notes:
    - The IKM and OKM buffers are ``bytearray`` objects and are zeroed with
      ``secure_zero`` in a ``finally`` block, regardless of exceptions.
    - ``check_hibp`` uses a ``while`` loop (max 10 attempts) instead of
      recursion to prevent unbounded call-stack growth.
    - HIBP failures are fail-secure: network errors produce a warning but do
      not silently mark the password as safe when the API is unreachable.
    - A ``User-Agent`` header is included in all outgoing HTTP requests.

Public API:
    lemire_unbiased_mapping(alphabet, length, stream) -> str
        Map *length* characters from *alphabet* using an ``OKMStream``.

    check_hibp(password) -> tuple[bool, int | None]
        k-Anonymity HIBP check.  Returns (True, count) if breached, or
        (False, 0) if clean.  Returns (False, None) when the API is
        unreachable, signalling an indeterminate result.

    generate_secure_password(length, max_attempts) -> str
        Full pipeline with memory hygiene and HIBP retry loop.
"""

import hashlib
import warnings

import requests
from entropy_engine import (
    OKMStream,
    collect_ikm,
    dbg,
    derive_okm,
    get_unbiased_index,
    is_quantum_worker_alive,
    secure_zero,
    start_quantum_refresh_worker,
)

# ---------------------------------------------------------------------------
# Alphabet
# ---------------------------------------------------------------------------

_ALPHABET: str = (
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
)
"""Character pool used when generating passwords (76 symbols)."""


# ---------------------------------------------------------------------------
# Character mapping
# ---------------------------------------------------------------------------


def lemire_unbiased_mapping(alphabet: str, length: int, stream: OKMStream) -> str:
    """Build a random string driven by an OKMStream.

    Selects *length* characters uniformly from *alphabet* by calling
    ``get_unbiased_index`` with the provided *stream* as the randomness
    source.  Because the stream is backed by HKDF-derived OKM, the full
    entropy pipeline (OS + quantum + atmospheric → HKDF → OKM) directly
    influences every character chosen.

    Args:
        alphabet: Non-empty string of allowed characters.
        length:   Desired output length in characters.
        stream:   ``OKMStream`` instance supplying 64-bit words.  The stream
                  is consumed but not reset; pass a fresh instance for each
                  password.

    Returns:
        A string of exactly *length* characters, or an empty string if
        *alphabet* is empty.
    """
    n = len(alphabet)
    if n == 0:
        return ""
    dbg(f"lemire_unbiased_mapping: {length} chars from alphabet of {n} symbols")
    return "".join(alphabet[get_unbiased_index(n, stream)] for _ in range(length))


# ---------------------------------------------------------------------------
# HIBP k-anonymity breach check
# ---------------------------------------------------------------------------

_HIBP_HEADERS: dict[str, str] = {
    "User-Agent": "HackUDC26-PasswordGen/1.0",
    "Add-Padding": "true",  # ask HIBP to pad the response to a fixed size
}

_HIBP_URL = "https://api.pwnedpasswords.com/range/{prefix}"


def check_hibp(password: str) -> tuple[bool, int | None]:
    """Check *password* against the HIBP Pwned Passwords k-anonymity API.

    Computes the SHA-1 hash of the password and sends only the first
    5 hex characters (the "prefix") to the HIBP server.  The server returns
    all hash suffixes that share the prefix; the full hash never leaves the
    local machine.

    Fail-secure behaviour:
        - If the API is unreachable or returns an unexpected status code, the
          function returns ``(False, None)`` to signal an *indeterminate*
          result rather than silently asserting the password is safe.  The
          caller (``generate_secure_password``) treats ``None`` as a warning.

    Args:
        password: Plaintext password to check.

    Returns:
        A ``(is_pwned, count)`` tuple where:

        - ``(True,  int)``  — password found in *count* breaches.
        - ``(False, 0)``    — password not found; API responded normally.
        - ``(False, None)`` — API unreachable or error; result indeterminate.
    """
    sha1_pwd = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_pwd[:5], sha1_pwd[5:]
    dbg(f"check_hibp: querying HIBP prefix {prefix}...")

    try:
        res = requests.get(
            _HIBP_URL.format(prefix=prefix),
            headers=_HIBP_HEADERS,
            timeout=3,
        )
        if res.status_code != 200:
            warnings.warn(
                f"HIBP API returned HTTP {res.status_code}; "
                "breach status is indeterminate.",
                RuntimeWarning,
                stacklevel=2,
            )
            return False, None

        for line in res.text.splitlines():
            parts = line.split(":")
            if len(parts) != 2:
                continue
            h, count = parts
            if h.strip() == suffix:
                dbg(f"check_hibp: MATCH — password found in {count} breaches")
                return True, int(count)

        dbg("check_hibp: no match — password is clean")
        return False, 0

    except requests.Timeout:
        warnings.warn(
            "HIBP API request timed out; breach status is indeterminate.",
            RuntimeWarning,
            stacklevel=2,
        )
        return False, None

    except requests.RequestException as exc:
        warnings.warn(
            f"HIBP API network error ({exc}); breach status is indeterminate.",
            RuntimeWarning,
            stacklevel=2,
        )
        return False, None


# ---------------------------------------------------------------------------
# Full password generation pipeline
# ---------------------------------------------------------------------------


def generate_secure_password(
    length: int = 20,
    max_attempts: int = 10,
) -> str:
    """Generate a cryptographically strong password.

    Runs the complete pipeline with memory hygiene and a bounded HIBP retry
    loop.  IKM and OKM buffers are stored as ``bytearray`` objects and
    zeroed in a ``finally`` block so sensitive key material has a minimal
    lifetime regardless of exceptions.

    Pipeline per attempt:
        1. ``collect_ikm``               — 96 bytes from three entropy sources.
        2. ``derive_okm``                — HKDF-SHA256, 64-byte OKM.
        3. ``OKMStream``                 — wrap OKM as a consumable word stream.
        4. ``lemire_unbiased_mapping``   — map *length* chars from ``_ALPHABET``.
        5. ``check_hibp``                — reject and retry if breached.
        6. ``secure_zero``               — wipe IKM and OKM buffers.

    Args:
        length:       Desired password length in characters.  Defaults to 20.
        max_attempts: Maximum number of generation+HIBP cycles before giving
                      up.  Defaults to 10.

    Returns:
        A randomly generated password string of the requested length.

    Raises:
        RuntimeError: If no acceptable password is produced within
                      *max_attempts* attempts.
    """
    dbg(f"generate_secure_password: length={length}, max_attempts={max_attempts}")

    # Ensure the background ANU refresh worker is running.
    if not is_quantum_worker_alive():
        dbg("generate_secure_password: worker not alive — restarting")
        print("[*] Quantum refresh worker was not running; restarting...")
        start_quantum_refresh_worker()

    attempt = 0
    while attempt < max_attempts:
        attempt += 1
        dbg(f"--- Attempt {attempt}/{max_attempts} ---")

        ikm: bytearray = bytearray()
        okm: bytearray = bytearray()

        try:
            # Step 1 — entropy collection
            ikm = collect_ikm()

            # Step 2 — key derivation
            okm = derive_okm(ikm)

            # Step 3 — OKM stream (wraps OKM as a 64-bit word source)
            stream = OKMStream(okm)

            # Step 4 — character mapping driven by the OKM stream
            dbg(f"Alphabet: {len(_ALPHABET)} symbols")
            password = lemire_unbiased_mapping(_ALPHABET, length, stream)
            if stream._fallback_count:
                dbg(
                    f"OKMStream used secrets fallback "
                    f"{stream._fallback_count} time(s) this attempt"
                )

            # Step 5 — HIBP breach check
            dbg("Checking HIBP...")
            is_pwned, count = check_hibp(password)

            if is_pwned:
                print(
                    f"[*] Attempt {attempt}: password found in {count} breaches; "
                    "regenerating..."
                )
                continue  # try again

            if count is None:
                # Indeterminate — API unreachable; warn but accept the password
                warnings.warn(
                    "HIBP check was inconclusive (API unreachable). "
                    "The password has not been verified against breach databases.",
                    RuntimeWarning,
                    stacklevel=2,
                )

            dbg(f"generate_secure_password: success on attempt {attempt}")
            return password

        finally:
            # Step 6 — zero sensitive buffers regardless of outcome
            if ikm:
                secure_zero(ikm)
                dbg("secure_zero: IKM wiped")
            if okm:
                secure_zero(okm)
                dbg("secure_zero: OKM wiped")

    raise RuntimeError(
        f"Could not generate a breach-free password in {max_attempts} attempts."
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    start_quantum_refresh_worker()
    print(f"[*] Quantum refresh worker alive: {is_quantum_worker_alive()}")
    pwd = generate_secure_password(24)
    print(f"Generated password: {pwd}")
