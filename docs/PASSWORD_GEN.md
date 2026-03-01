<!--
SPDX-FileCopyrightText: 2026 Noa Rodríguez noa.rpache@gmail.com  Pablo Diz pablo.diz@gmailcom  Hugo Freire hugo.freire@udc.es  Eloy Sastre elhoyyy@gmail.com

SPDX-License-Identifier: Apache-2.0
-->

# Secure Password Generation Architecture

This document details the cryptographic design and implementation of the password generator used in the **HackUDC26** server. The system prioritizes high-entropy provenance, bias-free character selection, and memory hygiene.

## 1. Entropy Acquisition

The generator aggregates entropy from three independent physical and pseudo-random sources to mitigate trust issues with any single provider.

### 1.1 Local CSPRNG (Kernel)
- **Source**: `/dev/urandom` (Linux) via Python's `os.urandom`.
- **Mechanism**: Sourced synchronously at generation time. Depends on local environmental noise (interrupts, I/O).
- **Volume**: 32 bytes per password.

### 1.2 Quantum Vacuum Fluctuations (ANU QRNG)
- **Source**: Australian National University Quantum Random Number Generator API.
- **Mechanism**:
  - A background daemon thread manages pool refresh with the following cadence:
    - On success: fetches a new 1024-byte pool, persists it to MongoDB, then waits 15 minutes before the next attempt.
    - On failure: waits 90 seconds and retries. Continues retrying every 90 seconds until the API responds successfully, then resumes the normal 15-minute interval.
  - The pool is cached in MongoDB (`quantum_entropy_cache` collection) to respect API rate limits and persist across server restarts.
  - **Generation time**: A 32-byte slice is selected from the cached pool using a random offset derived from `os.urandom`. This ensures different passwords generated within the same refresh window consume distinct quantum segments.
- **Failover chain**:
  1. Fresh MongoDB cache (normal path, no network call at generation time).
  2. Synchronous fetch from ANU (first run or cache disappeared).
  3. Expired cache (stale but still random).
  4. `os.urandom(32)` if no cache has ever been populated.

### 1.3 Atmospheric Noise (Random.org)
- **Source**: Radio atmospheric noise picked up by receiver arrays.
- **Mechanism**:
  - Sourced synchronously at generation time.
  - **Timeout**: Strict 1.5-second limit to prevent latency spikes.
  - **Failover**: If the API times out or returns malformed data, `os.urandom` is used as a fallback.
- **Volume**: 32 bytes per password.

## 2. Entropy Fusion & Key Derivation

Raw entropy is never used directly. It is mixed using a cryptographically secure Key Derivation Function (KDF) to ensure uniformity and erase any statistical bias from the sources.

- **Input Key Material (IKM)**: Formed by concatenating the three sources.
  $$ IKM = E_{local} \parallel E_{quantum} \parallel E_{random} $$
  *(Total size: 96 bytes)*

- **Extraction & Expansion (HKDF-SHA256)**:
  We use RFC 5869 (HKDF) to extract a pseudo-random key (PRK) and expand it into Output Key Material (OKM).
  - **Hash Function**: SHA-256.
  - **Info Tag**: `b"HackUDC26-v1-PWD"` (domain separation).
  - **Salt**: None (defaults to string of zeros).
  - **Output Length**: 256 bytes. This provides enough 64-bit words to generate long passwords without exhausting the stream.

  $$ OKM = \text{HKDF-Expand}(\text{HKDF-Extract}(0, IKM), \text{info}, 256) $$

## 3. Unbiased Character Mapping (Lemire's Algorithm)

To convert the random bits (OKM) into ASCII characters, we use **Daniel Lemire's "Nearly Divisionless" algorithm (2019)** instead of the modulo operator (`%`).

- **Problem**: Using `random % N` introduces statistical bias if the random range is not a perfect multiple of `N`.
- **Solution**:
  1. An `OKMStream` class provides a deterministic stream of 64-bit integers from the OKM buffer.
  2. The algorithm maps a 64-bit integer $x$ to the range $[0, N)$ using fixed-point multiplication.
  3. **Rejection Sampling**: If a number falls into a specific "bias zone", it is discarded, and a new 64-bit word is fetched from the stream.
- **Result**: Every character in the alphabet has a mathematically equal probability of selection.

## 4. Breach Verification (Fail-Secure)

Before returning a password, it is checked against known leaks using the **Have I Been Pwned (HIBP)** API.

- **k-Anonymity**: Only the first 5 characters of the SHA-1 hash are sent to the API. The full hash never leaves the server.
- **Policy**:
  - If a password is found in a breach, it is discarded, and the generation loop restarts (up to 10 attempts).
  - **Fail-Secure**: If the HIBP API is unreachable (timeout/network error), the system raises a warning flagged as "indeterminate" rather than silently marking the password as safe.

## 5. Memory Hygiene

To prevent secrets from lingering in RAM (e.g., in swap files or crash dumps):
- Sensitive buffers (IKM, OKM) are allocated as mutable `bytearray` objects.
- A `secure_zero()` function overwrites these buffers with null bytes immediately after use, within a `finally` block.
