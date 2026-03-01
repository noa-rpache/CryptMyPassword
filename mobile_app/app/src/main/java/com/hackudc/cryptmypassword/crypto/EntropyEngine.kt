// SPDX-FileCopyrightText: 2026 Noa Rodríguez noa.rpache@gmail.com  Pablo Diz pablo.diz.edu@gmail.com  Hugo Freire hugo.freire@udc.es  Eloy Sastre elhoyyy@gmail.com
//
// SPDX-License-Identifier: Apache-2.0

package com.hackudc.cryptmypassword.crypto

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import kotlinx.coroutines.*
import okhttp3.OkHttpClient
import okhttp3.Request
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.TimeUnit

/**
 * Cryptographic entropy engine that replicates the server-side Python pipeline.
 *
 * Collects entropy from 3 independent sources (96-byte IKM), derives uniform
 * OKM via HKDF-SHA256, and exposes an OKM word stream for Lemire's unbiased
 * index selection.
 */
object EntropyEngine {

    private const val TAG = "EntropyEngine"

    // -----------------------------------------------------------------------
    // HTTP client
    // -----------------------------------------------------------------------
    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(5, TimeUnit.SECONDS)
        .build()

    // -----------------------------------------------------------------------
    // Quantum cache (SharedPreferences)
    // -----------------------------------------------------------------------
    private const val PREFS_NAME = "quantum_entropy_cache"
    private const val KEY_POOL_HEX = "pool_hex"
    private const val KEY_TIMESTAMP = "timestamp"
    private const val CACHE_DURATION_MS = 12 * 3600 * 1000L   // 12 hours
    private const val REFRESH_INTERVAL_MS = 15 * 60 * 1000L   // 15 minutes

    private var refreshJob: Job? = null
    private val refreshScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    /**
     * Start the background coroutine that refreshes the ANU quantum pool
     * every 15 minutes.
     */
    fun startQuantumRefreshWorker(context: Context) {
        if (refreshJob?.isActive == true) return
        refreshJob = refreshScope.launch {
            // Immediate fetch if cache missing or stale
            val prefs = getPrefs(context)
            val ts = prefs.getLong(KEY_TIMESTAMP, 0L)
            if (System.currentTimeMillis() - ts >= REFRESH_INTERVAL_MS) {
                fetchAndSaveAnuPool(context)
            }
            while (isActive) {
                delay(REFRESH_INTERVAL_MS)
                fetchAndSaveAnuPool(context)
            }
        }
    }

    private fun getPrefs(context: Context): SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    // -----------------------------------------------------------------------
    // ANU QRNG fetch
    // -----------------------------------------------------------------------
    private fun fetchAnuPool(): ByteArray? {
        return try {
            val request = Request.Builder()
                .url("https://qrng.anu.edu.au/API/jsonI.php?length=1024&type=uint8")
                .header("User-Agent", "HackUDC26-PasswordGen/1.0")
                .build()
            val response = httpClient.newCall(request).execute()
            if (response.code != 200) {
                Log.w(TAG, "ANU QRNG returned HTTP ${response.code}")
                return null
            }
            val body = response.body?.string() ?: return null
            val json = org.json.JSONObject(body)
            if (!json.optBoolean("success", false)) return null
            val dataArray = json.optJSONArray("data") ?: return null
            val pool = ByteArray(dataArray.length())
            for (i in 0 until dataArray.length()) {
                pool[i] = dataArray.getInt(i).toByte()
            }
            Log.d(TAG, "ANU pool fetched: ${pool.size} bytes")
            pool
        } catch (e: Exception) {
            Log.w(TAG, "ANU fetch failed: ${e.message}")
            null
        }
    }

    private fun fetchAndSaveAnuPool(context: Context) {
        val pool = fetchAnuPool() ?: return
        getPrefs(context).edit()
            .putString(KEY_POOL_HEX, pool.joinToString("") { "%02x".format(it) })
            .putLong(KEY_TIMESTAMP, System.currentTimeMillis())
            .apply()
    }

    // -----------------------------------------------------------------------
    // Entropy source 1 — Android OS CSPRNG
    // -----------------------------------------------------------------------
    private fun getEntropy1(): ByteArray {
        Log.d(TAG, "Source 1: SecureRandom.generateSeed(32)")
        return SecureRandom().generateSeed(32)
    }

    // -----------------------------------------------------------------------
    // Entropy source 2 — ANU Quantum (from cache or synchronous fetch)
    // -----------------------------------------------------------------------
    private fun getEntropy2(context: Context): ByteArray {
        Log.d(TAG, "Source 2: ANU quantum entropy")
        val prefs = getPrefs(context)
        val hex = prefs.getString(KEY_POOL_HEX, null)
        val ts = prefs.getLong(KEY_TIMESTAMP, 0L)
        val age = System.currentTimeMillis() - ts

        // Fresh cache — extract 32 bytes at random offset
        if (hex != null && age < CACHE_DURATION_MS) {
            val pool = hexToBytes(hex)
            if (pool.size >= 32) {
                val offset = SecureRandom().nextInt(pool.size - 31)
                Log.d(TAG, "Source 2: cache hit, offset=$offset")
                return pool.copyOfRange(offset, offset + 32)
            }
        }

        // Synchronous fetch (first run or cache gone)
        val pool = fetchAnuPool()
        if (pool != null && pool.size >= 32) {
            prefs.edit()
                .putString(KEY_POOL_HEX, pool.joinToString("") { "%02x".format(it) })
                .putLong(KEY_TIMESTAMP, System.currentTimeMillis())
                .apply()
            val offset = SecureRandom().nextInt(pool.size - 31)
            return pool.copyOfRange(offset, offset + 32)
        }

        // Expired cache fallback
        if (hex != null) {
            Log.w(TAG, "Source 2: using expired cache")
            val pool2 = hexToBytes(hex)
            if (pool2.size >= 32) {
                val offset = SecureRandom().nextInt(pool2.size - 31)
                return pool2.copyOfRange(offset, offset + 32)
            }
        }

        // Final fallback
        Log.w(TAG, "Source 2: falling back to SecureRandom")
        return SecureRandom().generateSeed(32)
    }

    // -----------------------------------------------------------------------
    // Entropy source 3 — Random.org atmospheric noise
    // -----------------------------------------------------------------------
    private fun getEntropy3(): ByteArray {
        Log.d(TAG, "Source 3: Random.org atmospheric noise")
        val client = OkHttpClient.Builder()
            .connectTimeout(1500, TimeUnit.MILLISECONDS)
            .readTimeout(1500, TimeUnit.MILLISECONDS)
            .build()
        return try {
            val request = Request.Builder()
                .url("https://www.random.org/cgi-bin/randbyte?nbytes=32&format=h")
                .header("User-Agent", "HackUDC26-PasswordGen/1.0")
                .build()
            val response = client.newCall(request).execute()
            if (response.code != 200) {
                Log.w(TAG, "Random.org HTTP ${response.code}")
                return SecureRandom().generateSeed(32)
            }
            val body = response.body?.string() ?: return SecureRandom().generateSeed(32)
            val hexClean = body.trim().replace(" ", "").replace("\n", "").replace("\r", "")
            hexToBytes(hexClean).also {
                Log.d(TAG, "Source 3: got ${it.size} bytes")
            }
        } catch (e: Exception) {
            Log.w(TAG, "Source 3 failed: ${e.message}, falling back to SecureRandom")
            SecureRandom().generateSeed(32)
        }
    }

    // -----------------------------------------------------------------------
    // IKM collection
    // -----------------------------------------------------------------------
    /**
     * Concatenate 32 bytes from each of the 3 entropy sources into a
     * 96-byte Input Key Material buffer.
     */
    fun collectIkm(context: Context): ByteArray {
        val e1 = getEntropy1()
        val e2 = getEntropy2(context)
        val e3 = getEntropy3()
        val ikm = ByteArray(96)
        System.arraycopy(e1, 0, ikm, 0, 32)
        System.arraycopy(e2, 0, ikm, 32, 32)
        System.arraycopy(e3, 0, ikm, 64, 32)
        Log.d(TAG, "IKM assembled: ${ikm.size} bytes (${e1.size}+${e2.size}+${e3.size})")
        return ikm
    }

    // -----------------------------------------------------------------------
    // HKDF-SHA256 derivation (Bouncy Castle)
    // -----------------------------------------------------------------------
    /**
     * Derive [length] bytes of uniform OKM from [ikm] using HKDF-SHA256.
     */
    fun deriveOkm(ikm: ByteArray, length: Int = 256): ByteArray {
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        val info = "HackUDC26-v1-PWD".toByteArray(Charsets.UTF_8)
        hkdf.init(HKDFParameters(ikm, null, info))
        val okm = ByteArray(length)
        hkdf.generateBytes(okm, 0, length)
        Log.d(TAG, "OKM derived: $length bytes via HKDF-SHA256")
        return okm
    }

    // -----------------------------------------------------------------------
    // OKM Stream — 64-bit word stream with SecureRandom fallback
    // -----------------------------------------------------------------------
    class OkmStream(okm: ByteArray) {
        private val buf = ByteArrayInputStream(okm.copyOf())
        private val secureRandom = SecureRandom()
        var fallbackCount = 0
            private set

        /**
         * Read the next 64-bit unsigned word from the OKM stream.
         * Falls back to SecureRandom when OKM bytes are exhausted.
         */
        fun readWord(): Long {
            val raw = ByteArray(8)
            val n = buf.read(raw)
            if (n < 8) {
                fallbackCount++
                val padding = ByteArray(8 - maxOf(n, 0))
                secureRandom.nextBytes(padding)
                if (n > 0) {
                    System.arraycopy(padding, 0, raw, n, 8 - n)
                } else {
                    System.arraycopy(padding, 0, raw, 0, 8)
                }
            }
            // Big-endian 8 bytes → Long
            var value = 0L
            for (i in 0..7) {
                value = (value shl 8) or (raw[i].toLong() and 0xFF)
            }
            return value
        }
    }

    // -----------------------------------------------------------------------
    // Lemire's nearly divisionless unbiased index algorithm
    // -----------------------------------------------------------------------
    /**
     * Return an unbiased random integer in [0, n) using Lemire's algorithm.
     * Consumes 64-bit words from [stream].
     */
    fun getUnbiasedIndex(n: Int, stream: OkmStream): Int {
        val nLong = n.toLong() and 0xFFFFFFFFL
        val twoTo64 = BigInteger.ONE.shiftLeft(64) // 2^64

        while (true) {
            val x = stream.readWord()
            // Compute 128-bit product: x (unsigned) * n
            val xUnsigned = BigInteger(1, longToBytes(x))
            val product = xUnsigned.multiply(BigInteger.valueOf(nLong))

            // High 64 bits = index candidate
            val index = product.shiftRight(64).toInt()

            // Low 64 bits = leftover
            val leftover = product.and(twoTo64.subtract(BigInteger.ONE))

            // Fast path
            if (leftover >= BigInteger.valueOf(nLong)) {
                return index
            }

            // Slow path: compute threshold = (2^64) % n
            val threshold = twoTo64.mod(BigInteger.valueOf(nLong))
            if (leftover >= threshold) {
                return index
            }
            // Discard and retry
        }
    }

    // -----------------------------------------------------------------------
    // Memory hygiene
    // -----------------------------------------------------------------------
    /**
     * Overwrite a byte array with zeros.
     */
    fun secureZero(buf: ByteArray) {
        buf.fill(0)
    }

    // -----------------------------------------------------------------------
    // Utility
    // -----------------------------------------------------------------------
    private fun hexToBytes(hex: String): ByteArray {
        val len = hex.length
        if (len % 2 != 0) return ByteArray(0)
        val result = ByteArray(len / 2)
        for (i in result.indices) {
            val hi = Character.digit(hex[i * 2], 16)
            val lo = Character.digit(hex[i * 2 + 1], 16)
            if (hi < 0 || lo < 0) return ByteArray(0)
            result[i] = ((hi shl 4) or lo).toByte()
        }
        return result
    }

    private fun longToBytes(value: Long): ByteArray {
        val result = ByteArray(8)
        for (i in 7 downTo 0) {
            result[7 - i] = ((value ushr (i * 8)) and 0xFF).toByte()
        }
        return result
    }
}
