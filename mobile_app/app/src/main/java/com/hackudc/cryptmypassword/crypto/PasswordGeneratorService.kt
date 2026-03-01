// SPDX-FileCopyrightText: 2026 Noa Rodríguez noa.rpache@gmail.com  Pablo Diz pablo.diz@gmailcom  Hugo Freire hugo.freire@udc.es  Eloy Sastre elhoyyy@gmail.com
//
// SPDX-License-Identifier: Apache-2.0

package com.hackudc.cryptmypassword.crypto

import android.content.Context
import android.util.Log
import okhttp3.OkHttpClient
import okhttp3.Request
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

/**
 * Password generation and breach-validation service.
 *
 * Orchestrates the full pipeline: entropy collection → HKDF → Lemire mapping → HIBP check.
 */
object PasswordGeneratorService {

    private const val TAG = "PasswordGenService"

    /** Character pool: 76 symbols. */
    private const val ALPHABET =
        "abcdefghijklmnopqrstuvwxyz" +
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
        "0123456789" +
        "!@#\$%^&*()-_=+"

    private val hibpClient = OkHttpClient.Builder()
        .connectTimeout(3, TimeUnit.SECONDS)
        .readTimeout(3, TimeUnit.SECONDS)
        .build()

    // -------------------------------------------------------------------
    // Character mapping (Lemire's)
    // -------------------------------------------------------------------
    /**
     * Build a random string from [alphabet] of given [length],
     * driven by [stream] (HKDF-derived OKM).
     */
    private fun lemireUnbiasedMapping(
        alphabet: String,
        length: Int,
        stream: EntropyEngine.OkmStream
    ): String {
        val n = alphabet.length
        if (n == 0) return ""
        val sb = StringBuilder(length)
        repeat(length) {
            val idx = EntropyEngine.getUnbiasedIndex(n, stream)
            sb.append(alphabet[idx])
        }
        return sb.toString()
    }

    // -------------------------------------------------------------------
    // HIBP k-anonymity breach check
    // -------------------------------------------------------------------
    data class HibpResult(val isPwned: Boolean, val count: Int?)

    /**
     * Check [password] against the HIBP Pwned Passwords k-anonymity API.
     *
     * Returns (true, count) if breached, (false, 0) if clean,
     * (false, null) if API unreachable (indeterminate).
     */
    fun checkHibp(password: String): HibpResult {
        return try {
            val sha1 = MessageDigest.getInstance("SHA-1")
                .digest(password.toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02X".format(it) }

            val prefix = sha1.substring(0, 5)
            val suffix = sha1.substring(5)

            val request = Request.Builder()
                .url("https://api.pwnedpasswords.com/range/$prefix")
                .header("User-Agent", "HackUDC26-PasswordGen/1.0")
                .header("Add-Padding", "true")
                .build()

            val response = hibpClient.newCall(request).execute()
            if (response.code != 200) {
                Log.w(TAG, "HIBP API returned HTTP ${response.code}")
                return HibpResult(false, null)
            }

            val body = response.body?.string() ?: return HibpResult(false, null)
            for (line in body.lines()) {
                val parts = line.split(":")
                if (parts.size != 2) continue
                val hash = parts[0].trim()
                val count = parts[1].trim().toIntOrNull() ?: 0
                if (hash.equals(suffix, ignoreCase = true)) {
                    Log.d(TAG, "HIBP: password found in $count breaches")
                    return HibpResult(true, count)
                }
            }

            HibpResult(false, 0)
        } catch (e: Exception) {
            Log.w(TAG, "HIBP check failed: ${e.message}")
            HibpResult(false, null)
        }
    }

    // -------------------------------------------------------------------
    // Full generation pipeline
    // -------------------------------------------------------------------
    data class GenerationResult(
        val password: String,
        val hibpWarning: Boolean = false,  // true if HIBP was unreachable
        val attempts: Int = 1
    )

    /**
     * Generate a cryptographically strong password of given [length].
     *
     * Runs the full entropy → HKDF → Lemire → HIBP pipeline with memory
     * hygiene. If the password is found in a breach, regenerates up to
     * [maxAttempts] times.
     *
     * Must be called from a background thread (performs network I/O).
     */
    fun generateSecurePassword(
        context: Context,
        length: Int = 24,
        maxAttempts: Int = 10
    ): GenerationResult {
        Log.d(TAG, "generateSecurePassword: length=$length, maxAttempts=$maxAttempts")

        // Ensure quantum worker is running
        EntropyEngine.startQuantumRefreshWorker(context)

        var attempt = 0
        while (attempt < maxAttempts) {
            attempt++
            Log.d(TAG, "--- Attempt $attempt/$maxAttempts ---")

            var ikm = ByteArray(0)
            var okm = ByteArray(0)

            try {
                // Step 1: entropy collection
                ikm = EntropyEngine.collectIkm(context)

                // Step 2: key derivation
                okm = EntropyEngine.deriveOkm(ikm)

                // Step 3: OKM stream
                val stream = EntropyEngine.OkmStream(okm)

                // Step 4: character mapping
                val password = lemireUnbiasedMapping(ALPHABET, length, stream)
                if (stream.fallbackCount > 0) {
                    Log.d(TAG, "OKM stream used SecureRandom fallback ${stream.fallbackCount} time(s)")
                }

                // Step 5: HIBP breach check
                val hibpResult = checkHibp(password)

                if (hibpResult.isPwned) {
                    Log.w(TAG, "Attempt $attempt: password found in ${hibpResult.count} breaches; regenerating")
                    continue
                }

                val hibpWarning = hibpResult.count == null
                if (hibpWarning) {
                    Log.w(TAG, "HIBP check inconclusive (API unreachable)")
                }

                Log.d(TAG, "Success on attempt $attempt")
                return GenerationResult(
                    password = password,
                    hibpWarning = hibpWarning,
                    attempts = attempt
                )
            } finally {
                // Step 6: zero sensitive buffers
                EntropyEngine.secureZero(ikm)
                EntropyEngine.secureZero(okm)
            }
        }

        throw RuntimeException("Could not generate a breach-free password in $maxAttempts attempts.")
    }
}
