package com.hackudc.cryptmypassword.data.repository

import com.hackudc.cryptmypassword.data.db.PasswordDao
import com.hackudc.cryptmypassword.data.db.PasswordEntry
import kotlinx.coroutines.flow.Flow

/**
 * Repository wrapping the Room DAO. Exposes suspend functions and Flows
 * for the rest of the architecture.
 */
class PasswordRepository(private val dao: PasswordDao) {

    /** Observable stream of all stored passwords, ordered by domain. */
    val allPasswords: Flow<List<PasswordEntry>> = dao.getAllPasswords()

    /** One-shot list of all passwords (for audit). */
    suspend fun getAllPasswordsList(): List<PasswordEntry> = dao.getAllPasswordsList()

    /** Insert or replace a password entry (upsert). */
    suspend fun upsert(entry: PasswordEntry) = dao.upsert(entry)

    /** Get a single entry by domain. */
    suspend fun getByDomain(domain: String): PasswordEntry? = dao.getByDomain(domain)

    /** Delete an entry by domain. */
    suspend fun deleteByDomain(domain: String) = dao.deleteByDomain(domain)
}
