// SPDX-FileCopyrightText: 2026 Noa Rodríguez noa.rpache@gmail.com  Pablo Diz pablo.diz.edu@gmail.com  Hugo Freire hugo.freire@udc.es  Eloy Sastre elhoyyy@gmail.com
//
// SPDX-License-Identifier: Apache-2.0

package com.hackudc.cryptmypassword.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

/**
 * Data Access Object for the passwords table.
 */
@Dao
interface PasswordDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(entry: PasswordEntry)

    @Query("SELECT * FROM passwords ORDER BY domain ASC")
    fun getAllPasswords(): Flow<List<PasswordEntry>>

    @Query("SELECT * FROM passwords ORDER BY domain ASC")
    suspend fun getAllPasswordsList(): List<PasswordEntry>

    @Query("SELECT * FROM passwords WHERE domain = :domain LIMIT 1")
    suspend fun getByDomain(domain: String): PasswordEntry?

    @Query("DELETE FROM passwords WHERE domain = :domain")
    suspend fun deleteByDomain(domain: String)
}
