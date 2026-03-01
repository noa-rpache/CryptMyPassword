// SPDX-FileCopyrightText: 2026 Noa Rodríguez noa.rpache@gmail.com  Pablo Diz pablo.diz@gmailcom  Hugo Freire hugo.freire@udc.es  Eloy Sastre elhoyyy@gmail.com
//
// SPDX-License-Identifier: Apache-2.0

package com.hackudc.cryptmypassword.data.db

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Room entity representing a stored password entry.
 */
@Entity(tableName = "passwords")
data class PasswordEntry(
    @PrimaryKey val domain: String,
    val user: String,
    val password: String
)
