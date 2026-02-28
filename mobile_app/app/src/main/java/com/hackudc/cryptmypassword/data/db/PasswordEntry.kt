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
