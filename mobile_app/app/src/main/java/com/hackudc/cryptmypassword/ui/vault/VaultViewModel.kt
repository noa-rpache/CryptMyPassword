// SPDX-FileCopyrightText: 2026 Noa Rodríguez noa.rpache@gmail.com  Pablo Diz pablo.diz.edu@gmail.com  Hugo Freire hugo.freire@udc.es  Eloy Sastre elhoyyy@gmail.com
//
// SPDX-License-Identifier: Apache-2.0

package com.hackudc.cryptmypassword.ui.vault

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.hackudc.cryptmypassword.data.db.AppDatabase
import com.hackudc.cryptmypassword.data.db.PasswordEntry
import com.hackudc.cryptmypassword.data.repository.PasswordRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class VaultViewModel(application: Application) : AndroidViewModel(application) {

    private val repo = PasswordRepository(
        AppDatabase.getInstance(application).passwordDao()
    )

    val passwords: StateFlow<List<PasswordEntry>> = repo.allPasswords
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    // Dialog state
    private val _showAddDialog = MutableStateFlow(false)
    val showAddDialog: StateFlow<Boolean> = _showAddDialog

    fun openAddDialog() { _showAddDialog.value = true }
    fun closeAddDialog() { _showAddDialog.value = false }

    fun addPassword(domain: String, user: String, password: String) {
        if (domain.isBlank()) return
        viewModelScope.launch {
            repo.upsert(PasswordEntry(domain.trim(), user.trim(), password.trim()))
            _showAddDialog.value = false
        }
    }

    fun deletePassword(domain: String) {
        viewModelScope.launch {
            repo.deleteByDomain(domain)
        }
    }
}
