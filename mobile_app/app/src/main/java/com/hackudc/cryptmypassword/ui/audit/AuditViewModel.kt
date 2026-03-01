// SPDX-FileCopyrightText: 2026 Noa Rodríguez noa.rpache@gmail.com  Pablo Diz pablo.diz.edu@gmail.com  Hugo Freire hugo.freire@udc.es  Eloy Sastre elhoyyy@gmail.com
//
// SPDX-License-Identifier: Apache-2.0

package com.hackudc.cryptmypassword.ui.audit

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.hackudc.cryptmypassword.crypto.PasswordGeneratorService
import com.hackudc.cryptmypassword.data.db.AppDatabase
import com.hackudc.cryptmypassword.data.repository.PasswordRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

data class AuditEntry(
    val domain: String,
    val user: String,
    val breachCount: Int
)

data class AuditUiState(
    val isChecking: Boolean = false,
    val compromised: List<AuditEntry> = emptyList(),
    val totalChecked: Int = 0,
    val checkedSoFar: Int = 0,
    val hasRun: Boolean = false,
    val errorMessage: String? = null
)

class AuditViewModel(application: Application) : AndroidViewModel(application) {

    private val repo = PasswordRepository(
        AppDatabase.getInstance(application).passwordDao()
    )

    private val _state = MutableStateFlow(AuditUiState())
    val state: StateFlow<AuditUiState> = _state

    fun checkAllPasswords() {
        _state.value = AuditUiState(isChecking = true)
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val passwords = repo.getAllPasswordsList()
                _state.value = _state.value.copy(totalChecked = passwords.size)

                val compromised = mutableListOf<AuditEntry>()
                for ((index, entry) in passwords.withIndex()) {
                    _state.value = _state.value.copy(checkedSoFar = index + 1)
                    val result = PasswordGeneratorService.checkHibp(entry.password)
                    if (result.isPwned && result.count != null) {
                        compromised.add(
                            AuditEntry(
                                domain = entry.domain,
                                user = entry.user,
                                breachCount = result.count
                            )
                        )
                    }
                }

                _state.value = _state.value.copy(
                    isChecking = false,
                    compromised = compromised,
                    hasRun = true
                )
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    isChecking = false,
                    errorMessage = e.message ?: "Audit failed",
                    hasRun = true
                )
            }
        }
    }
}
