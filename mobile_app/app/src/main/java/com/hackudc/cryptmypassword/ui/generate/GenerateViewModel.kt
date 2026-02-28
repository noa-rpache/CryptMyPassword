package com.hackudc.cryptmypassword.ui.generate

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.hackudc.cryptmypassword.crypto.PasswordGeneratorService
import com.hackudc.cryptmypassword.data.db.AppDatabase
import com.hackudc.cryptmypassword.data.db.PasswordEntry
import com.hackudc.cryptmypassword.data.repository.PasswordRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

data class GenerateUiState(
    val domain: String = "",
    val username: String = "",
    val passwordLength: Int = 24,
    val generatedPassword: String = "",
    val isGenerating: Boolean = false,
    val hibpWarning: Boolean = false,
    val errorMessage: String? = null,
    val saved: Boolean = false
)

class GenerateViewModel(application: Application) : AndroidViewModel(application) {

    private val repo = PasswordRepository(
        AppDatabase.getInstance(application).passwordDao()
    )

    private val _state = MutableStateFlow(GenerateUiState())
    val state: StateFlow<GenerateUiState> = _state

    fun setDomain(domain: String) {
        _state.value = _state.value.copy(domain = domain, saved = false)
    }

    fun setUsername(username: String) {
        _state.value = _state.value.copy(username = username, saved = false)
    }

    fun setPasswordLength(length: Int) {
        _state.value = _state.value.copy(passwordLength = length.coerceIn(12, 64), saved = false)
    }

    fun generatePassword() {
        _state.value = _state.value.copy(
            isGenerating = true,
            errorMessage = null,
            hibpWarning = false,
            saved = false
        )
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val result = PasswordGeneratorService.generateSecurePassword(
                    context = getApplication(),
                    length = _state.value.passwordLength
                )
                _state.value = _state.value.copy(
                    generatedPassword = result.password,
                    isGenerating = false,
                    hibpWarning = result.hibpWarning
                )
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    isGenerating = false,
                    errorMessage = e.message ?: "Password generation failed"
                )
            }
        }
    }

    fun savePassword() {
        val s = _state.value
        if (s.domain.isBlank() || s.generatedPassword.isBlank()) return
        viewModelScope.launch {
            repo.upsert(
                PasswordEntry(
                    domain = s.domain.trim(),
                    user = s.username.trim(),
                    password = s.generatedPassword
                )
            )
            _state.value = _state.value.copy(saved = true)
        }
    }

    /** Pre-fill domain/username when navigating from the vault. */
    fun prefill(domain: String?, username: String?) {
        _state.value = _state.value.copy(
            domain = domain ?: "",
            username = username ?: "",
            generatedPassword = "",
            saved = false,
            errorMessage = null,
            hibpWarning = false
        )
    }
}
