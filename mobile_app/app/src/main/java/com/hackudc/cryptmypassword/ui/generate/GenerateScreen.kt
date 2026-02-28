package com.hackudc.cryptmypassword.ui.generate

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlin.math.roundToInt

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GenerateScreen(
    viewModel: GenerateViewModel = viewModel(),
    domain: String? = null,
    username: String? = null
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    var showPassword by remember { mutableStateOf(false) }

    // Pre-fill on first composition if needed
    LaunchedEffect(domain, username) {
        if (domain != null || username != null) {
            viewModel.prefill(domain, username)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Generate Password") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer
                )
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Domain
            OutlinedTextField(
                value = state.domain,
                onValueChange = { viewModel.setDomain(it) },
                label = { Text("Domain (optional)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )

            // Username
            OutlinedTextField(
                value = state.username,
                onValueChange = { viewModel.setUsername(it) },
                label = { Text("Username (optional)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )

            // Password length slider
            Column {
                Text(
                    text = "Password length: ${state.passwordLength}",
                    style = MaterialTheme.typography.bodyMedium
                )
                Slider(
                    value = state.passwordLength.toFloat(),
                    onValueChange = { viewModel.setPasswordLength(it.roundToInt()) },
                    valueRange = 12f..64f,
                    steps = 51,
                    modifier = Modifier.fillMaxWidth()
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text("12", style = MaterialTheme.typography.labelSmall)
                    Text("64", style = MaterialTheme.typography.labelSmall)
                }
            }

            // Generate button
            Button(
                onClick = { viewModel.generatePassword() },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp),
                enabled = !state.isGenerating
            ) {
                if (state.isGenerating) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(24.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onPrimary
                    )
                    Spacer(Modifier.width(12.dp))
                    Text("Generating...")
                } else {
                    Text("Generate", style = MaterialTheme.typography.titleMedium)
                }
            }

            // Error
            state.errorMessage?.let { error ->
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.errorContainer
                    ),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = error,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                        modifier = Modifier.padding(16.dp)
                    )
                }
            }

            // HIBP warning
            if (state.hibpWarning) {
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.tertiaryContainer
                    ),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = "Warning: HIBP check was inconclusive (API unreachable). " +
                                "The password has not been verified against breach databases.",
                        color = MaterialTheme.colorScheme.onTertiaryContainer,
                        modifier = Modifier.padding(16.dp),
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }

            // Generated password display
            if (state.generatedPassword.isNotEmpty()) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceVariant
                    )
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            "Generated Password",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.height(8.dp))
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                text = if (showPassword) state.generatedPassword else "••••••••••••",
                                style = MaterialTheme.typography.bodyLarge.copy(
                                    fontFamily = FontFamily.Monospace
                                ),
                                modifier = Modifier.weight(1f)
                            )
                            IconButton(onClick = { showPassword = !showPassword }) {
                                Icon(
                                    if (showPassword) Icons.Outlined.VisibilityOff
                                    else Icons.Outlined.Visibility,
                                    contentDescription = "Toggle"
                                )
                            }
                        }
                    }
                }

                // Copy & Save buttons
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    OutlinedButton(
                        onClick = {
                            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE)
                                    as ClipboardManager
                            clipboard.setPrimaryClip(
                                ClipData.newPlainText("password", state.generatedPassword)
                            )
                            Toast.makeText(context, "Password copied", Toast.LENGTH_SHORT).show()
                        },
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("Copy")
                    }
                    Button(
                        onClick = { viewModel.savePassword() },
                        modifier = Modifier.weight(1f),
                        enabled = state.domain.isNotBlank() && !state.saved
                    ) {
                        Text(if (state.saved) "Saved ✓" else "Save")
                    }
                }

                if (state.saved) {
                    Text(
                        "Password saved for ${state.domain}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary
                    )
                }
            }
        }
    }
}
