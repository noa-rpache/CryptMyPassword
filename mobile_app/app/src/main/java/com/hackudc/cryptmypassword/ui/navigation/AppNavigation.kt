// SPDX-FileCopyrightText: 2026 Noa Rodríguez noa.rpache@gmail.com  Pablo Diz pablo.diz@gmailcom  Hugo Freire hugo.freire@udc.es  Eloy Sastre elhoyyy@gmail.com
//
// SPDX-License-Identifier: Apache-2.0

package com.hackudc.cryptmypassword.ui.navigation

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.hackudc.cryptmypassword.ui.audit.AuditScreen
import com.hackudc.cryptmypassword.ui.audit.AuditViewModel
import com.hackudc.cryptmypassword.ui.generate.GenerateScreen
import com.hackudc.cryptmypassword.ui.generate.GenerateViewModel
import com.hackudc.cryptmypassword.ui.vault.VaultScreen
import com.hackudc.cryptmypassword.ui.vault.VaultViewModel

sealed class Screen(val route: String, val label: String, val icon: ImageVector) {
    data object Vault : Screen("vault", "Vault", Icons.Default.Lock)
    data object Generate : Screen("generate?domain={domain}&username={username}", "Generate", Icons.Default.Refresh) {
        fun createRoute(domain: String = "", username: String = ""): String {
            return "generate?domain=$domain&username=$username"
        }
        const val BASE = "generate"
    }
    data object Audit : Screen("audit", "Audit", Icons.Default.Shield)
}

private val bottomNavItems = listOf(Screen.Vault, Screen.Generate, Screen.Audit)

@Composable
fun AppNavigation() {
    val navController = rememberNavController()
    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = navBackStackEntry?.destination?.route

    // Shared ViewModels scoped to the NavHost
    val vaultViewModel: VaultViewModel = viewModel()
    val generateViewModel: GenerateViewModel = viewModel()
    val auditViewModel: AuditViewModel = viewModel()

    Scaffold(
        bottomBar = {
            NavigationBar {
                bottomNavItems.forEach { screen ->
                    val baseRoute = when (screen) {
                        is Screen.Generate -> Screen.Generate.BASE
                        else -> screen.route
                    }
                    val selected = currentRoute?.startsWith(baseRoute) == true

                    NavigationBarItem(
                        selected = selected,
                        onClick = {
                            val targetRoute = when (screen) {
                                is Screen.Generate -> Screen.Generate.createRoute()
                                else -> screen.route
                            }
                            navController.navigate(targetRoute) {
                                popUpTo(navController.graph.findStartDestination().id) {
                                    saveState = true
                                }
                                launchSingleTop = true
                                restoreState = true
                            }
                        },
                        icon = { Icon(screen.icon, contentDescription = screen.label) },
                        label = { Text(screen.label) }
                    )
                }
            }
        }
    ) { innerPadding ->
        NavHost(
            navController = navController,
            startDestination = Screen.Vault.route,
            modifier = Modifier.padding(innerPadding)
        ) {
            composable(Screen.Vault.route) {
                VaultScreen(
                    viewModel = vaultViewModel,
                    onGenerateForDomain = { domain, username ->
                        navController.navigate(Screen.Generate.createRoute(domain, username))
                    }
                )
            }

            composable(
                route = "generate?domain={domain}&username={username}",
                arguments = listOf(
                    navArgument("domain") {
                        type = NavType.StringType
                        defaultValue = ""
                    },
                    navArgument("username") {
                        type = NavType.StringType
                        defaultValue = ""
                    }
                )
            ) { backStackEntry ->
                val domain = backStackEntry.arguments?.getString("domain") ?: ""
                val username = backStackEntry.arguments?.getString("username") ?: ""
                GenerateScreen(
                    viewModel = generateViewModel,
                    domain = domain.ifBlank { null },
                    username = username.ifBlank { null }
                )
            }

            composable(Screen.Audit.route) {
                AuditScreen(viewModel = auditViewModel)
            }
        }
    }
}
