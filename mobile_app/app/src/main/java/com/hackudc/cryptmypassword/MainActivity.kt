package com.hackudc.cryptmypassword

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import com.hackudc.cryptmypassword.ui.navigation.AppNavigation
import com.hackudc.cryptmypassword.ui.theme.CryptMyPasswordTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            CryptMyPasswordTheme {
                AppNavigation()
            }
        }
    }
}
