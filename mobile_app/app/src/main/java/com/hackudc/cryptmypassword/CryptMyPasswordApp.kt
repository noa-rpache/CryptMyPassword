package com.hackudc.cryptmypassword

import android.app.Application
import com.hackudc.cryptmypassword.crypto.EntropyEngine

class CryptMyPasswordApp : Application() {
    override fun onCreate() {
        super.onCreate()
        // Start quantum entropy cache refresh worker on app launch
        EntropyEngine.startQuantumRefreshWorker(this)
    }
}
