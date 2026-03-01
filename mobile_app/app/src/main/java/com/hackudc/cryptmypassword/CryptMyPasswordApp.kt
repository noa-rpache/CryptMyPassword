// SPDX-FileCopyrightText: 2026 Noa Rodríguez noa.rpache@gmail.com  Pablo Diz pablo.diz.edu@gmail.com  Hugo Freire hugo.freire@udc.es  Eloy Sastre elhoyyy@gmail.com
//
// SPDX-License-Identifier: Apache-2.0

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
