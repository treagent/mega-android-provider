package com.mega.provider

import android.app.Application

class MegaProviderApp : Application() {

    override fun onCreate() {
        super.onCreate()
        // Initialize the MEGA client singleton
        MegaClientHolder.init(this)
    }
}
