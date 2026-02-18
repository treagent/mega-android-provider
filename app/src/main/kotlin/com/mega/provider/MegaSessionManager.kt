package com.mega.provider

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Manages the MEGA session string in EncryptedSharedPreferences,
 * backed by Android Keystore.
 */
object MegaSessionManager {

    private const val PREFS_FILE = "mega_secure_prefs"
    private const val KEY_SESSION = "mega_session"

    private fun getPrefs(context: Context) =
        EncryptedSharedPreferences.create(
            context,
            PREFS_FILE,
            MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build(),
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )

    fun saveSession(context: Context, session: String) {
        getPrefs(context).edit().putString(KEY_SESSION, session).apply()
    }

    fun getSession(context: Context): String? =
        getPrefs(context).getString(KEY_SESSION, null)

    fun clearSession(context: Context) {
        getPrefs(context).edit().remove(KEY_SESSION).apply()
    }

    fun hasSession(context: Context): Boolean =
        getSession(context) != null
}
