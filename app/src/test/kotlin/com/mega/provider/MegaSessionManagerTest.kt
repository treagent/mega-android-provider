package com.mega.provider

import android.content.Context
import android.content.SharedPreferences
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Tests for [MegaSessionManager] using Robolectric to provide a real Android
 * Context. EncryptedSharedPreferences falls back to a standard implementation
 * under Robolectric, which is sufficient for verifying save/get/clear logic.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], manifest = Config.NONE)
class MegaSessionManagerTest {

    private lateinit var context: Context

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
    }

    @Test
    fun `saveSession and getSession round-trip`() {
        val session = "test-session-token-abc123"
        MegaSessionManager.saveSession(context, session)
        assertEquals(session, MegaSessionManager.getSession(context))
    }

    @Test
    fun `getSession returns null when no session saved`() {
        // Use a fresh context — no session has been saved
        MegaSessionManager.clearSession(context)
        assertNull(MegaSessionManager.getSession(context))
    }

    @Test
    fun `hasSession returns true after save`() {
        MegaSessionManager.saveSession(context, "some-session")
        assertTrue(MegaSessionManager.hasSession(context))
    }

    @Test
    fun `hasSession returns false after clear`() {
        MegaSessionManager.saveSession(context, "some-session")
        MegaSessionManager.clearSession(context)
        assertFalse(MegaSessionManager.hasSession(context))
    }

    @Test
    fun `clearSession removes the session`() {
        MegaSessionManager.saveSession(context, "to-be-cleared")
        MegaSessionManager.clearSession(context)
        assertNull(MegaSessionManager.getSession(context))
    }

    @Test
    fun `saveSession overwrites previous session`() {
        MegaSessionManager.saveSession(context, "first")
        MegaSessionManager.saveSession(context, "second")
        assertEquals("second", MegaSessionManager.getSession(context))
    }
}
