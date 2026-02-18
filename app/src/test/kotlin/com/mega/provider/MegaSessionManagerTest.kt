package com.mega.provider

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class MegaSessionManagerTest {

    private lateinit var context: Context

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        MegaSessionManager.clearSession(context)
    }

    @Test
    fun `hasSession returns false when no session saved`() {
        assertFalse(MegaSessionManager.hasSession(context))
    }

    @Test
    fun `saveSession and getSession round-trip`() {
        val token = "test_session_token_12345:AAAA"
        MegaSessionManager.saveSession(context, token)
        assertEquals(token, MegaSessionManager.getSession(context))
    }

    @Test
    fun `clearSession removes saved session`() {
        MegaSessionManager.saveSession(context, "some_session:BBBB")
        MegaSessionManager.clearSession(context)
        assertFalse(MegaSessionManager.hasSession(context))
        assertNull(MegaSessionManager.getSession(context))
    }

    @Test
    fun `hasSession returns true after saving`() {
        MegaSessionManager.saveSession(context, "sid:CCCC")
        assertTrue(MegaSessionManager.hasSession(context))
    }
}
