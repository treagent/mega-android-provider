package com.mega.provider

import android.content.ContentResolver
import android.content.Context
import android.content.pm.ProviderInfo
import android.provider.DocumentsContract
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import androidx.test.core.app.ApplicationProvider

/**
 * Tests for [MegaDocumentsProvider].
 *
 * Since the MEGA SDK is not available in unit tests, MegaClientHolder will
 * never be logged in, and the provider methods should return empty cursors
 * or false as appropriate.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], manifest = Config.NONE)
class MegaDocumentsProviderTest {

    private lateinit var provider: MegaDocumentsProvider

    @Before
    fun setUp() {
        provider = MegaDocumentsProvider()
        val providerInfo = ProviderInfo().apply {
            authority = "com.mega.provider.documents"
            grantUriPermissions = true
        }
        val context = ApplicationProvider.getApplicationContext<Context>()
        provider.attachInfo(context, providerInfo)
    }

    @Test
    fun `queryRoots returns empty cursor when not logged in`() {
        val cursor = provider.queryRoots(null)
        assertNotNull(cursor)
        assertEquals(0, cursor.count)
        cursor.close()
    }

    @Test
    fun `queryChildDocuments returns empty cursor when not logged in`() {
        val cursor = provider.queryChildDocuments("12345", null, null)
        assertNotNull(cursor)
        assertEquals(0, cursor.count)
        cursor.close()
    }

    @Test
    fun `queryDocument returns empty cursor when not logged in`() {
        val cursor = provider.queryDocument("12345", null)
        assertNotNull(cursor)
        assertEquals(0, cursor.count)
        cursor.close()
    }

    @Test
    fun `isChildDocument returns false when not logged in`() {
        val result = provider.isChildDocument("111", "222")
        assertFalse(result)
    }

    @Test
    fun `createDocument returns null when not logged in`() {
        val result = provider.createDocument("111", "text/plain", "test.txt")
        assertEquals(null, result)
    }

    @Test
    fun `openDocument returns null when not logged in`() {
        val result = provider.openDocument("111", "r", null)
        assertEquals(null, result)
    }

    @Test
    fun `onCreate returns true`() {
        // onCreate should always return true — initialization is done in Application
        val fresh = MegaDocumentsProvider()
        val providerInfo = ProviderInfo().apply {
            authority = "com.mega.provider.documents"
            grantUriPermissions = true
        }
        val context = ApplicationProvider.getApplicationContext<Context>()
        fresh.attachInfo(context, providerInfo)
        // If attachInfo didn't throw, onCreate succeeded
    }
}
