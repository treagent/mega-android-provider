package com.mega.provider

import android.provider.DocumentsContract.Document
import android.provider.DocumentsContract.Root
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for MegaDocumentsProvider helper logic.
 * Provider methods themselves require Android context / Robolectric for full testing.
 */
class MegaDocumentsProviderTest {

    @Before
    fun setUp() {
        MegaClientHolder.logout()
    }

    @Test
    fun `MegaNode stores handle as string`() {
        val node = MegaNode("ABCDEFGH", "ROOT1234", "test.txt", false, 1024L, 1700000000L)
        assertEquals("ABCDEFGH", node.handle)
        assertEquals("ROOT1234", node.parentHandle)
        assertEquals("test.txt", node.name)
        assertFalse(node.isFolder)
        assertEquals(1024L, node.size)
    }

    @Test
    fun `MegaNode folder flag is set correctly`() {
        val folder = MegaNode("FOLDER01", "", "Photos", true, 0L, 0L)
        assertTrue(folder.isFolder)
        assertEquals(0L, folder.size)
    }

    @Test
    fun `MegaNode equality works`() {
        val a = MegaNode("H1", "P1", "file.pdf", false, 500L, 100L)
        val b = MegaNode("H1", "P1", "file.pdf", false, 500L, 100L)
        assertEquals(a, b)
    }
}
