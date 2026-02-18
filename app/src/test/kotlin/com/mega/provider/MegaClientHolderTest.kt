package com.mega.provider

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for MegaClientHolder.
 * Uses MegaApi directly (no SDK, no native libs).
 */
class MegaClientHolderTest {

    @Before
    fun setUp() {
        // MegaClientHolder is a singleton — reset state between tests
        MegaClientHolder.logout()
    }

    @Test
    fun `isLoggedIn returns false when not authenticated`() {
        assertFalse(MegaClientHolder.isLoggedIn)
    }

    @Test
    fun `logout clears session`() {
        MegaClientHolder.logout()
        assertFalse(MegaClientHolder.isLoggedIn)
    }

    @Test
    fun `getRootNode returns null when not logged in`() {
        assertNull(MegaClientHolder.getRootNode())
    }

    @Test
    fun `getNodeByHandle returns null for unknown handle`() {
        assertNull(MegaClientHolder.getNodeByHandle("nonexistent"))
    }

    @Test
    fun `getChildren returns empty list when not logged in`() {
        val fakeParent = MegaNode("h1", "", "Root", true, 0L, 0L)
        val children = MegaClientHolder.getChildren(fakeParent)
        assertTrue(children.isEmpty())
    }
}
