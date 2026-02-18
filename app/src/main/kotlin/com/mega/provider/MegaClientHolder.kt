package com.mega.provider

import android.content.Context
import java.io.File

/**
 * Singleton wrapper around MegaApi.
 * Keeps the same public interface as the original SDK-based version
 * but uses the pure Kotlin HTTP implementation.
 */
object MegaClientHolder {

    private var api: MegaApi? = null

    val isLoggedIn: Boolean
        get() = api?.sessionId != null

    fun init(context: Context) {
        // No SDK initialization needed — MegaApi is pure Kotlin
        if (api == null) api = MegaApi()
    }

    /** Login with email + password. Returns encoded session string to persist. */
    fun login(email: String, password: String): String {
        val a = getApi()
        val session = a.login(email, password)
        return session
    }

    /** Resume a previously saved session. Returns true on success. */
    fun fastLogin(session: String): Boolean {
        val a = getApi()
        return a.fastLogin(session)
    }

    fun logout() {
        api?.logout()
    }

    fun getRootNode(): MegaNode? {
        api?.ensureNodes()
        return api?.getRootNode()
    }

    fun getNodeByHandle(handle: String): MegaNode? {
        api?.ensureNodes()
        return api?.getNode(handle)
    }

    fun getChildren(node: MegaNode): List<MegaNode> {
        api?.ensureNodes()
        return api?.getChildren(node.handle) ?: emptyList()
    }

    fun getDownloadUrl(handle: String): String = getApi().getDownloadUrl(handle)

    fun getDecryptedBytes(handle: String): ByteArray = getApi().getDecryptedBytes(handle)

    fun downloadFile(node: MegaNode, destPath: String): File {
        getApi().downloadFile(node.handle, destPath)
        return File(destPath)
    }

    fun uploadFile(localPath: String, parentNode: MegaNode): MegaNode? =
        api?.uploadFile(localPath, parentNode.handle)

    fun createFolder(name: String, parentNode: MegaNode): MegaNode? =
        api?.createFolder(name, parentNode.handle)

    fun moveNode(node: MegaNode, targetNode: MegaNode): Boolean =
        api?.moveNode(node.handle, targetNode.handle) ?: false

    fun deleteNode(node: MegaNode): Boolean =
        api?.deleteNode(node.handle) ?: false

    /** Count how many direct child folders have purely numeric names. */
    fun scanNumberedFolders(node: MegaNode): Int {
        api?.ensureNodes()
        val children = api?.getChildren(node.handle) ?: return 0
        return children.count { it.isFolder && it.name.trim().matches(Regex("^\\d+$")) }
    }

    /** Reorganize numbered sub-folders of [parentNode] into chunks of [chunkSize]. */
    fun reorganizeNumberedFolders(
        parentNode: MegaNode,
        chunkSize: Int = 100,
        onProgress: (done: Int, total: Int, msg: String) -> Unit = { _, _, _ -> }
    ): MegaApi.ReorgResult {
        api?.ensureNodes()
        return getApi().reorganizeNumberedFolders(parentNode.handle, chunkSize, onProgress)
    }

    val nodesLoaded: Boolean get() = api?.nodesLoaded ?: false

    /** Force a full re-fetch from MEGA. */
    fun refreshNodes() = getApi().refreshNodes()

    /** Fetch nodes with persistent retry on rate-limit / timeout. */
    fun fetchNodesRetry(onWait: (String) -> Unit = {}) = getApi().fetchNodesRetry(onWait)

    /** Save the current node tree to app-private disk cache. */
    fun saveNodeCache(context: Context) {
        try {
            val json = api?.serializeNodes() ?: return
            val file = java.io.File(context.filesDir, "mega_nodes_cache.json")
            file.writeText(json)
            android.util.Log.d("MegaClientHolder", "Node cache saved: ${file.length()} bytes")
        } catch (e: Exception) {
            android.util.Log.w("MegaClientHolder", "saveNodeCache failed: ${e.message}")
        }
    }

    /** Load node tree from disk cache. Returns true if cache was valid. */
    fun loadNodeCache(context: Context): Boolean {
        return try {
            val file = java.io.File(context.filesDir, "mega_nodes_cache.json")
            if (!file.exists()) return false
            api?.loadCachedNodes(file.readText()) ?: false
        } catch (e: Exception) {
            android.util.Log.w("MegaClientHolder", "loadNodeCache failed: ${e.message}")
            false
        }
    }

    /** Invalidate and delete the on-disk node cache. */
    fun clearNodeCache(context: Context) {
        try { java.io.File(context.filesDir, "mega_nodes_cache.json").delete() } catch (_: Exception) {}
    }

    fun isChildOf(parentHandle: String, childHandle: String): Boolean =
        api?.isAncestor(parentHandle, childHandle) ?: false

    private fun getApi(): MegaApi {
        return api ?: MegaApi().also { api = it }
    }
}
