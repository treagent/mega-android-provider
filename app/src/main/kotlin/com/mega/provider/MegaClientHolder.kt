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

    fun getRootNode(): MegaNode? = api?.getRootNode()

    fun getNodeByHandle(handle: String): MegaNode? = api?.getNode(handle)

    fun getChildren(node: MegaNode): List<MegaNode> =
        api?.getChildren(node.handle) ?: emptyList()

    fun downloadFile(node: MegaNode, destPath: String): File {
        getApi().downloadFile(node.handle, destPath)
        return File(destPath)
    }

    fun uploadFile(localPath: String, parentNode: MegaNode): MegaNode? =
        api?.uploadFile(localPath, parentNode.handle)

    fun createFolder(name: String, parentNode: MegaNode): MegaNode? =
        api?.createFolder(name, parentNode.handle)

    fun deleteNode(node: MegaNode): Boolean =
        api?.deleteNode(node.handle) ?: false

    fun isChildOf(parentHandle: String, childHandle: String): Boolean =
        api?.isAncestor(parentHandle, childHandle) ?: false

    private fun getApi(): MegaApi {
        return api ?: MegaApi().also { api = it }
    }
}
