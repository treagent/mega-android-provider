package com.mega.provider

import android.content.Context
import nz.mega.sdk.MegaApiAndroid
import nz.mega.sdk.MegaApiJava
import nz.mega.sdk.MegaError
import nz.mega.sdk.MegaNode
import nz.mega.sdk.MegaRequest
import nz.mega.sdk.MegaRequestListenerInterface
import nz.mega.sdk.MegaTransfer
import nz.mega.sdk.MegaTransferListenerInterface
import java.io.File
import java.util.concurrent.CountDownLatch

/**
 * Singleton holding the MegaApiAndroid instance and providing
 * synchronous wrappers around the async MEGA SDK calls.
 */
object MegaClientHolder {

    // Replace with your own MEGA API key from https://mega.nz/sdk
    private const val MEGA_API_KEY = "YOUR_MEGA_API_KEY"

    private lateinit var appContext: Context
    lateinit var megaApi: MegaApiAndroid
        private set

    val isInitialized: Boolean
        get() = ::megaApi.isInitialized

    fun init(context: Context) {
        appContext = context.applicationContext
        megaApi = MegaApiAndroid(MEGA_API_KEY, null, null, appContext)
    }

    val isLoggedIn: Boolean
        get() = isInitialized && megaApi.isLoggedIn != 0

    /** Blocking login with email + password. Returns session string or throws. */
    fun login(email: String, password: String): String {
        val latch = CountDownLatch(1)
        var resultError: MegaError? = null

        megaApi.login(email, password, object : SimpleRequestListener() {
            override fun onRequestFinish(api: MegaApiJava, request: MegaRequest, e: MegaError) {
                resultError = e
                latch.countDown()
            }
        })
        latch.await()

        val err = resultError ?: throw IllegalStateException("No response from MEGA")
        if (err.errorCode != MegaError.API_OK) {
            throw MegaLoginException("Login failed: ${err.errorString} (${err.errorCode})")
        }

        // Fetch nodes after login
        fetchNodes()

        return megaApi.dumpSession()
    }

    /** Blocking session resume. Returns true on success. */
    fun fastLogin(session: String): Boolean {
        val latch = CountDownLatch(1)
        var resultError: MegaError? = null

        megaApi.fastLogin(session, object : SimpleRequestListener() {
            override fun onRequestFinish(api: MegaApiJava, request: MegaRequest, e: MegaError) {
                resultError = e
                latch.countDown()
            }
        })
        latch.await()

        val err = resultError ?: return false
        if (err.errorCode != MegaError.API_OK) return false

        fetchNodes()
        return true
    }

    /** Blocking fetchNodes — must be called after login/fastLogin. */
    private fun fetchNodes() {
        val latch = CountDownLatch(1)
        var resultError: MegaError? = null

        megaApi.fetchNodes(object : SimpleRequestListener() {
            override fun onRequestFinish(api: MegaApiJava, request: MegaRequest, e: MegaError) {
                resultError = e
                latch.countDown()
            }
        })
        latch.await()

        val err = resultError ?: throw IllegalStateException("No response from MEGA fetchNodes")
        if (err.errorCode != MegaError.API_OK) {
            throw IllegalStateException("fetchNodes failed: ${err.errorString}")
        }
    }

    fun getRootNode(): MegaNode? = megaApi.rootNode

    fun getNodeByHandle(handle: Long): MegaNode? = megaApi.getNodeByHandle(handle)

    fun getChildren(node: MegaNode): List<MegaNode> =
        megaApi.getChildren(node)?.let { nodeList ->
            (0 until nodeList.size()).map { nodeList.get(it) }
        } ?: emptyList()

    /** Blocking file download to a local path. */
    fun downloadFile(node: MegaNode, destPath: String): File {
        val destFile = File(destPath)
        val latch = CountDownLatch(1)
        var resultError: MegaError? = null

        megaApi.startDownload(
            node,
            destFile.parent + "/",
            destFile.name,
            null, null, false, null,
            object : SimpleTransferListener() {
                override fun onTransferFinish(
                    api: MegaApiJava, transfer: MegaTransfer, e: MegaError
                ) {
                    resultError = e
                    latch.countDown()
                }
            }
        )
        latch.await()

        val err = resultError
        if (err != null && err.errorCode != MegaError.API_OK) {
            throw IllegalStateException("Download failed: ${err.errorString}")
        }
        return destFile
    }

    /** Blocking file upload from a local path to a parent folder. */
    fun uploadFile(localPath: String, parentNode: MegaNode): MegaNode? {
        val latch = CountDownLatch(1)
        var resultError: MegaError? = null

        megaApi.startUpload(
            localPath, parentNode,
            null, 0, null, false, false, null,
            object : SimpleTransferListener() {
                override fun onTransferFinish(
                    api: MegaApiJava, transfer: MegaTransfer, e: MegaError
                ) {
                    resultError = e
                    latch.countDown()
                }
            }
        )
        latch.await()

        val err = resultError
        if (err != null && err.errorCode != MegaError.API_OK) {
            throw IllegalStateException("Upload failed: ${err.errorString}")
        }
        // Return the newly uploaded node
        val fileName = File(localPath).name
        return megaApi.getChildren(parentNode)?.let { list ->
            (0 until list.size()).map { list.get(it) }.firstOrNull { it.name == fileName }
        }
    }

    /** Blocking folder creation. */
    fun createFolder(name: String, parentNode: MegaNode): MegaNode? {
        val latch = CountDownLatch(1)
        var resultError: MegaError? = null
        var createdHandle: Long = MegaApiJava.INVALID_HANDLE

        megaApi.createFolder(name, parentNode, object : SimpleRequestListener() {
            override fun onRequestFinish(api: MegaApiJava, request: MegaRequest, e: MegaError) {
                resultError = e
                createdHandle = request.nodeHandle
                latch.countDown()
            }
        })
        latch.await()

        val err = resultError
        if (err != null && err.errorCode != MegaError.API_OK) return null
        return megaApi.getNodeByHandle(createdHandle)
    }

    /** Blocking node deletion (move to rubbish). */
    fun deleteNode(node: MegaNode): Boolean {
        val latch = CountDownLatch(1)
        var resultError: MegaError? = null

        megaApi.moveNode(node, megaApi.rubbishNode, object : SimpleRequestListener() {
            override fun onRequestFinish(api: MegaApiJava, request: MegaRequest, e: MegaError) {
                resultError = e
                latch.countDown()
            }
        })
        latch.await()

        return resultError?.errorCode == MegaError.API_OK
    }

    fun logout() {
        if (isInitialized) {
            megaApi.logout()
        }
    }

    // --- Listener stubs ---

    abstract class SimpleRequestListener : MegaRequestListenerInterface {
        override fun onRequestStart(api: MegaApiJava, request: MegaRequest) {}
        override fun onRequestUpdate(api: MegaApiJava, request: MegaRequest) {}
        override fun onRequestTemporaryError(api: MegaApiJava, request: MegaRequest, e: MegaError) {}
    }

    abstract class SimpleTransferListener : MegaTransferListenerInterface {
        override fun onTransferStart(api: MegaApiJava, transfer: MegaTransfer) {}
        override fun onTransferUpdate(api: MegaApiJava, transfer: MegaTransfer) {}
        override fun onTransferTemporaryError(api: MegaApiJava, transfer: MegaTransfer, e: MegaError) {}
        override fun onTransferData(api: MegaApiJava, transfer: MegaTransfer, buffer: ByteArray): Boolean = false
    }
}

class MegaLoginException(message: String) : Exception(message)
