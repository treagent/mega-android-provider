package com.mega.provider

import android.content.res.AssetFileDescriptor
import android.database.Cursor
import android.database.MatrixCursor
import android.graphics.Point
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract
import android.provider.DocumentsContract.Document
import android.provider.DocumentsContract.Root
import android.provider.DocumentsProvider
import android.webkit.MimeTypeMap
import nz.mega.sdk.MegaNode
import java.io.File
import java.io.FileOutputStream

class MegaDocumentsProvider : DocumentsProvider() {

    companion object {
        private const val AUTHORITY = "com.mega.provider.documents"

        private const val ROOT_ID = "mega_root"

        private val DEFAULT_ROOT_PROJECTION = arrayOf(
            Root.COLUMN_ROOT_ID,
            Root.COLUMN_MIME_TYPES,
            Root.COLUMN_FLAGS,
            Root.COLUMN_ICON,
            Root.COLUMN_TITLE,
            Root.COLUMN_SUMMARY,
            Root.COLUMN_DOCUMENT_ID
        )

        private val DEFAULT_DOCUMENT_PROJECTION = arrayOf(
            Document.COLUMN_DOCUMENT_ID,
            Document.COLUMN_MIME_TYPE,
            Document.COLUMN_DISPLAY_NAME,
            Document.COLUMN_LAST_MODIFIED,
            Document.COLUMN_FLAGS,
            Document.COLUMN_SIZE
        )
    }

    override fun onCreate(): Boolean {
        // Provider is created by the system; the App class initializes MegaClientHolder.
        return true
    }

    private fun ensureLoggedIn(): Boolean {
        if (MegaClientHolder.isLoggedIn) return true
        val ctx = context ?: return false
        val session = MegaSessionManager.getSession(ctx) ?: return false
        return MegaClientHolder.fastLogin(session)
    }

    // ----- Roots -----

    override fun queryRoots(projection: Array<out String>?): Cursor {
        val result = MatrixCursor(resolveRootProjection(projection))

        if (!ensureLoggedIn()) return result

        val rootNode = MegaClientHolder.getRootNode() ?: return result

        result.newRow().apply {
            add(Root.COLUMN_ROOT_ID, ROOT_ID)
            add(Root.COLUMN_MIME_TYPES, "*/*")
            add(
                Root.COLUMN_FLAGS,
                Root.FLAG_SUPPORTS_CREATE or
                        Root.FLAG_SUPPORTS_IS_CHILD or
                        Root.FLAG_SUPPORTS_RECENTS
            )
            add(Root.COLUMN_ICON, R.drawable.ic_mega)
            add(Root.COLUMN_TITLE, "MEGA")
            add(Root.COLUMN_SUMMARY, "MEGA Cloud Drive")
            add(Root.COLUMN_DOCUMENT_ID, rootNode.handle.toString())
        }

        return result
    }

    // ----- Documents -----

    override fun queryDocument(documentId: String, projection: Array<out String>?): Cursor {
        val result = MatrixCursor(resolveDocumentProjection(projection))

        if (!ensureLoggedIn()) return result

        val handle = documentId.toLongOrNull() ?: return result
        val node = MegaClientHolder.getNodeByHandle(handle) ?: return result

        addNodeRow(result, node)
        return result
    }

    override fun queryChildDocuments(
        parentDocumentId: String,
        projection: Array<out String>?,
        sortOrder: String?
    ): Cursor {
        val result = MatrixCursor(resolveDocumentProjection(projection))

        if (!ensureLoggedIn()) return result

        val handle = parentDocumentId.toLongOrNull() ?: return result
        val parentNode = MegaClientHolder.getNodeByHandle(handle) ?: return result

        for (child in MegaClientHolder.getChildren(parentNode)) {
            addNodeRow(result, child)
        }
        return result
    }

    // ----- Open / Read -----

    override fun openDocument(
        documentId: String,
        mode: String,
        signal: CancellationSignal?
    ): ParcelFileDescriptor? {
        if (!ensureLoggedIn()) return null

        val handle = documentId.toLongOrNull() ?: return null
        val node = MegaClientHolder.getNodeByHandle(handle) ?: return null

        // For read mode, download to a temp file and return its FD.
        if (mode == "r") {
            val cacheDir = context?.cacheDir ?: return null
            val tempFile = File(cacheDir, "mega_${node.handle}_${node.name}")

            if (!tempFile.exists() || tempFile.length() != node.size) {
                MegaClientHolder.downloadFile(node, tempFile.absolutePath)
            }

            return ParcelFileDescriptor.open(tempFile, ParcelFileDescriptor.MODE_READ_ONLY)
        }

        // For write mode, create a pipe: caller writes → we upload on close.
        if (mode == "w" || mode == "rw") {
            val cacheDir = context?.cacheDir ?: return null
            val tempFile = File(cacheDir, "mega_upload_${node.handle}_${node.name}")

            val parentNode = MegaClientHolder.getNodeByHandle(node.parentHandle) ?: return null

            val pipe = ParcelFileDescriptor.createReliablePipe()
            val readFd = pipe[0]
            val writeFd = pipe[1]

            Thread {
                try {
                    ParcelFileDescriptor.AutoCloseInputStream(readFd).use { input ->
                        FileOutputStream(tempFile).use { output ->
                            input.copyTo(output)
                        }
                    }
                    MegaClientHolder.uploadFile(tempFile.absolutePath, parentNode)
                } finally {
                    tempFile.delete()
                }
            }.start()

            return writeFd
        }

        return null
    }

    // ----- Create -----

    override fun createDocument(
        parentDocumentId: String,
        mimeType: String,
        displayName: String
    ): String? {
        if (!ensureLoggedIn()) return null

        val handle = parentDocumentId.toLongOrNull() ?: return null
        val parentNode = MegaClientHolder.getNodeByHandle(handle) ?: return null

        // Create folder
        if (mimeType == Document.MIME_TYPE_DIR) {
            val folder = MegaClientHolder.createFolder(displayName, parentNode) ?: return null
            notifyChange(parentDocumentId)
            return folder.handle.toString()
        }

        // Create file: write an empty temp file, upload it
        val cacheDir = context?.cacheDir ?: return null
        val tempFile = File(cacheDir, displayName)
        tempFile.createNewFile()

        try {
            val uploaded = MegaClientHolder.uploadFile(tempFile.absolutePath, parentNode)
                ?: return null
            notifyChange(parentDocumentId)
            return uploaded.handle.toString()
        } finally {
            tempFile.delete()
        }
    }

    // ----- Delete -----

    override fun deleteDocument(documentId: String) {
        if (!ensureLoggedIn()) return

        val handle = documentId.toLongOrNull() ?: return
        val node = MegaClientHolder.getNodeByHandle(handle) ?: return
        val parentHandle = node.parentHandle

        MegaClientHolder.deleteNode(node)

        if (parentHandle != nz.mega.sdk.MegaApiJava.INVALID_HANDLE) {
            notifyChange(parentHandle.toString())
        }
    }

    // ----- isChildDocument -----

    override fun isChildDocument(parentDocumentId: String, documentId: String): Boolean {
        if (!ensureLoggedIn()) return false

        val parentHandle = parentDocumentId.toLongOrNull() ?: return false
        val childHandle = documentId.toLongOrNull() ?: return false

        var current = MegaClientHolder.getNodeByHandle(childHandle)
        while (current != null) {
            if (current.handle == parentHandle) return true
            current = MegaClientHolder.getNodeByHandle(current.parentHandle)
        }
        return false
    }

    // ----- Thumbnails (optional, returns null) -----

    override fun openDocumentThumbnail(
        documentId: String,
        sizeHint: Point?,
        signal: CancellationSignal?
    ): AssetFileDescriptor? = null

    // ----- Helpers -----

    private fun addNodeRow(cursor: MatrixCursor, node: MegaNode) {
        val mimeType = if (node.isFolder) {
            Document.MIME_TYPE_DIR
        } else {
            getMimeType(node.name)
        }

        var flags = 0
        if (node.isFolder) {
            flags = flags or Document.FLAG_DIR_SUPPORTS_CREATE
        }
        flags = flags or Document.FLAG_SUPPORTS_DELETE
        if (!node.isFolder) {
            flags = flags or Document.FLAG_SUPPORTS_WRITE
        }

        cursor.newRow().apply {
            add(Document.COLUMN_DOCUMENT_ID, node.handle.toString())
            add(Document.COLUMN_MIME_TYPE, mimeType)
            add(Document.COLUMN_DISPLAY_NAME, node.name)
            add(Document.COLUMN_LAST_MODIFIED, node.modificationTime * 1000L)
            add(Document.COLUMN_FLAGS, flags)
            add(Document.COLUMN_SIZE, if (node.isFolder) null else node.size)
        }
    }

    private fun getMimeType(fileName: String): String {
        val ext = fileName.substringAfterLast('.', "").lowercase()
        if (ext.isEmpty()) return "application/octet-stream"
        return MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext)
            ?: "application/octet-stream"
    }

    private fun resolveRootProjection(projection: Array<out String>?): Array<String> =
        projection?.toList()?.toTypedArray() ?: DEFAULT_ROOT_PROJECTION

    private fun resolveDocumentProjection(projection: Array<out String>?): Array<String> =
        projection?.toList()?.toTypedArray() ?: DEFAULT_DOCUMENT_PROJECTION

    private fun notifyChange(documentId: String) {
        val uri = DocumentsContract.buildChildDocumentsUri(AUTHORITY, documentId)
        context?.contentResolver?.notifyChange(uri, null)
    }
}
