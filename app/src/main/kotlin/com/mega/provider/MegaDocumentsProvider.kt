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
import java.io.File
import java.io.FileOutputStream

class MegaDocumentsProvider : DocumentsProvider() {

    companion object {
        private const val AUTHORITY = "com.mega.provider.documents"
        private const val ROOT_ID   = "mega_root"

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

    override fun onCreate(): Boolean = true

    private fun ensureLoggedIn(): Boolean {
        if (MegaClientHolder.isLoggedIn) return true
        val ctx = context ?: return false
        val session = MegaSessionManager.getSession(ctx) ?: return false
        return MegaClientHolder.fastLogin(session)
    }

    // ── Roots ──────────────────────────────────────────────────────────────

    override fun queryRoots(projection: Array<out String>?): Cursor {
        val result = MatrixCursor(resolveRootProjection(projection))
        if (!ensureLoggedIn()) return result

        val rootNode = MegaClientHolder.getRootNode() ?: return result

        result.newRow().apply {
            add(Root.COLUMN_ROOT_ID,      ROOT_ID)
            add(Root.COLUMN_MIME_TYPES,   "*/*")
            add(Root.COLUMN_FLAGS,
                Root.FLAG_SUPPORTS_CREATE or
                Root.FLAG_SUPPORTS_IS_CHILD or
                Root.FLAG_SUPPORTS_RECENTS)
            add(Root.COLUMN_ICON,         R.drawable.ic_mega)
            add(Root.COLUMN_TITLE,        "MEGA")
            add(Root.COLUMN_SUMMARY,      "MEGA Cloud Drive")
            add(Root.COLUMN_DOCUMENT_ID,  rootNode.handle)
        }
        return result
    }

    // ── Documents ──────────────────────────────────────────────────────────

    override fun queryDocument(documentId: String, projection: Array<out String>?): Cursor {
        val result = MatrixCursor(resolveDocumentProjection(projection))
        if (!ensureLoggedIn()) return result
        val node = MegaClientHolder.getNodeByHandle(documentId) ?: return result
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
        val parent = MegaClientHolder.getNodeByHandle(parentDocumentId) ?: return result
        MegaClientHolder.getChildren(parent).forEach { addNodeRow(result, it) }
        return result
    }

    // ── Open / read / write ────────────────────────────────────────────────

    override fun openDocument(
        documentId: String,
        mode: String,
        signal: CancellationSignal?
    ): ParcelFileDescriptor? {
        if (!ensureLoggedIn()) return null
        val node = MegaClientHolder.getNodeByHandle(documentId) ?: return null

        if ("r" in mode) {
            val cacheDir = context?.cacheDir ?: return null
            val tmp = File(cacheDir, "mega_${node.handle}_${node.name}")
            if (!tmp.exists() || tmp.length() != node.size) {
                MegaClientHolder.downloadFile(node, tmp.absolutePath)
            }
            return ParcelFileDescriptor.open(tmp, ParcelFileDescriptor.MODE_READ_ONLY)
        }

        if ("w" in mode) {
            val cacheDir = context?.cacheDir ?: return null
            val tmp = File(cacheDir, "mega_upload_${node.handle}_${node.name}")
            val parentNode = MegaClientHolder.getNodeByHandle(node.parentHandle) ?: return null
            val pipe = ParcelFileDescriptor.createReliablePipe()
            val readFd = pipe[0]
            val writeFd = pipe[1]
            Thread {
                try {
                    ParcelFileDescriptor.AutoCloseInputStream(readFd).use { input ->
                        FileOutputStream(tmp).use { input.copyTo(it) }
                    }
                    MegaClientHolder.uploadFile(tmp.absolutePath, parentNode)
                } finally {
                    tmp.delete()
                }
            }.start()
            return writeFd
        }

        return null
    }

    // ── Create ─────────────────────────────────────────────────────────────

    override fun createDocument(
        parentDocumentId: String,
        mimeType: String,
        displayName: String
    ): String? {
        if (!ensureLoggedIn()) return null
        val parent = MegaClientHolder.getNodeByHandle(parentDocumentId) ?: return null

        if (mimeType == Document.MIME_TYPE_DIR) {
            val folder = MegaClientHolder.createFolder(displayName, parent) ?: return null
            notifyChange(parentDocumentId)
            return folder.handle
        }

        val tmp = File(context?.cacheDir, displayName)
        tmp.createNewFile()
        return try {
            val uploaded = MegaClientHolder.uploadFile(tmp.absolutePath, parent) ?: return null
            notifyChange(parentDocumentId)
            uploaded.handle
        } finally {
            tmp.delete()
        }
    }

    // ── Delete ─────────────────────────────────────────────────────────────

    override fun deleteDocument(documentId: String) {
        if (!ensureLoggedIn()) return
        val node = MegaClientHolder.getNodeByHandle(documentId) ?: return
        val parentHandle = node.parentHandle
        MegaClientHolder.deleteNode(node)
        if (parentHandle.isNotEmpty()) notifyChange(parentHandle)
    }

    // ── isChildDocument ────────────────────────────────────────────────────

    override fun isChildDocument(parentDocumentId: String, documentId: String): Boolean {
        if (!ensureLoggedIn()) return false
        return MegaClientHolder.isChildOf(parentDocumentId, documentId)
    }

    // ── Thumbnails (not implemented) ───────────────────────────────────────

    override fun openDocumentThumbnail(
        documentId: String,
        sizeHint: Point?,
        signal: CancellationSignal?
    ): AssetFileDescriptor? = null

    // ── Helpers ────────────────────────────────────────────────────────────

    private fun addNodeRow(cursor: MatrixCursor, node: MegaNode) {
        val mime = if (node.isFolder) Document.MIME_TYPE_DIR else getMime(node.name)
        var flags = 0
        if (node.isFolder) flags = flags or Document.FLAG_DIR_SUPPORTS_CREATE
        flags = flags or Document.FLAG_SUPPORTS_DELETE
        if (!node.isFolder) flags = flags or Document.FLAG_SUPPORTS_WRITE

        cursor.newRow().apply {
            add(Document.COLUMN_DOCUMENT_ID,   node.handle)
            add(Document.COLUMN_MIME_TYPE,      mime)
            add(Document.COLUMN_DISPLAY_NAME,   node.name)
            add(Document.COLUMN_LAST_MODIFIED,  node.modificationTime * 1000L)
            add(Document.COLUMN_FLAGS,          flags)
            add(Document.COLUMN_SIZE,           if (node.isFolder) null else node.size)
        }
    }

    private fun getMime(name: String): String {
        val ext = name.substringAfterLast('.', "").lowercase()
        if (ext.isEmpty()) return "application/octet-stream"
        return MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext)
            ?: "application/octet-stream"
    }

    private fun resolveRootProjection(p: Array<out String>?) =
        p?.toList()?.toTypedArray() ?: DEFAULT_ROOT_PROJECTION

    private fun resolveDocumentProjection(p: Array<out String>?) =
        p?.toList()?.toTypedArray() ?: DEFAULT_DOCUMENT_PROJECTION

    private fun notifyChange(documentId: String) {
        val uri = DocumentsContract.buildChildDocumentsUri(AUTHORITY, documentId)
        context?.contentResolver?.notifyChange(uri, null)
    }
}
