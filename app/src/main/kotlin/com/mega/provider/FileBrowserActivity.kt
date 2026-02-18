package com.mega.provider

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.*
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.PopupMenu
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import kotlinx.coroutines.*

class FileBrowserActivity : AppCompatActivity() {

    private lateinit var recycler: RecyclerView
    private lateinit var progressBar: ProgressBar
    private lateinit var emptyText: TextView
    private lateinit var pathText: TextView

    private val navStack = mutableListOf<String?>()   // null = root
    private val adapter = NodeAdapter(
        emptyList(),
        onClick     = { node -> onNodeClick(node) },
        onLongClick = { node, anchor -> onNodeLongClick(node, anchor) }
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_file_browser)

        supportActionBar?.apply {
            title = "MEGA Files"
            setDisplayHomeAsUpEnabled(true)
        }

        recycler    = findViewById(R.id.file_list)
        progressBar = findViewById(R.id.file_progress)
        emptyText   = findViewById(R.id.empty_text)
        pathText    = findViewById(R.id.path_text)

        recycler.layoutManager = LinearLayoutManager(this)
        recycler.adapter = adapter

        loadFolder(null)   // load root
    }

    override fun onSupportNavigateUp(): Boolean {
        if (navStack.size > 1) {
            navStack.removeLastOrNull()
            loadFolder(navStack.lastOrNull())
            return true
        }
        finish()
        return true
    }

    override fun onBackPressed() {
        if (navStack.size > 1) {
            navStack.removeLastOrNull()
            loadFolder(navStack.lastOrNull())
        } else {
            super.onBackPressed()
        }
    }

    private fun onNodeClick(node: MegaNode) {
        if (node.isFolder) {
            navStack.add(node.handle)
            loadFolder(node.handle)
        } else {
            openFile(node)
        }
    }

    // ── Long-press: folder actions ────────────────────────────────────────

    private fun onNodeLongClick(node: MegaNode, anchor: View) {
        if (!node.isFolder) return
        val popup = PopupMenu(this, anchor)
        popup.menu.add(0, 1, 0, "🔢 Auto-organize numbered sub-folders")
        popup.setOnMenuItemClickListener { item ->
            if (item.itemId == 1) showReorgScan(node)
            true
        }
        popup.show()
    }

    private fun showReorgScan(folderNode: MegaNode) {
        val scanDialog = AlertDialog.Builder(this)
            .setTitle("Scanning…")
            .setMessage("Counting numbered sub-folders in \"${folderNode.name}\"…")
            .setCancelable(false)
            .create()
        scanDialog.show()

        CoroutineScope(Dispatchers.IO).launch {
            val count = try { MegaClientHolder.scanNumberedFolders(folderNode) } catch (_: Exception) { 0 }
            withContext(Dispatchers.Main) {
                scanDialog.dismiss()
                if (count == 0) {
                    Toast.makeText(this@FileBrowserActivity,
                        "No numbered sub-folders found in \"${folderNode.name}\".", Toast.LENGTH_SHORT).show()
                } else {
                    showReorgConfigDialog(folderNode, count)
                }
            }
        }
    }

    private fun showReorgConfigDialog(folderNode: MegaNode, count: Int) {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(72, 32, 72, 16)
        }

        container.addView(TextView(this).apply {
            text = "Found $count numbered sub-folders in\n\"${folderNode.name}\"."
            textSize = 14f
            setPadding(0, 0, 0, 28)
        })
        container.addView(TextView(this).apply {
            text = "Folders per group:"
            textSize = 14f
        })

        val chunkInput = EditText(this).apply {
            inputType = android.text.InputType.TYPE_CLASS_NUMBER
            setText("100")
            textSize = 16f
        }
        container.addView(chunkInput)

        val estimateText = TextView(this).apply {
            val g = (count + 99) / 100
            text = "→ Will create ~$g groups"
            textSize = 13f
            setTextColor(android.graphics.Color.GRAY)
            setPadding(0, 10, 0, 0)
        }
        container.addView(estimateText)

        chunkInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count2: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, c: Int) {}
            override fun afterTextChanged(s: Editable?) {
                val size = s.toString().toIntOrNull()?.coerceAtLeast(1) ?: 100
                val g = (count + size - 1) / size
                estimateText.text = "→ Will create ~$g groups"
            }
        })

        AlertDialog.Builder(this)
            .setTitle("Auto-organize: ${folderNode.name}")
            .setView(container)
            .setPositiveButton("▶ Start") { _, _ ->
                val chunkSize = chunkInput.text.toString().toIntOrNull()?.coerceIn(1, 10000) ?: 100
                startReorganization(folderNode, chunkSize, count)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun startReorganization(folderNode: MegaNode, chunkSize: Int, total: Int) {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(72, 32, 72, 32)
        }
        val statusText = TextView(this).apply { text = "Initializing…"; textSize = 13f }
        val progressBar = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
            max = total; progress = 0; setPadding(0, 16, 0, 4)
        }
        val countText = TextView(this).apply {
            text = "0 / $total"
            textSize = 12f
            setTextColor(android.graphics.Color.GRAY)
            gravity = android.view.Gravity.END
        }
        container.addView(statusText)
        container.addView(progressBar)
        container.addView(countText)

        val progressDialog = AlertDialog.Builder(this)
            .setTitle("Reorganizing…")
            .setView(container)
            .setCancelable(false)
            .create()
        progressDialog.show()

        CoroutineScope(Dispatchers.IO).launch {
            try {
                val result = MegaClientHolder.reorganizeNumberedFolders(folderNode, chunkSize) { done, tot, msg ->
                    runOnUiThread {
                        statusText.text = msg
                        progressBar.progress = done
                        countText.text = "$done / $tot"
                    }
                }
                withContext(Dispatchers.Main) {
                    progressDialog.dismiss()
                    val summary = buildString {
                        append("✅ Created ${result.groupsCreated} groups\n")
                        append("📁 Moved ${result.foldersMoved} folders")
                        if (result.errors > 0) append("\n⚠️ ${result.errors} errors")
                    }
                    AlertDialog.Builder(this@FileBrowserActivity)
                        .setTitle("Done!")
                        .setMessage(summary)
                        .setPositiveButton("OK") { _, _ -> loadFolder(navStack.lastOrNull()) }
                        .show()
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    progressDialog.dismiss()
                    Toast.makeText(this@FileBrowserActivity, "Error: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private val imageExts = setOf("jpg", "jpeg", "png", "gif", "webp", "heic", "bmp")
    private val videoExts = setOf("mp4", "mkv", "avi", "mov", "webm", "m4v", "3gp", "ts", "flv")
    private val audioExts = setOf("mp3", "aac", "flac", "wav", "ogg", "m4a", "opus")

    // Current folder's list — kept so the photo viewer can swipe through all images
    private var currentNodes: List<MegaNode> = emptyList()

    private fun openFile(node: MegaNode) {
        val ext = node.name.substringAfterLast('.', "").lowercase()

        if (ext in imageExts) {
            // Open full-screen swipeable gallery
            val imageNodes = currentNodes.filter {
                it.name.substringAfterLast('.', "").lowercase() in imageExts
            }
            val idx = imageNodes.indexOfFirst { it.handle == node.handle }.coerceAtLeast(0)
            val intent = android.content.Intent(this, PhotoViewerActivity::class.java).apply {
                putStringArrayListExtra(PhotoViewerActivity.EXTRA_HANDLES, ArrayList(imageNodes.map { it.handle }))
                putStringArrayListExtra(PhotoViewerActivity.EXTRA_NAMES,   ArrayList(imageNodes.map { it.name }))
                putExtra(PhotoViewerActivity.EXTRA_INDEX, idx)
            }
            startActivity(intent)
            return
        }

        val mimeType = when (ext) {
            in videoExts -> "video/*"
            in audioExts -> "audio/*"
            "pdf" -> "application/pdf"
            else -> "*/*"
        }

        Toast.makeText(this, "Getting stream URL…", Toast.LENGTH_SHORT).show()

        CoroutineScope(Dispatchers.IO).launch {
            try {
                val api = MegaClientHolder
                val url = api.getDownloadUrl(node.handle)

                withContext(Dispatchers.Main) {
                    val intent = android.content.Intent(android.content.Intent.ACTION_VIEW)
                    intent.setDataAndType(android.net.Uri.parse(url), mimeType)
                    intent.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)

                    // Try VLC first
                    intent.setPackage("org.videolan.vlc")
                    if (intent.resolveActivity(packageManager) != null) {
                        startActivity(intent)
                    } else {
                        // Fallback: any app that can handle this type
                        intent.setPackage(null)
                        try {
                            startActivity(android.content.Intent.createChooser(intent, "Open with…"))
                        } catch (e: Exception) {
                            Toast.makeText(this@FileBrowserActivity,
                                "No app found to open ${node.name}", Toast.LENGTH_LONG).show()
                        }
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@FileBrowserActivity,
                        "Stream error: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    // Whether a background node refresh is already running
    private var refreshRunning = false

    private fun loadFolder(handle: String?) {
        progressBar.visibility = View.VISIBLE
        emptyText.visibility   = View.GONE
        recycler.visibility    = View.GONE

        CoroutineScope(Dispatchers.IO).launch {
            val client = MegaClientHolder

            // ── Cache-first path ─────────────────────────────────────────
            if (!client.nodesLoaded) {
                val fromCache = client.loadNodeCache(applicationContext)
                if (fromCache) {
                    val children = getChildrenFromClient(client, handle)
                    withContext(Dispatchers.Main) {
                        showChildren(children, handle)
                        Toast.makeText(this@FileBrowserActivity,
                            "Showing cached files — refreshing in background…", Toast.LENGTH_SHORT).show()
                    }
                    if (!refreshRunning) {
                        refreshRunning = true
                        try {
                            client.refreshNodes()
                            client.saveNodeCache(applicationContext)
                            val fresh = getChildrenFromClient(client, handle)
                            withContext(Dispatchers.Main) { showChildren(fresh, handle) }
                        } catch (_: Exception) { /* keep showing cached data */ }
                        finally { refreshRunning = false }
                    }
                    return@launch
                }
            }

            // ── Fresh fetch — start foreground service ────────────────────
            if (!client.nodesLoaded) {
                withContext(Dispatchers.Main) {
                    if (MegaLoadState.isLoading) {
                        reattachServiceCallbacks(handle)  // already running
                    } else {
                        startMegaLoadService(handle)
                    }
                }
                return@launch  // service fires onComplete → calls loadFolder again
            }

            // Nodes now loaded — show folder
            try {
                val children = getChildrenFromClient(client, handle)
                withContext(Dispatchers.Main) { showChildren(children, handle) }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    showRetryButton(handle, "Error: ${e.message}")
                }
            }
        }
    }

    // ── Foreground service management ─────────────────────────────────────

    override fun onResume() {
        super.onResume()
        when {
            MegaLoadState.isLoading -> {
                // Service still running — re-attach callbacks
                reattachServiceCallbacks(navStack.lastOrNull())
            }
            MegaClientHolder.nodesLoaded && recycler.visibility != View.VISIBLE -> {
                // Service finished while we were away — show files now
                loadFolder(navStack.lastOrNull())
            }
            !MegaClientHolder.nodesLoaded && MegaLoadState.loadError != null -> {
                // Service failed while we were away
                showRetryButton(navStack.lastOrNull(), MegaLoadState.loadError!!)
            }
        }
    }

    override fun onPause() {
        clearServiceCallbacks()
        super.onPause()
    }

    private fun startMegaLoadService(handle: String?) {
        progressBar.visibility = View.GONE
        recycler.visibility    = View.GONE
        emptyText.text         = "⏳ Loading MEGA files in background…\nYou can switch apps — it keeps running."
        emptyText.visibility   = View.VISIBLE

        MegaLoadState.onStatusUpdate = { status ->
            runOnUiThread { emptyText.text = "⏳ $status" }
        }
        MegaLoadState.onComplete = {
            runOnUiThread { clearServiceCallbacks(); loadFolder(handle) }
        }
        MegaLoadState.onError = { error ->
            runOnUiThread { clearServiceCallbacks(); showRetryButton(handle, error) }
        }

        val intent = Intent(this, MegaLoadService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    private fun reattachServiceCallbacks(handle: String?) {
        progressBar.visibility = View.GONE
        recycler.visibility    = View.GONE
        emptyText.text = if (MegaLoadState.lastStatus.isNotEmpty())
            "⏳ ${MegaLoadState.lastStatus}"
        else
            "⏳ Loading MEGA files in background…\nYou can switch apps — it keeps running."
        emptyText.visibility = View.VISIBLE

        MegaLoadState.onStatusUpdate = { status ->
            runOnUiThread { emptyText.text = "⏳ $status" }
        }
        MegaLoadState.onComplete = {
            runOnUiThread { clearServiceCallbacks(); loadFolder(handle) }
        }
        MegaLoadState.onError = { error ->
            runOnUiThread { clearServiceCallbacks(); showRetryButton(handle, error) }
        }
    }

    private fun clearServiceCallbacks() {
        MegaLoadState.onStatusUpdate = null
        MegaLoadState.onComplete     = null
        MegaLoadState.onError        = null
    }

    private fun showRetryButton(handle: String?, errorMsg: String) {
        progressBar.visibility = View.GONE
        emptyText.text = "$errorMsg\n\nTap Retry to try again."
        emptyText.visibility = View.VISIBLE
        // Re-use the empty text view as a clickable retry button
        emptyText.setOnClickListener {
            emptyText.setOnClickListener(null)
            MegaClientHolder.clearNodeCache(applicationContext)
            loadFolder(handle)
        }
    }

    private fun getChildrenFromClient(client: MegaClientHolder, handle: String?): List<MegaNode> {
        return if (handle == null) {
            val root = client.getRootNode()
            if (root != null) client.getChildren(root) else emptyList()
        } else {
            val node = client.getNodeByHandle(handle) ?: return emptyList()
            client.getChildren(node)
        }
    }

    private fun showChildren(children: List<MegaNode>, handle: String?) {
        progressBar.visibility = View.GONE
        val path = if (handle == null) "/ (root)" else "/$handle"
        pathText.text = path

        if (children.isEmpty()) {
            emptyText.text = "Empty folder"
            emptyText.visibility = View.VISIBLE
        } else {
            val sorted = children.sortedWith(compareBy({ !it.isFolder }, { it.name.lowercase() }))
            currentNodes = sorted
            adapter.update(sorted)
            recycler.visibility = View.VISIBLE
        }
    }

    private fun formatSize(bytes: Long): String = when {
        bytes < 1024 -> "$bytes B"
        bytes < 1024 * 1024 -> "${bytes / 1024} KB"
        bytes < 1024 * 1024 * 1024 -> "${bytes / (1024 * 1024)} MB"
        else -> "${bytes / (1024 * 1024 * 1024)} GB"
    }

    // ── Adapter ───────────────────────────────────────────────────────────

    inner class NodeAdapter(
        private var nodes: List<MegaNode>,
        private val onClick: (MegaNode) -> Unit,
        private val onLongClick: (MegaNode, View) -> Unit = { _, _ -> }
    ) : RecyclerView.Adapter<NodeAdapter.VH>() {

        fun update(list: List<MegaNode>) { nodes = list; notifyDataSetChanged() }

        inner class VH(v: View) : RecyclerView.ViewHolder(v) {
            val icon: TextView = v.findViewById(R.id.node_icon)
            val name: TextView = v.findViewById(R.id.node_name)
            val info: TextView = v.findViewById(R.id.node_info)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH =
            VH(LayoutInflater.from(parent.context).inflate(R.layout.item_node, parent, false))

        override fun getItemCount() = nodes.size

        override fun onBindViewHolder(vh: VH, pos: Int) {
            val n = nodes[pos]
            vh.icon.text = if (n.isFolder) "📁" else "📄"
            vh.name.text = n.name
            vh.info.text = if (n.isFolder) "Folder" else formatSize(n.size)
            vh.itemView.setOnClickListener { onClick(n) }
            vh.itemView.setOnLongClickListener { onLongClick(n, it); true }
        }
    }
}
