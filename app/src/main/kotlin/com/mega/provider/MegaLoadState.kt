package com.mega.provider

/**
 * Shared state between MegaLoadService and FileBrowserActivity.
 * The service writes; the Activity reads and registers callbacks.
 */
object MegaLoadState {
    @Volatile var isLoading: Boolean = false
    @Volatile var lastStatus: String = ""
    @Volatile var loadError: String? = null

    // Callbacks — set by Activity, cleared in onPause, re-attached in onResume
    @Volatile var onStatusUpdate: ((String) -> Unit)? = null
    @Volatile var onComplete: (() -> Unit)? = null
    @Volatile var onError: ((String) -> Unit)? = null
}
