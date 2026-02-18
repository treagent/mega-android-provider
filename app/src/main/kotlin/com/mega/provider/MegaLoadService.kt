package com.mega.provider

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.*

/**
 * Foreground service that loads the MEGA node tree in the background.
 * Shows a persistent notification so Android won't kill the process.
 * Communicates back to FileBrowserActivity via MegaLoadState callbacks.
 */
class MegaLoadService : Service() {

    companion object {
        const val CHANNEL_ID = "mega_load"
        const val NOTIF_ID   = 1001
    }

    private var job: Job? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val notif = buildNotification("Connecting to MEGA…")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIF_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(NOTIF_ID, notif)
        }

        MegaLoadState.isLoading  = true
        MegaLoadState.loadError  = null
        MegaLoadState.lastStatus = "Connecting to MEGA…"

        job = CoroutineScope(Dispatchers.IO).launch {
            try {
                MegaClientHolder.fetchNodesRetry { status ->
                    MegaLoadState.lastStatus = status
                    MegaLoadState.onStatusUpdate?.invoke(status)
                    updateNotification(status)
                }
                MegaClientHolder.saveNodeCache(applicationContext)
                MegaLoadState.isLoading = false
                MegaLoadState.onComplete?.invoke()
                updateNotification("Files loaded ✓")
            } catch (e: Exception) {
                val msg = e.message ?: "Unknown error"
                MegaLoadState.isLoading  = false
                MegaLoadState.loadError  = msg
                MegaLoadState.onError?.invoke(msg)
                updateNotification("Error: $msg")
            } finally {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    stopForeground(STOP_FOREGROUND_REMOVE)
                } else {
                    @Suppress("DEPRECATION")
                    stopForeground(true)
                }
                stopSelf()
            }
        }

        return START_NOT_STICKY
    }

    override fun onDestroy() {
        job?.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "MEGA File Loading",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows progress while loading your MEGA files"
                setShowBadge(false)
            }
            getSystemService(NotificationManager::class.java)
                .createNotificationChannel(channel)
        }
    }

    private fun buildNotification(status: String): Notification {
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, FileBrowserActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
            },
            PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Loading MEGA files…")
            .setContentText(status)
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setContentIntent(pi)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun updateNotification(status: String) {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIF_ID, buildNotification(status))
    }
}
