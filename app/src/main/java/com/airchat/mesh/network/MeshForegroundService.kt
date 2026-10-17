package com.airchat.mesh.network

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.airchat.mesh.MeshApp
import com.airchat.mesh.ui.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel

/**
 * Foreground service that keeps the mesh engine (and therefore packet relaying)
 * alive while the app is backgrounded. Uses the connected-device foreground
 * service type introduced for exactly this class of local-radio work.
 */
class MeshForegroundService : Service() {

    companion object {
        const val CHANNEL_ID = "airchat_mesh"
        const val NOTIFICATION_ID = 42
        const val ACTION_START = "com.airchat.mesh.action.START"
        const val ACTION_STOP = "com.airchat.mesh.action.STOP"

        fun start(context: Context) {
            val intent = Intent(context, MeshForegroundService::class.java).setAction(ACTION_START)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                @Suppress("DEPRECATION")
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            val intent = Intent(context, MeshForegroundService::class.java).setAction(ACTION_STOP)
            context.startService(intent)
        }
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onCreate() {
        super.onCreate()
        createChannel()
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
            )
        } else {
            @Suppress("DEPRECATION")
            startForeground(NOTIFICATION_ID, notification)
        }
        (application as MeshApp).engine.start()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            (application as MeshApp).engine.stop()
            stopSelf()
            return START_NOT_STICKY
        }
        return START_STICKY
    }

    override fun onDestroy() {
        (application as MeshApp).engine.stop()
        serviceScope.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createChannel() {
        val manager = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            CHANNEL_ID,
            "AIRCHAT Mesh",
            NotificationManager.IMPORTANCE_LOW
        ).apply { description = "Keeps the local mesh network alive" }
        manager.createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("AIRCHAT mesh active")
            .setContentText("Relaying encrypted packets for nearby peers")
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setContentIntent(openIntent)
            .setOngoing(true)
            .build()
    }
}
