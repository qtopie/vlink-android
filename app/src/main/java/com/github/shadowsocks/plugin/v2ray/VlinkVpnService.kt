package com.github.shadowsocks.plugin.v2ray

import android.content.Intent
import android.net.TrafficStats
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import com.github.shadowsocks.plugin.PluginOptions
import java.io.File
import java.io.IOException

class VlinkVpnService : VpnService() {
    companion object {
        private const val TAG = "VlinkVpnService"
        const val ACTION_START = "com.github.shadowsocks.plugin.v2ray.START"
        const val ACTION_STOP = "com.github.shadowsocks.plugin.v2ray.STOP"
        const val BROADCAST_STATS = "com.github.shadowsocks.plugin.v2ray.STATS"
        const val EXTRA_SPEED_UP = "extra_speed_up"
        const val EXTRA_SPEED_DOWN = "extra_speed_down"
        const val EXTRA_STATE = "extra_state"

        const val MTU = 1200

        @Volatile
        private var INSTANCE: VlinkVpnService? = null

        init {
            System.loadLibrary("vlink")
        }

        // Called from native code to ask VpnService to protect a socket FD.
        @JvmStatic
        fun protectFd(fd: Int): Boolean {
            return try {
                INSTANCE?.protect(fd) ?: false
            } catch (e: Exception) {
                false
            }
        }
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var statsHandler = Handler(Looper.getMainLooper())
    private var lastRxBytes: Long = 0
    private var lastTxBytes: Long = 0
    private var isRunning = false
    
    private external fun startVLinkNative(
        fd: Int,
        server: String,
        host: String,
        userAgent: String,
        serviceName: String,
        tunAddr: String,
        upstreamSocks: String,
        tunMTU: Int,
        verbose: Boolean,
        logPath: String
    )

    private val statsRunnable = object : Runnable {
        override fun run() {
            if (!isRunning) return
            val currentRxBytes = TrafficStats.getTotalRxBytes()
            val currentTxBytes = TrafficStats.getTotalTxBytes()
            val downSpeed = if (lastRxBytes > 0) (currentRxBytes - lastRxBytes) else 0
            val upSpeed = if (lastTxBytes > 0) (currentTxBytes - lastTxBytes) else 0
            lastRxBytes = currentRxBytes
            lastTxBytes = currentTxBytes

            // Enhanced logging for debugging
            Log.d(TAG, "DownSpeed: ${formatSpeed(downSpeed)}, UpSpeed: ${formatSpeed(upSpeed)}")

            sendBroadcast(Intent(BROADCAST_STATS).apply {
                putExtra(EXTRA_SPEED_DOWN, formatSpeed(downSpeed))
                putExtra(EXTRA_SPEED_UP, formatSpeed(upSpeed))
                putExtra(EXTRA_STATE, true)
            })
            statsHandler.postDelayed(this, 1000)
        }
    }

    private fun formatSpeed(bytes: Long): String {
        val speed = bytes.toDouble()
        return when {
            speed >= 1024 * 1024 -> String.format("%.1f MB/s", speed / (1024 * 1024))
            speed >= 1024 -> String.format("%.1f KB/s", speed / 1024)
            else -> "$bytes B/s"
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startVpn()
            ACTION_STOP -> stopVpn()
        }
        return START_STICKY
    }

    private fun startVLink(options: PluginOptions, fd: Int) {
        try {
            val serverUrl = "ss://${options["encrypt_method"]}:${options["password"]}@${options["server_address"]}:${options["server_port"]}"
            val tunAddr = "172.19.0.2/30"
            val logPath = File(cacheDir, "vlink.log").absolutePath
            
            Log.i(TAG, "Starting vlink via JNI (FD: $fd, Log: $logPath)")
            
            startVLinkNative(
                fd = fd,
                server = serverUrl,
                host = options["host"] ?: "qtopie.space",
                userAgent = options["userAgent"] ?: "",
                serviceName = options["serviceName"] ?: "moon.shot",
                tunAddr = tunAddr,
                upstreamSocks = options["upstreamSocks"] ?: "socks5://192.168.31.63:1080",
                tunMTU = MTU,
                verbose = options["verbose"] == "true",
                logPath = logPath
            )

            Log.i(TAG, "vlink native call initiated with FD $fd")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start vlink native", e)
            throw e
        }
    }

    private fun startVpn() {
        if (isRunning) return
        INSTANCE = this
        try {
            val options = Settings.getOptions(this)

            // 1. Establish VPN Interface
            val builder = Builder()
                .setSession("vlink")
                .setMtu(MTU)
                .addAddress("172.19.0.1", 30) // Go side will be 172.19.0.2
                .addDnsServer("223.5.5.5")
                .addDnsServer("223.6.6.6")
                .addAllowedApplication("com.android.chrome")
//                .addAllowedApplication("com.google.android.apps.bard")
                .addRoute("0.0.0.0", 0)


            val vpnInterface = builder.establish() ?: throw IOException("Failed to establish VPN interface")

            // 2. Start vlink unified binary (TUN + Encryption + Transport)
            startVLink(options, vpnInterface.fd)

            isRunning = true
            lastRxBytes = TrafficStats.getTotalRxBytes()
            lastTxBytes = TrafficStats.getTotalTxBytes()
            statsHandler.post(statsRunnable)
            Log.i(TAG, "VLink Proxy Active")
        } catch (e: Exception) {
            Log.e(TAG, "VPN Start Failed", e)
            stopVpn()
        }
    }

    private fun stopVpn() {
        isRunning = false
        INSTANCE = null
        statsHandler.removeCallbacks(statsRunnable)
        
        sendBroadcast(Intent(BROADCAST_STATS).apply { putExtra(EXTRA_STATE, false) })
        try { vpnInterface?.close() } catch (e: Exception) { }
        vpnInterface = null
        stopSelf()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }
}
