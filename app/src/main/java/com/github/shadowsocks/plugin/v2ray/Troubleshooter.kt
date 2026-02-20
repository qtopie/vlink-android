package com.github.shadowsocks.plugin.v2ray

import android.content.Context
import android.net.VpnService
import java.io.File
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Socket

class Troubleshooter(private val context: Context) {
    
    data class DiagnosticResult(
        val title: String,
        val status: Status,
        val message: String
    )

    enum class Status {
        OK, WARNING, ERROR
    }

    fun runDiagnostics(): List<DiagnosticResult> {
        val results = mutableListOf<DiagnosticResult>()

        // 1. 核心二进制文件检测 (libvlink.so)
        results.add(checkBinary())

        // 2. VPN 系统权限检测
        results.add(checkVpnPermission())

        // 3. 系统架构检测
        results.add(checkArchitecture())

        // 4. TUN 虚拟网卡状态检测 (替代原有的 1080 端口检测)
        results.add(checkTunInterface())

        // 5. 远程服务器连通性检测
        results.add(checkNetwork())

        // 6. 基础互联网连通性 (Ping 1.1.1.1)
        results.add(checkInternet())

        // 7. 插件日志详细面板
        results.add(checkPluginLogs())

        return results
    }

    private fun checkInternet(): DiagnosticResult {
        return try {
            val start = System.currentTimeMillis()
            val socket = Socket()
            // 尝试连接 Cloudflare DNS 的 53 端口 (TCP)
            socket.connect(InetSocketAddress("1.1.1.1", 53), 2000)
            val delay = System.currentTimeMillis() - start
            socket.close()
            DiagnosticResult("Internet Path", Status.OK, "Successfully reached 1.1.1.1:53 via VPN in $delay ms")
        } catch (e: Exception) {
            DiagnosticResult("Internet Path", Status.ERROR, "Cannot reach 1.1.1.1. Traffic is not passing through TUN or proxy is failing: ${e.message}")
        }
    }

    /**
     * 读取并展示插件的详细运行日志
     */
    private fun checkPluginLogs(): DiagnosticResult {
        val logFile = File(context.cacheDir, "vlink.log")
        if (!logFile.exists()) {
            return DiagnosticResult("Plugin Logs", Status.WARNING, "No logs found. Start the VPN first.")
        }

        return try {
            val lines = logFile.readLines()
            val lastLines = if (lines.size > 100) lines.takeLast(100) else lines
            val logText = lastLines.joinToString("\n")
            
            if (logText.isBlank()) {
                DiagnosticResult("Plugin Logs", Status.WARNING, "Log file is empty.")
            } else {
                DiagnosticResult("Detailed Logs", Status.OK, logText)
            }
        } catch (e: Exception) {
            DiagnosticResult("Plugin Logs", Status.ERROR, "Failed to read logs: ${e.message}")
        }
    }

    /**
     * 检测 TUN 网卡是否已在系统层建立。
     * 在 TUN 直连模式下，这是判定链路是否“活着”的关键。
     */
    private fun checkTunInterface(): DiagnosticResult {
        return try {
            val interfaces = NetworkInterface.getNetworkInterfaces()
            var foundTun = false
            while (interfaces?.hasMoreElements() == true) {
                val ni = interfaces.nextElement()
                if (ni.name.contains("tun", ignoreCase = true)) {
                    foundTun = true
                    break
                }
            }
            if (foundTun) {
                DiagnosticResult("TUN Interface", Status.OK, "Virtual network interface is ACTIVE.")
            } else {
                DiagnosticResult("TUN Interface", Status.WARNING, "No active TUN interface found. Start the VPN service first.")
            }
        } catch (e: Exception) {
            DiagnosticResult("TUN Interface", Status.ERROR, "Failed to query network interfaces: ${e.message}")
        }
    }

    private fun checkBinary(): DiagnosticResult {
        val path = context.applicationInfo.nativeLibraryDir + "/libvlink.so"
        val file = File(path)
        
        if (!file.exists()) {
            return DiagnosticResult("Binary Check", Status.ERROR, "Critical: libvlink.so NOT found at $path")
        }

        return DiagnosticResult("Binary Check", Status.OK, "Native library found: $path")
    }

    private fun checkVpnPermission(): DiagnosticResult {
        val intent = VpnService.prepare(context)
        return if (intent == null) {
            DiagnosticResult("VPN Permission", Status.OK, "Permission granted.")
        } else {
            DiagnosticResult("VPN Permission", Status.WARNING, "Permission not granted.")
        }
    }

    private fun checkArchitecture(): DiagnosticResult {
        val abi = android.os.Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown"
        return DiagnosticResult("Architecture", Status.OK, "Device ABI: $abi")
    }

    private fun checkNetwork(): DiagnosticResult {
        val options = Settings.getOptions(context)
        val host = options["server_address"]
        val portStr = options["server_port"]
        
        if (host.isNullOrBlank() || portStr.isNullOrBlank()) {
            return DiagnosticResult("Server Connectivity", Status.WARNING, "Server address or port not configured.")
        }
        
        val port = portStr.toIntOrNull() ?: return DiagnosticResult("Server Connectivity", Status.ERROR, "Invalid port: $portStr")

        return try {
            val start = System.currentTimeMillis()
            val socket = Socket()
            socket.connect(InetSocketAddress(host, port), 2000) 
            val delay = System.currentTimeMillis() - start
            socket.close()
            DiagnosticResult("Server Latency", Status.OK, "Connected to remote server: $delay ms")
        } catch (e: Exception) {
            DiagnosticResult("Server Latency", Status.ERROR, "Remote server UNREACHABLE: ${e.message}")
        }
    }
}
