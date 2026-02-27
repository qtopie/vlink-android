package rw.qtopie.vlink

import android.content.Context
import android.net.VpnService
import com.github.shadowsocks.plugin.PluginOptions
import java.io.File
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Socket
import java.net.URI

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
        val options = Settings.getOptions(context)

        // 2. VPN 系统权限检测
        results.add(checkVpnPermission())

        // 3. 系统架构检测
        results.add(checkArchitecture())

        // 4. TUN 虚拟网卡状态检测
        results.add(checkTunInterface())

        // 5. SOCKS Proxy 检测
        // 如果开启了 tun2socks 或者配置了 upstreamSocks，则进行检测
        if (options["tun2socks"] == "true" || !options["upstreamSocks"].isNullOrBlank()) {
            results.add(checkSocksTcp(options))
            results.add(checkSocksUdp(options))
        }

        // 6. 远程服务器连通性检测
        results.add(checkNetwork(options))

        // 7. 基础互联网连通性 (Ping 1.1.1.1)
        results.add(checkInternet())

        // 8. 插件日志详细面板
        results.add(checkPluginLogs())

        return results
    }

    private fun parseSocksAddr(options: PluginOptions): Pair<String, Int> {
        val upstream = options["upstreamSocks"]
        if (!upstream.isNullOrBlank()) {
            try {
                val uri = URI(upstream)
                if (uri.host != null) {
                    return Pair(uri.host, if (uri.port != -1) uri.port else 1080)
                }
            } catch (e: Exception) {
                // 简单的字符串解析兜底
                val clean = upstream.removePrefix("socks5://")
                if (clean.contains(":")) {
                    val host = clean.substringBefore(":")
                    val port = clean.substringAfter(":").toIntOrNull() ?: 1080
                    return Pair(host, port)
                }
            }
        }
        val port = options["local_port"]?.toIntOrNull() ?: 1080
        return Pair("127.0.0.1", port)
    }

    private fun Socket.readFully(buffer: ByteArray) {
        val inStream = getInputStream()
        var offset = 0
        while (offset < buffer.size) {
            val bytesRead = inStream.read(buffer, offset, buffer.size - offset)
            if (bytesRead == -1) throw Exception("Connection closed prematurely")
            offset += bytesRead
        }
    }

    private fun checkSocksTcp(options: PluginOptions): DiagnosticResult {
        val (host, port) = parseSocksAddr(options)
        val title = if (host == "127.0.0.1") "Local SOCKS5 TCP" else "Upstream SOCKS5 TCP"
        return try {
            val start = System.currentTimeMillis()
            val socket = Socket()
            socket.connect(InetSocketAddress(host, port), 2000)
            
            val outStream = socket.getOutputStream()
            
            // SOCKS5 Auth Request: [VER 5] [NMETHODS 1] [METHODS 0 (No Auth)]
            outStream.write(byteArrayOf(0x05, 0x01, 0x00))
            outStream.flush()
            
            val response = ByteArray(2)
            socket.readFully(response)
            socket.close()

            if (response[0] != 0x05.toByte() || response[1] != 0x00.toByte()) {
                 DiagnosticResult(title, Status.ERROR, "Handshake failed, response: ${response.contentToString()}")
            } else {
                 val delay = System.currentTimeMillis() - start
                 DiagnosticResult(title, Status.OK, "SOCKS5 TCP port $host:$port is reachable ($delay ms)")
            }
        } catch (e: Exception) {
            DiagnosticResult(title, Status.ERROR, "Failed to connect or handshake with SOCKS5 TCP $host:$port: ${e.message}")
        }
    }

    private fun checkSocksUdp(options: PluginOptions): DiagnosticResult {
        val (host, port) = parseSocksAddr(options)
        val title = if (host == "127.0.0.1") "Local SOCKS5 UDP" else "Upstream SOCKS5 UDP"
        var socket: Socket? = null
        return try {
            socket = Socket()
            socket.connect(InetSocketAddress(host, port), 2000)
            socket.soTimeout = 2000
            
            val outStream = socket.getOutputStream()
            val inStream = socket.getInputStream()
            
            // SOCKS5 Auth Request
            outStream.write(byteArrayOf(0x05, 0x01, 0x00))
            outStream.flush()
            val authResp = ByteArray(2)
            socket.readFully(authResp)
            if (authResp[1] != 0x00.toByte()) {
                throw Exception("TCP Auth failed")
            }

            // UDP Associate Request
            val udpAssocReq = byteArrayOf(0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
            outStream.write(udpAssocReq)
            outStream.flush()

            // Read UDP Associate Response Header
            val header = ByteArray(4)
            socket.readFully(header)
            
            if (header[1] != 0x00.toByte()) {
                throw Exception("UDP Associate request rejected, REP: ${header[1]}")
            }

            // Consume the rest of the address/port info
            val addrLen = when (header[3]) {
                0x01.toByte() -> 4 // IPv4
                0x04.toByte() -> 16 // IPv6
                0x03.toByte() -> {
                    val len = inStream.read()
                    if (len == -1) throw Exception("Failed to read domain length")
                    len
                }
                else -> throw Exception("Unknown ATYP: ${header[3]}")
            }
            val remaining = ByteArray(addrLen + 2)
            socket.readFully(remaining)

            DiagnosticResult(title, Status.OK, "SOCKS5 UDP Associate successful via $host:$port")
        } catch (e: Exception) {
            DiagnosticResult(title, Status.ERROR, "UDP Associate failed via $host:$port: ${e.message}")
        } finally {
            try { socket?.close() } catch (_: Exception) {}
        }
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

    private fun checkNetwork(options: PluginOptions): DiagnosticResult {
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
