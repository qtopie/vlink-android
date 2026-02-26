# vlink android

流量出站: vpn -> tun.go -> socks5 -> shadowsocks(encrypted) -> v2ray-grpc -> cdn -> server

流量出站: vpn -> tun.go -> socks5 -> upstream socks5代理

流量出站: vpn -> tun.go -> socks5 -> socks5://192.168.31.63:1080

## 运行要求与权限 (Permissions)

### Linux 客户端
在 Linux 环境下运行 `vlink_client` 必须使用 **`sudo`** 或拥有 root 权限。
**原因**：
1. **创建虚拟网卡**：程序需要调用内核接口创建 `tun` 设备（如 `vlink0`），这是特权操作。
2. **eBPF 透明代理**：为了实现透明代理而不修改应用配置，程序会加载 eBPF 程序到内核，并挂载 cgroup2 路径（通常在 `/sys/fs/cgroup/vproxy`），这些操作均需要 root 权限。
3. **防止流量回环**：程序通过 `SO_MARK` 选项标记代理后的流量，确保它们能绕过拦截逻辑。设置 socket mark 需要 `CAP_NET_ADMIN` 权限。

### Android 客户端
Android 版通过标准的 `VpnService` 运行。
* **注意**：程序内部会自动启动一个 SOCKS5 桥接服务，并由 gVisor 协议栈完成流量捕获与转换。如果遇到不通，请优先检查 Troubleshooter 中的诊断信息。

## 常见问题排查 (Troubleshooting)
如果连接成功但无法上网：
1. **MTU 问题**：默认 MTU 已设为 1280 以兼容各类链路。如果仍不通，请检查服务器网卡 MTU。
2. **DNS 解析**：确保已配置有效的 DNS 服务器（如 8.8.8.8）。
3. **UDP 转发**：某些公共 WiFi 可能会拦截非 53 端口的 UDP 流量，导致 UDP Associate 失败。

## 本地测试
1. 创建设备： make setup
2. 运行本地测试： make local
3. 停止并删除设备： make teardown

## 构建apk

```bash
./gradlew :app:assembleDebug
```

https://github.com/xjasonlyu/tun2socks/issues/123