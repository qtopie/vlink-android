# vlink android

流量出站: vpn -> tun.go -> socks5 -> shadowsocks(encrypted) -> v2ray-grpc -> cdn -> server

流量出站: vpn -> tun.go -> socks5 -> upstream socks5代理

流量出站: vpn -> tun.go -> socks5 -> socks5://192.168.31.63:1080

## 本地测试
1. 创建设备： make setup
2. 运行本地测试： make local
3. 停止并删除设备： make teardown

## 构建apk

```bash
./gradlew :app:assembleDebug
```

https://github.com/xjasonlyu/tun2socks/issues/123