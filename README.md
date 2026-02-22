# vlink android

流量出站: vpn -> tun.go -> socks5 -> shadowsocks(encrypted) -> v2ray-grpc -> cdn -> server

流量出站: vpn -> tun.go -> socks5 -> upstream socks5代理

流量出站: vpn -> tun.go -> socks5 -> socks5://192.168.31.63:1080