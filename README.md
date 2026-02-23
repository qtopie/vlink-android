# vlink android

流量出站: vpn -> tun.go -> socks5 -> shadowsocks(encrypted) -> v2ray-grpc -> cdn -> server

流量出站: vpn -> tun.go -> socks5 -> upstream socks5代理

流量出站: vpn -> tun.go -> socks5 -> socks5://192.168.31.63:1080

   1. 创建设备： 
sudo bash ./app/scripts/setup_vlink0.sh
   2. 运行本地测试： sudo app/scripts/run_vlink_local.sh
   3. 停止并删除设备： sudo app/scripts/teardown_vlink0.sh

