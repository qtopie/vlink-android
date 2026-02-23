module github.com/qtopie/vlink/libvlink

go 1.25.6

require (
	github.com/qtopie/vlink v0.4.3
	golang.org/x/mobile v0.0.0-20260217195705-b56b3793a9c4
	golang.org/x/net v0.50.0
	golang.org/x/sys v0.41.0
	gvisor.dev/gvisor v0.0.0-20250523182742-eede7a881b20
)

require (
	github.com/adrg/xdg v0.5.3 // indirect
	github.com/cilium/ebpf v0.20.0 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/miekg/dns v1.1.68 // indirect
	github.com/pires/go-proxyproto v0.8.1 // indirect
	github.com/v2fly/v2ray-core/v5 v5.41.0 // indirect
	github.com/vishvananda/netlink v1.3.1 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/mod v0.33.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	golang.org/x/time v0.11.0 // indirect
	golang.org/x/tools v0.42.0 // indirect
	google.golang.org/genproto v0.0.0-20230110181048-76db0878b65f // indirect
	google.golang.org/grpc v1.76.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace gvisor.dev/gvisor => gvisor.dev/gvisor v0.0.0-20231020174304-b8a429915ff1

replace google.golang.org/genproto/googleapis/rpc => google.golang.org/genproto v0.0.0-20250818200422-3122310a409c

replace github.com/qtopierw/workspace/projects/vlink-android/app/src/main/golang => ./
