//go:build !confonly
// +build !confonly

package grpc

import (
	"context"
	stdtls "crypto/tls"
	gonet "net"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	core "github.com/v2fly/v2ray-core/v5"
	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/environment"
	"github.com/v2fly/v2ray-core/v5/common/environment/envctx"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/session"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
	"github.com/v2fly/v2ray-core/v5/transport/internet/grpc/encoding"
	"github.com/v2fly/v2ray-core/v5/transport/internet/tls"
)

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (internet.Connection, error) {
	newError("creating connection to ", dest).WriteToLog(session.ExportIDToError(ctx))

	conn, err := dialgRPC(ctx, dest, streamSettings)
	if err != nil {
		return nil, newError("failed to dial Grpc").Base(err)
	}
	return internet.Connection(conn), nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}

type transportConnectionState struct {
	scopedDialerMap    map[net.Destination]*grpc.ClientConn
	scopedDialerAccess sync.Mutex
}

func (t *transportConnectionState) IsTransientStorageLifecycleReceiver() {
}

func (t *transportConnectionState) Close() error {
	t.scopedDialerAccess.Lock()
	defer t.scopedDialerAccess.Unlock()
	for _, conn := range t.scopedDialerMap {
		_ = conn.Close()
	}
	t.scopedDialerMap = nil
	return nil
}

type dialerCanceller func()

func buildClientConn(ctx context.Context, target, authority string, creds credentials.TransportCredentials, extraOpts ...grpc.DialOption) (*grpc.ClientConn, error) {
	opts := []grpc.DialOption{
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second, // Ping 间隔（建议 >=25s 以适配 Cloudflare）
			Timeout:             10 * time.Second, // Ping 超时
			PermitWithoutStream: true,
		}),
		grpc.WithTransportCredentials(creds),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  500 * time.Millisecond,
				Multiplier: 1.5,
				Jitter:     0.2,
				MaxDelay:   19 * time.Second,
			},
			MinConnectTimeout: 5 * time.Second,
		}),
		// 增加默认回执窗口大小，防止大数据包卡死
    grpc.WithInitialWindowSize(65535 * 32),
    grpc.WithInitialConnWindowSize(65535 * 32),
	}
	if authority != "" {
		opts = append(opts, grpc.WithAuthority(authority))
	}
	// 这里无法完全去除go user-agent的关键词，但是cloudflare暂时不会拦截
	// 如果后续还是被拦截，可以设置出口流量为grpc insecure, 然后在代理层修改user-agent头后，再由tls加密发送出去
	// 类似于服务器端实际由caddy完成tls解密。中间件可以考虑使用envoy
	if ua := os.Getenv("GRPC_USER_AGENT"); ua != "" {
		opts = append(opts, grpc.WithUserAgent(ua))
	}
	opts = append(opts, extraOpts...)
	cc, err := grpc.NewClient(target, opts...)
	if err != nil {
		return nil, err
	}
	// Optional: honor ctx cancellation early by closing the conn if ctx done.
	if ctx != nil {
		go func() {
			<-ctx.Done()
			if cc.GetState() != connectivity.Shutdown {
				_ = cc.Close()
			}
		}()
	}
	return cc, nil
}

func dialgRPC(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (net.Conn, error) {
	grpcSettings := streamSettings.ProtocolSettings.(*Config)

	config := tls.ConfigFromStreamSettings(streamSettings)

	transportCredentials := insecure.NewCredentials()
	if config != nil {
		transportCredentials = credentials.NewTLS(config.GetTLSConfig(tls.WithDestination(dest)))
	}

	// 仅保留必要拦截器等自定义选项；默认的 TransportCredentials/User-Agent/Backoff/Keepalive 交给 buildClientConn 统一设置
	dialOptions := []grpc.DialOption{}
	conn, canceller, err := getGrpcClient(ctx, dest, streamSettings, transportCredentials, dialOptions...)
	if err != nil {
		return nil, newError("Cannot dial grpc").Base(err)
	}
	client := encoding.NewGunServiceClient(conn)
	gunService, err := client.(encoding.GunServiceClientX).TunCustomName(ctx, grpcSettings.ServiceName)
	if err != nil {
		canceller()
		return nil, newError("Cannot dial grpc").Base(err)
	}
	return encoding.NewGunConn(gunService, nil), nil
}

// 传入 creds，避免在 getGrpcClient 里与 buildClientConn 再次重复设置
func getGrpcClient(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig, creds credentials.TransportCredentials, dialOptions ...grpc.DialOption) (*grpc.ClientConn, dialerCanceller, error) {
	transportEnvironment := envctx.EnvironmentFromContext(ctx).(environment.TransportEnvironment)
	state, err := transportEnvironment.TransientStorage().Get(ctx, "grpc-transport-connection-state")
	if err != nil {
		state = &transportConnectionState{}
		transportEnvironment.TransientStorage().Put(ctx, "grpc-transport-connection-state", state)
		state, err = transportEnvironment.TransientStorage().Get(ctx, "grpc-transport-connection-state")
		if err != nil {
			return nil, nil, newError("failed to get grpc transport connection state").Base(err)
		}
	}
	stateTyped := state.(*transportConnectionState)

	stateTyped.scopedDialerAccess.Lock()
	defer stateTyped.scopedDialerAccess.Unlock()

	if stateTyped.scopedDialerMap == nil {
		stateTyped.scopedDialerMap = make(map[net.Destination]*grpc.ClientConn)
	}

	canceller := func() {
		stateTyped.scopedDialerAccess.Lock()
		defer stateTyped.scopedDialerAccess.Unlock()
		delete(stateTyped.scopedDialerMap, dest)
	}

	if client, found := stateTyped.scopedDialerMap[dest]; found && client.GetState() != connectivity.Shutdown {
		return client, canceller, nil
	}

	// 仅在这里追加专属的 ContextDialer；不要再加 ConnectParams/TransportCredentials，避免与 buildClientConn 重复
	opts := make([]grpc.DialOption, 0, len(dialOptions)+1)
	opts = append(opts, dialOptions...)
	opts = append(opts,
		grpc.WithContextDialer(func(ctxGrpc context.Context, s string) (gonet.Conn, error) {
			rawHost, rawPort, err := net.SplitHostPort(s)
			if err != nil {
				return nil, err
			}
			if len(rawPort) == 0 {
				rawPort = "443"
			}
			port, err := net.PortFromString(rawPort)
			if err != nil {
				return nil, err
			}
			address := net.ParseAddress(rawHost)
			detachedContext := core.ToBackgroundDetachedContext(ctx)
			return internet.DialSystem(detachedContext, net.TCPDestination(address, port), streamSettings.SocketSettings)
		}),
	)

	// 统一由 buildClientConn 注入 Keepalive/ConnectParams/Authority/UserAgent/TransportCredentials
	cc, err := buildClientConn(ctx, dest.Address.String()+":"+dest.Port.String(), dest.Address.String(), creds, opts...)
	canceller = func() {
		stateTyped.scopedDialerAccess.Lock()
		defer stateTyped.scopedDialerAccess.Unlock()
		delete(stateTyped.scopedDialerMap, dest)
		if err != nil && cc != nil {
			cc.Close()
		}
	}
	stateTyped.scopedDialerMap[dest] = cc
	return cc, canceller, err
}

// openGunTunnel 只负责在已有 *grpc.ClientConn 上打开 gun 隧道
func openGunTunnel(ctx context.Context, cc *grpc.ClientConn, serviceName string) (gonet.Conn, error) {
	if serviceName == "" {
		serviceName = "GunService"
	}
	client := encoding.NewGunServiceClient(cc)
	newError("creating connection to ", serviceName).WriteToLog(session.ExportIDToError(ctx))
	gunService, err := client.(encoding.GunServiceClientX).TunCustomName(ctx, serviceName)
	if err != nil {
		return nil, newError("Cannot open gun tunnel with service: " + serviceName).Base(err)
	}
	return encoding.NewGunConn(gunService, nil), nil
}

// DialDirectContext 现在复用 openGunTunnel，逻辑更简洁
func DialDirectContext(ctx context.Context, serverAddr, host, serviceName string, useTLS bool) (gonet.Conn, error) {
	var creds credentials.TransportCredentials
	if useTLS {
		creds = credentials.NewTLS(&stdtls.Config{
			ServerName: host,
			NextProtos: []string{"h2"},
			MinVersion: stdtls.VersionTLS12,
			MaxVersion: stdtls.VersionTLS13,
		})
	} else {
		creds = insecure.NewCredentials()
	}

	cc, err := buildClientConn(ctx, serverAddr, host, creds)
	if err != nil {
		return nil, newError("Cannot dial grpc to " + serverAddr).Base(err)
	}
	conn, err := openGunTunnel(ctx, cc, serviceName)
	if err != nil {
		_ = cc.Close()
		return nil, err
	}
	return conn, nil
}
