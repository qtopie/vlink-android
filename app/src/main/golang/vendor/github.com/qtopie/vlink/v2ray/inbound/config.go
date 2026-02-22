package inbound

import (
	vlinkcore "github.com/qtopie/vlink/core"
	"github.com/qtopie/vlink/internal/router"
	"github.com/qtopie/vlink/internal/servermanager"
)

// InboundConfig configures the inbound handler.
type InboundConfig struct {
	ListenAddress   string
	ListenPort      uint32
	ServerManager   *servermanager.ServerManager
	Cipher          vlinkcore.Cipher
	Host            string
	ServiceName     string
	TLS             bool
	RuleManager     *router.RuleManager
	EnableAutoProxy bool

	// DefaultProxy controls behaviour when no explicit rule matches.
	// If true, traffic defaults to proxy when there's no rule match.
	// If false, traffic defaults to direct when there's no rule match.
	DefaultProxy bool

	// SocksProxy is an optional local SOCKS5 proxy address (host:port) to forward
	// proxied connections to. If set, TProxy will connect to this SOCKS5 service
	// and request the target, reusing the local SOCKS service instead of opening
	// a new upstream connection.
	SocksProxy string
	// SocksPoolSize controls how many "warm" TCP connections to the local SOCKS
	// server TProxy keeps ready to reduce dial latency. Each warm connection is
	// consumed when used to perform a SOCKS CONNECT and is asynchronously
	// replenished in the background. Set to 0 to disable pooling.
	SocksPoolSize int
}

// DefaultSocksPoolSize is used when SocksPoolSize is zero. Chosen to be
// reasonably sized for LAN / gateway deployments where many short-lived
// connections may be proxied via a local SOCKS server.
const DefaultSocksPoolSize = 16
