package vlinkjni

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/qtopie/vlink/core"
	vlink "github.com/qtopie/vlink/internal"
	"github.com/qtopie/vlink/internal/servermanager"
	"github.com/qtopie/vlink/v2ray/inbound"
)

const defaultGRPCUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0"

// StartVLink is an exported function intended for gomobile binding.
// It replaces the previous JNI entry point and uses plain Go types.
func StartVLink(
	fd int,
	server string,
	host string,
	userAgent string,
	serviceName string,
	tunAddr string,
	upstreamSocks string,
	tunMTU int,
	verbose bool,
	logPath string,
) {
	log.Printf("StartVLink called (FD: %d, MTU: %d, TunAddr: %s)", fd, tunMTU, tunAddr)

	if logPath != "" {
		log.Printf("Redirecting log to %s", logPath)
		f, err := os.OpenFile(logPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
		if err == nil {
			log.SetOutput(f)
			log.Println("--- Go Engine Log Initialized ---")
		} else {
			log.Printf("Failed to open log file: %v", err)
		}
	}

	goTunFD := fd
	goTunMTU := tunMTU
	goVerbose := verbose

	if goVerbose {
		vlink.SetVerbose(true)
	}

	// Start in a goroutine so the caller is not blocked.
	go func() {
		log.Printf("vlink Goroutine: Started (FD: %d, MTU: %d, TunAddr: %s)", goTunFD, goTunMTU, tunAddr)

		serverAddr, cipher, pass, err := parseServerUrl(server)
		if err != nil {
			log.Printf("vlink: Error parsing server URL '%s': %v", server, err)
			return
		}
		log.Printf("vlink: Parsed server address: %s, cipher: %s", serverAddr, cipher)

		if userAgent == "" {
			userAgent = defaultGRPCUserAgent
		}
		os.Setenv("GRPC_USER_AGENT", userAgent)

		ciph, err := core.PickCipher(cipher, nil, pass)
		if err != nil {
			log.Printf("vlink Error: pick cipher '%s': %v", cipher, err)
			return
		}

		log.Printf("vlink: Starting TUN inbound. SNI Host: %s, ServiceName: %s", host, serviceName)

		log.Printf("vlink: Initializing ServerManager with server %s", serverAddr)
		sm := servermanager.New([]string{serverAddr}, 10*time.Minute, 2*time.Second)
		sm.Start()

		log.Printf("vlink: Configuring SocksInboundHandler (TLS: true, Host: %s)", host)
		sconf := &inbound.InboundConfig{
			ListenAddress: "127.0.0.1",
			ListenPort:    0,
			Cipher:        ciph,
			Host:          host,
			ServiceName:   serviceName,
			TLS:           true,
			ServerManager: sm,
		}
		socksHandler := &inbound.SocksInboundHandler{}
		socksHandler.SetConfig(sconf)

		tconf := &TunInboundConfig{
			FD:            goTunFD,
			Address:       []string{tunAddr},
			MTU:           goTunMTU,
			UpstreamSocks: upstreamSocks,
		}

		tunHandler := &TunInboundHandler{
			config: tconf,
			SocksHandler: socksHandler,
		}

		log.Printf("vlink: Starting TunInboundHandler...")
		if err := tunHandler.Start(); err != nil {
			log.Printf("vlink: Failed to start TUN handler: %v", err)
			return
		}

		log.Printf("vlink: TUN handler started successfully. Entering wait state.")
		select {}
	}()
}

// parseServerUrl extracts network addresses and assumes a common cipher/password from a list of ss:// URLs.
func parseServerUrl(server string) (address string, cipher, password string, err error) {
	if server == "" {
		return "", "", "", fmt.Errorf("server address is empty")
	}
	// Use the provided server entry to parse details
	address, cipher, password, err = vlink.ParseURL(server)
	return
}

// main is intentionally omitted for library binding builds.
