package router

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

type GoogleIPs struct {
	SyncToken    string `json:"syncToken"`
	CreationTime string `json:"creationTime"`
	Prefixes     []struct {
		IPv4Prefix string `json:"ipv4Prefix,omitempty"`
		IPv6Prefix string `json:"ipv6Prefix,omitempty"`
	} `json:"prefixes"`
}

var (
	googleSubnets []net.IPNet
	googleMu      sync.RWMutex
)

// FetchGoogleIPs 拉取并更新 Google IP 列表
// client: 用于发起请求的 HTTP 客户端。如果为 nil，则使用 http.DefaultClient (可能无法直连 Google)
func FetchGoogleIPs(client *http.Client) error {
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Get("https://www.gstatic.com/ipranges/goog.json")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var data GoogleIPs
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return err
	}

	var subnets []net.IPNet
	for _, p := range data.Prefixes {
		prefix := p.IPv4Prefix
		if prefix == "" {
			prefix = p.IPv6Prefix
		}
		if prefix == "" {
			continue
		}

		_, ipnet, err := net.ParseCIDR(prefix)
		if err == nil {
			subnets = append(subnets, *ipnet)
		}
	}

	googleMu.Lock()
	googleSubnets = subnets
	googleMu.Unlock()

	// log.Printf("Router: Updated Google IP list with %d subnets", len(subnets))
	return nil
}

// StartGoogleIPSync 开启定时同步
func StartGoogleIPSync(client *http.Client) {
	go func() {
		// Initial fetch
		if err := FetchGoogleIPs(client); err != nil {
			fmt.Printf("Warning: Failed to fetch Google IPs: %v. Will retry.\n", err)
		} else {
			fmt.Println("Router: Google IP list initialized.")
		}

		for {
			time.Sleep(24 * time.Hour) // 每天同步一次
			if err := FetchGoogleIPs(client); err != nil {
				fmt.Printf("Warning: Failed to update Google IPs: %v\n", err)
			}
		}
	}()
}

// IsGoogleIP 检查 IP 是否属于 Google
func IsGoogleIP(ip net.IP) bool {
	googleMu.RLock()
	defer googleMu.RUnlock()
	for _, subnet := range googleSubnets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}
