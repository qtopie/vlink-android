package servermanager

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qtopie/vlink/cloudflare/cdntest"
)

type healthCheckResult struct {
	IP      string
	Latency time.Duration
}

func RunCDNScanner(sm *ServerManager, sniHost string, port int) {
	for {
		log.Println("CDNScanner: Starting Cloudflare IP scan...")

		// 1. Fetch and expand IPs
		ranges, err := cdntest.FetchAllIPRanges()
		if err != nil {
			log.Printf("CDNScanner: Error fetching IP ranges: %v", err)
		} else {
			ips := cdntest.ExpandIPs(ranges)
			log.Printf("CDNScanner: Found %d potential IPs to test.", len(ips))

			// 2. Perform health checks concurrently
			var wg sync.WaitGroup
			var goodIPs []healthCheckResult
			var goodIPsMutex sync.Mutex
			ipChan := make(chan net.IP, len(ips))

			for i := 0; i < 100; i++ { // Worker pool
				wg.Add(1)
				go func() {
					defer wg.Done()
					for ip := range ipChan {
						res, err := checkHealth(ip, sniHost, port, 700*time.Millisecond)
						if err == nil {
							goodIPsMutex.Lock()
							goodIPs = append(goodIPs, res)
							goodIPsMutex.Unlock()
						}
					}
				}()
			}

			for _, ip := range ips {
				ipChan <- ip
			}
			close(ipChan)
			wg.Wait()

			if len(goodIPs) == 0 {
				log.Println("CDNScanner: Scan finished. No available CDN IPs found that meet the criteria.")
			} else {
				// 3. Sort by latency and take the top 5
				sort.Slice(goodIPs, func(i, j int) bool {
					return goodIPs[i].Latency < goodIPs[j].Latency
				})

				topCount := 5
				if len(goodIPs) < topCount {
					topCount = len(goodIPs)
				}

				newServerList := make([]string, 0, topCount)
				for i := 0; i < topCount; i++ {
					newServerList = append(newServerList, goodIPs[i].IP)
				}

				log.Printf("CDNScanner: Scan finished. Found %d available IPs. Updating server list with top %d.", len(goodIPs), topCount)
				sm.UpdateServers(newServerList)
			}
		}

		// 4. Wait for the next cycle with jitter.
		jitter := time.Duration(rand.Intn(11)) * time.Minute
		waitDuration := 7*time.Hour + jitter
		log.Printf("CDNScanner: Next scan will run in ~%s.", waitDuration.Round(time.Minute))
		time.Sleep(waitDuration)
	}
}

// checkHealth performs a health check against a single IP.
func checkHealth(ip net.IP, sniHost string, port int, timeout time.Duration) (healthCheckResult, error) {
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))

	// Custom transport to dial a specific IP while requesting a different host
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "tcp", addr)
		},
		TLSClientConfig: &tls.Config{
			ServerName:         sniHost, // This is crucial for SNI
			InsecureSkipVerify: true,    // Necessary because cert is for sniHost, not the IP
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	healthURL := fmt.Sprintf("https://%s/healthz", sniHost)
	req, _ := http.NewRequest("GET", healthURL, nil)

	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start)

	if err != nil {
		return healthCheckResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return healthCheckResult{}, fmt.Errorf("bad status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return healthCheckResult{}, err
	}

	if strings.TrimSpace(string(body)) != "OK" {
		return healthCheckResult{}, fmt.Errorf("unexpected body: %s", string(body))
	}

	return healthCheckResult{IP: addr, Latency: latency}, nil
}
