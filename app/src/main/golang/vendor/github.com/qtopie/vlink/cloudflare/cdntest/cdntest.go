package cdntest

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// CloudflareIPv4URL is the official URL for Cloudflare's IPv4 ranges.
	CloudflareIPv4URL = "https://www.cloudflare.com/ips-v4"
	// CloudflareIPv6URL is the official URL for Cloudflare's IPv6 ranges.
	CloudflareIPv6URL = "https://www.cloudflare.com/ips-v6"
	// DefaultTestURL is the URL used for speed testing. We download 1MB of data.
	DefaultTestURL = "https://speed.cloudflare.com/__down?bytes=1000000"
)

// Result holds the test result for a single IP.
type Result struct {
	IP            net.IP
	Latency       time.Duration
	DownloadSpeed float64 // in Mbps
	Err           error
}

// TesterConfig holds the configuration for the CDN tester.
type TesterConfig struct {
	Concurrency int
	Timeout     time.Duration
	TestURL     string
	HTTPSPort   int
}

// Tester runs the tests.
type Tester struct {
	config TesterConfig
}

// NewTester creates a new CDN tester.
func NewTester(config TesterConfig) *Tester {
	if config.TestURL == "" {
		config.TestURL = DefaultTestURL
	}
	if config.HTTPSPort == 0 {
		config.HTTPSPort = 443
	}
	return &Tester{config: config}
}

// fetchIPRangesFromURL fetches the list of CIDR ranges from a given URL.
func fetchIPRangesFromURL(url string) ([]*net.IPNet, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch IP ranges from %s: %w", url, err)
	}
	defer resp.Body.Close()

	var ranges []*net.IPNet
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(line)
		if err != nil {
			// Ignore invalid lines
			continue
		}
		ranges = append(ranges, ipNet)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading IP ranges response from %s: %w", url, err)
	}

	return ranges, nil
}

// FetchAllIPRanges fetches both IPv4 and IPv6 CIDR ranges concurrently.
func FetchAllIPRanges() ([]*net.IPNet, error) {
	var (
		wg           sync.WaitGroup
		v4Ranges     []*net.IPNet
		v6Ranges     []*net.IPNet
		v4Err, v6Err error
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		v4Ranges, v4Err = fetchIPRangesFromURL(CloudflareIPv4URL)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		v6Ranges, v6Err = fetchIPRangesFromURL(CloudflareIPv6URL)
	}()

	wg.Wait()

	if v4Err != nil {
		return nil, v4Err
	}
	if v6Err != nil {
		return nil, v6Err
	}

	return append(v4Ranges, v6Ranges...), nil
}

// ExpandIPs takes a list of CIDR ranges and expands them into a list of IPs to test.
// For IPv4, we test the .1 address of each /24 subnet.
// For IPv6, we test the network address and network address + 1.
func ExpandIPs(ranges []*net.IPNet) []net.IP {
	var ips []net.IP
	ipSet := make(map[string]struct{}) // Use a map to ensure uniqueness

	for _, r := range ranges {
		if r.IP.To4() != nil { // IPv4
			// For IPv4 CIDRs, iterate and test the .1 address of each /24 subnet.
			// This is a common strategy to cover a broad range without testing too many IPs.
			tempIP := make(net.IP, len(r.IP))
			copy(tempIP, r.IP.Mask(r.Mask)) // Start at the network address of the given CIDR

			// The loop continues as long as tempIP is within the original CIDR.
			// It increments tempIP to the start of the next /24 subnet.
			for {
				if !r.Contains(tempIP) {
					break // Exited the original CIDR range
				}

				// Create the .1 address for the current /24 subnet
				ip24 := make(net.IP, len(tempIP))
				copy(ip24, tempIP)
				ip24[len(ip24)-1] = 1 // Set the last octet to 1

				// Add to our list if it's unique and actually within the original CIDR
				if _, exists := ipSet[ip24.String()]; !exists && r.Contains(ip24) {
					ips = append(ips, ip24)
					ipSet[ip24.String()] = struct{}{}
				}

				// Move to the next /24 boundary
				// Increment the third octet (byte at index len-2) to jump to the next /24
				inc24(tempIP)

				// If `inc24` causes the IP to wrap around or go beyond the original CIDR,
				// or if it's no longer within the mask (for smaller than /24 CIDRs), break.
				// This is a more robust check than just `r.Contains(tempIP)` after inc24
				// because inc24 might jump across multiple CIDR boundaries.
				currentNetworkAddr := tempIP.Mask(net.CIDRMask(24, 32))
				if currentNetworkAddr.Equal(ip24.Mask(net.CIDRMask(24, 32))) {
					// We are still in the same /24, meaning inc24 didn't move us
					// This can happen if the original CIDR is smaller than /24 or at its edge.
					// To prevent infinite loops in such specific edge cases, we break.
					// More generally, `inc24` should correctly jump to the next /24 network address.
					// If the loop condition `r.Contains(tempIP)` handles breaking, we just need `inc24`.
					// For example, if r is `192.168.1.0/24`, tempIP starts at `192.168.1.0`.
					// ip24 becomes `192.168.1.1`.
					// inc24(tempIP) makes tempIP `192.168.2.0`.
					// The loop will then correctly check `r.Contains(192.168.2.0)` which is false, and break.
				}
			}

		} else if r.IP.To16() != nil { // IPv6
			// For IPv6, we take the network address and network address + 1 for each CIDR.
			// This keeps the number of test IPs manageable as IPv6 ranges can be very large.
			netIP := r.IP.Mask(r.Mask)

			if _, exists := ipSet[netIP.String()]; !exists {
				ips = append(ips, netIP)
				ipSet[netIP.String()] = struct{}{}
			}

			// Add netIP + 1 if it's within the range and unique
			nextIP := make(net.IP, len(netIP))
			copy(nextIP, netIP)
			inc(nextIP) // Increment by 1
			if _, exists := ipSet[nextIP.String()]; !exists && r.Contains(nextIP) {
				ips = append(ips, nextIP)
				ipSet[nextIP.String()] = struct{}{}
			}
		}
	}
	return ips
}

// inc increments an IP address by 1.
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// inc24 increments an IPv4 address to the next /24 boundary.
func inc24(ip net.IP) {
	// Ensure it's an IPv4 address (4 bytes long)
	if ip4 := ip.To4(); ip4 != nil {
		// The third octet is at index 2 (0-indexed)
		// Increment the third octet
		ip4[2]++
		// Zero out the last octet to get to the start of the new /24
		ip4[3] = 0

		// Handle overflow for the third octet
		if ip4[2] == 0 { // if it wrapped from 255 to 0
			// Increment the second octet
			ip4[1]++
			if ip4[1] == 0 { // if it wrapped from 255 to 0
				// Increment the first octet
				ip4[0]++
			}
		}
	}
}

// RunTests tests a list of IPs and returns separate, sorted results for IPv4 and IPv6.
func (t *Tester) RunTests(ips []net.IP) ([]Result, []Result) {
	var wg sync.WaitGroup
	ipChan := make(chan net.IP, len(ips))
	resultChan := make(chan Result, len(ips))

	for i := 0; i < t.config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipChan {
				resultChan <- t.testIP(ip)
			}
		}()
	}

	for _, ip := range ips {
		ipChan <- ip
	}
	close(ipChan)

	wg.Wait()
	close(resultChan)

	var v4Results, v6Results []Result
	for res := range resultChan {
		if res.Err == nil {
			if res.IP.To4() != nil {
				v4Results = append(v4Results, res)
			} else {
				v6Results = append(v6Results, res)
			}
		}
	}

	// Sort IPv4 results: best latency first, then best speed.
	sort.Slice(v4Results, func(i, j int) bool {
		if v4Results[i].Latency == v4Results[j].Latency {
			return v4Results[i].DownloadSpeed > v4Results[j].DownloadSpeed
		}
		return v4Results[i].Latency < v4Results[j].Latency
	})

	// Sort IPv6 results: best latency first, then best speed.
	sort.Slice(v6Results, func(i, j int) bool {
		if v6Results[i].Latency == v6Results[j].Latency {
			return v6Results[i].DownloadSpeed > v6Results[j].DownloadSpeed
		}
		return v6Results[i].Latency < v6Results[j].Latency
	})

	return v4Results, v6Results
}

func (t *Tester) testIP(ip net.IP) Result {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", t.config.HTTPSPort))

	// Determine network type (tcp4 or tcp6) to ensure correct dial behavior
	network := "tcp" // Default, lets net.Dial choose
	if ip.To4() != nil {
		network = "tcp4"
	} else if ip.To16() != nil && ip.To4() == nil {
		network = "tcp6"
	}

	// 1. Test latency
	startLatency := time.Now()
	conn, err := net.DialTimeout(network, addr, t.config.Timeout)
	latency := time.Since(startLatency)
	if err != nil {
		return Result{IP: ip, Err: fmt.Errorf("latency test failed for %s (%s): %w", ip.String(), network, err)}
	}
	conn.Close()

	// 2. Test download speed
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			// Use the determined network type (tcp4 or tcp6)
			d := net.Dialer{Timeout: t.config.Timeout}
			return d.DialContext(ctx, network, addr)
		},
		// We are connecting to an IP, so we need to skip verification.
		// The domain is specified in the request Host.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   t.config.Timeout,
	}

	req, _ := http.NewRequest("GET", t.config.TestURL, nil)
	// We must set the Host to the domain name of our test URL for the TLS handshake to succeed.
	req.Host = "speed.cloudflare.com"

	startSpeed := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return Result{IP: ip, Latency: latency, Err: fmt.Errorf("speed test request failed for %s: %w", ip.String(), err)}
	}
	defer resp.Body.Close()

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return Result{IP: ip, Latency: latency, Err: fmt.Errorf("speed test read failed for %s: %w", ip.String(), err)}
	}
	duration := time.Since(startSpeed)

	if duration == 0 {
		return Result{IP: ip, Latency: latency, Err: fmt.Errorf("speed test duration was zero for %s", ip.String())}
	}

	// Calculate speed in Mbps (Megabits per second)
	speed := (float64(len(bytes)) * 8) / duration.Seconds() / 1_000_000

	return Result{
		IP:            ip,
		Latency:       latency,
		DownloadSpeed: speed,
	}
}
