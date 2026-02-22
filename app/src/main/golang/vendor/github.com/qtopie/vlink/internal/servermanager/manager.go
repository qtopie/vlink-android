package servermanager

import (
	"log"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// ServerInfo holds a server's address and its last measured latency.
type ServerInfo struct {
	Address string
	Latency time.Duration
}

// ServerManager holds a list of servers, periodically tests them, and provides the best one.
type ServerManager struct {
	servers      []string
	bestServer   string
	mu           sync.RWMutex
	testInterval time.Duration
	testTimeout  time.Duration
	stopChan     chan struct{}
}

// New creates a new ServerManager.
func New(servers []string, testInterval, testTimeout time.Duration) *ServerManager {
	if len(servers) == 0 {
		return nil
	}
	return &ServerManager{
		servers:      servers,
		bestServer:   servers[0],
		testInterval: testInterval,
		testTimeout:  testTimeout,
		stopChan:     make(chan struct{}),
	}
}

// Start begins the periodic testing of servers in a background goroutine.
func (sm *ServerManager) Start() {
	log.Println("ServerManager: Starting...")
	go func() {
		// Perform an initial test immediately.
		sm.testServers()

		ticker := time.NewTicker(sm.testInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				sm.testServers()
			case <-sm.stopChan:
				log.Println("ServerManager: Stopped.")
				return
			}
		}
	}()
}

// Stop terminates the background testing goroutine.
func (sm *ServerManager) Stop() {
	close(sm.stopChan)
}

// GetBestServer returns the current server with the lowest latency.
func (sm *ServerManager) GetBestServer() string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.bestServer
}

// HasWorkingServer returns true if at least one server has passed the latency test.
func (sm *ServerManager) HasWorkingServer() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.bestServer != ""
}

// GetServers returns the current list of servers.
func (sm *ServerManager) GetServers() []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	servers := make([]string, len(sm.servers))
	copy(servers, sm.servers)
	return servers
}

// UpdateServers safely replaces the current server list with a new one and triggers a new test run.
func (sm *ServerManager) UpdateServers(newServers []string) {
	if len(newServers) == 0 {
		log.Println("ServerManager: Update called with an empty server list. No changes made.")
		return
	}

	sm.mu.Lock()
	sm.servers = newServers
	// Set best server to the first in the new list as a temporary default.
	sm.bestServer = newServers[0]
	sm.mu.Unlock()

	log.Printf("ServerManager: Server list updated with %d new servers. Triggering new tests.", len(newServers))

	if len(newServers) > 1 {
		go sm.testServers()
	}
}

// testServers performs a latency test on all servers and updates the best one.
func (sm *ServerManager) testServers() {
	log.Println("ServerManager: Running latency tests...")

	var results []ServerInfo
	var wg sync.WaitGroup
	resultChan := make(chan ServerInfo, len(sm.servers))

	for _, serverAddr := range sm.servers {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			start := time.Now()

			dialAddr := addr
			if u, err := url.Parse(addr); err == nil && u.Host != "" {
				dialAddr = u.Host
				if !strings.Contains(dialAddr, ":") {
					if u.Scheme == "http" {
						dialAddr += ":80"
					} else if u.Scheme == "https" {
						dialAddr += ":443"
					} else if u.Scheme == "socks5" {
						dialAddr += ":1080"
					}
				}
			}

			conn, err := net.DialTimeout("tcp", dialAddr, sm.testTimeout)
			if err != nil {
				// Consider failed tests as having max latency.
				resultChan <- ServerInfo{Address: addr, Latency: time.Hour}
				return
			}
			conn.Close()
			latency := time.Since(start)
			resultChan <- ServerInfo{Address: addr, Latency: latency}
		}(serverAddr)
	}

	wg.Wait()
	close(resultChan)

	for res := range resultChan {
		results = append(results, res)
	}

	// Sort by latency, ascending.
	sort.Slice(results, func(i, j int) bool {
		return results[i].Latency < results[j].Latency
	})

	if len(results) > 0 && results[0].Latency < time.Hour {
		sm.mu.Lock()
		if sm.bestServer != results[0].Address {
			sm.bestServer = results[0].Address
			log.Printf("ServerManager: New best server is %s (latency: %s)", sm.bestServer, results[0].Latency.Round(time.Millisecond))
		}
		sm.mu.Unlock()
	} else {
		log.Println("ServerManager: All server tests failed.")
	}
}
