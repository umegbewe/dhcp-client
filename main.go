package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/dechristopher/dhcp-client/src/models"
)

type requestContext struct {
	mac []byte
	ch  chan models.DHCPPacket
}

type handshakeResult struct {
    success      bool          // Did we get an ACK?
    elapsed      time.Duration // Time from DISCOVER to ACK
    offeredIP    net.IP        // IP offered by the server
    acknowledged bool          // True if final packet was an ACK
}

func main() {
	requestedIP := flag.String("ip4", "", "Requested IPv4 address")
	count := flag.Int("count", 1, "Number of DHCP requests to send concurrently")
	timeout := flag.Int("timeout", 5, "Timeout in seconds for each handshake step (OFFER and ACK)")
	flag.Parse()

	fmt.Printf("~ DHCP Benchmark ~ %s\n", time.Now().Format(time.RFC822))
    fmt.Printf("  Will send %d concurrent requests\n", *count)
    if *requestedIP != "" {
        fmt.Printf("  Will request IP: %s\n", *requestedIP)
    }
    fmt.Println()


	serverAddr, err := net.ResolveUDPAddr("udp4", "255.255.255.255:67")
    if err != nil {
        fmt.Printf("Failed to resolve serverAddr: %v\n", err)
        os.Exit(1)
    }

    // Resolve local client address (0.0.0.0:68)
    clientAddr, err := net.ResolveUDPAddr("udp4", "0.0.0.0:68")
    if err != nil {
        fmt.Printf("Failed to resolve clientAddr: %v\n", err)
        os.Exit(1)
    }


	conn, err := net.ListenUDP("udp4", clientAddr)
	if err != nil {
		fmt.Printf("UDP dial error: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	macCh := make(map[string]chan models.DHCPPacket)

	requests := make([]requestContext, *count)
	for i := 0; i < *count; i++ {
		mac := RandomMac()                     // Our pseudo-random MAC
		respCh := make(chan models.DHCPPacket, 2) // Channel for receiving packets for this MAC

		macCh[string(mac)] = respCh
		requests[i] = requestContext{mac: mac, ch: respCh}
	}

	listener := make(chan struct{}) // signal to stop the reader
    go listenForDHCPPackets(conn, macCh, listener)

	results := make([]handshakeResult, *count)
	
	var wg sync.WaitGroup
	wg.Add(*count)

	// Fire off each DHCP handshake in its own goroutine
	startTime := time.Now()
    for i := range requests {
        go func(idx int, rc requestContext) {
            defer wg.Done()
            results[idx] = runDHCPHandshake(
                conn,
                serverAddr,
                rc.mac,
                rc.ch,
                *requestedIP,
                time.Duration(*timeout)*time.Second,
            )
        }(i, requests[i])
    }


	// Wait for all requests to complete
	wg.Wait()
	duration := time.Since(startTime)
	close(listener)
    time.Sleep(50 * time.Millisecond)
	summarizeResults(results, duration)
}

func listenForDHCPPackets(
    conn *net.UDPConn,
    macChannelMap map[string]chan models.DHCPPacket,
    stopListener chan struct{},
) {
    buf := make([]byte, 2048)

    for {
        select {
        case <-stopListener:
            // Time to stop listening
            return
        default:
            // Non-blocking check; if no stop signal, keep reading
        }

        conn.SetReadDeadline(time.Now().Add(1 * time.Second))
        n, _, err := conn.ReadFrom(buf)
        if err != nil {
            // Could be timeout (i/o timeout), or a legit error
            // We'll just loop again unless we get something fatal.
            continue
        }
        if n == 0 {
            continue
        }

        packet := models.ParsePacket(buf[:n])
        macStr := string(packet.ClientMAC)
        if ch, ok := macChannelMap[macStr]; ok {
            ch <- packet
        } else {
            // Packet doesn't match any known MAC
        }
    }
}

func runDHCPHandshake(
    conn *net.UDPConn,
    serverAddr *net.UDPAddr,
    mac []byte,
    respCh chan models.DHCPPacket,
    requestedIP string,
    stepTimeout time.Duration,
) handshakeResult {
    result := handshakeResult{}
    start := time.Now()

    // Build DISCOVER
    discoverPacket := models.BuildDiscoverPacket(mac, &requestedIP)
    if _, err := conn.WriteTo(discoverPacket.Data, serverAddr); err != nil {
        fmt.Printf("[MAC %X] DISCOVER write error: %v\n", mac, err)
        return result
    }

    // Wait for OFFER
    offer, ok := waitForPacket(respCh, stepTimeout)
    if !ok || offer.DHCPMessageType != models.OFFER {
        fmt.Printf("[MAC %X] Timeout or invalid OFFER\n", mac)
        return result
    }
    result.offeredIP = net.IP(offer.YourIP)

    // Send REQUEST
    request := models.BuildRequestPacket(mac, offer.YourIP, offer.ServerIP)
    if _, err := conn.WriteTo(request.Data, serverAddr); err != nil {
        fmt.Printf("[MAC %X] REQUEST write error: %v\n", mac, err)
        return result
    }

    // Wait for ACK
    ack, ok := waitForPacket(respCh, stepTimeout)
    if !ok || ack.DHCPMessageType != models.ACKNOWLEDGE {
        fmt.Printf("[MAC %X] Timeout or invalid ACK\n", mac)
        return result
    }

    // If we reach here, we have a valid ACK
    result.success = true
    result.acknowledged = true
    result.elapsed = time.Since(start)
    return result
}

func waitForPacket(ch chan models.DHCPPacket, timeout time.Duration) (models.DHCPPacket, bool) {
    select {
    case pkt := <-ch:
        return pkt, true
    case <-time.After(timeout):
        return models.DHCPPacket{}, false
    }
}

/*
 * Generates a pseudo-random MAC address for testing
 */
func RandomMac() []byte {
	buf := make([]byte, 6)

	// Fill buffer with random bytes
	_, err := rand.Read(buf)
	if err != nil {
	}

	// Set the local bit so we don't interfere with registered addresses
	buf[0] |= 2
	return buf
}


func summarizeResults(results []handshakeResult, total time.Duration) {
    var successCount, failCount int
    var minDur, maxDur time.Duration
    var totalDur time.Duration

    minDur = time.Hour // something big
    for _, r := range results {
        if r.success {
            successCount++
            if r.elapsed < minDur {
                minDur = r.elapsed
            }
            if r.elapsed > maxDur {
                maxDur = r.elapsed
            }
            totalDur += r.elapsed
        } else {
            failCount++
        }
    }

    fmt.Printf("\nBenchmark Complete\n")
    fmt.Printf("  Total requests: %d\n", len(results))
    fmt.Printf("  Successful ACKs: %d\n", successCount)
    fmt.Printf("  Failures/timeouts: %d\n", failCount)
    fmt.Printf("  Total time (wall-clock): %v\n", total)

    if successCount > 0 {
        avgDur := time.Duration(int64(totalDur) / int64(successCount))
        fmt.Printf("  Per-handshake (among successes):\n")
        fmt.Printf("    Min: %v\n", minDur)
        fmt.Printf("    Avg: %v\n", avgDur)
        fmt.Printf("    Max: %v\n", maxDur)

        // Derived metric: requests per second (only counting successful)
        rps := float64(successCount) / total.Seconds()
        fmt.Printf("  Approx throughput: %.2f requests/sec (successful only)\n", rps)
    }
}