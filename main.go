package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/dechristopher/dhcp-client/src/models"
)

type handshakeResult struct {
	success      bool          // Did we get an ACK?
	elapsed      time.Duration // Time from DISCOVER to ACK
	offeredIP    net.IP        // IP offered by the server
	acknowledged bool          // True if final packet was an ACK
	errReason string           // why failed if it did
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

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	results := make([]handshakeResult, *count)

	var wg sync.WaitGroup
	wg.Add(*count)

	startTime := time.Now()

	go func() {
		<-sigCh
		fmt.Println()
		fmt.Println("Received Ctrl+C – printing **partial** results and exiting:")
		summarizeResults(results, time.Since(startTime))
		os.Exit(0)
	}()

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

	for i := 0; i < *count; i++ {
		mac := RandomMac()
		respCh := make(chan models.DHCPPacket, 2)
		macCh[string(mac)] = respCh

		go func(idx int, mac []byte, ch chan models.DHCPPacket) {
			defer wg.Done()
			results[idx] = runDHCPHandshake(
				conn,
				serverAddr,
				mac,
				ch,
				*requestedIP,
				time.Duration(*timeout)*time.Second,
			)
		}(i, mac, respCh)
	}

	listener := make(chan struct{})
	go listenForDHCPPackets(conn, macCh, listener)

	wg.Wait()
	totalTime := time.Since(startTime)

	close(listener)

	time.Sleep(50 * time.Millisecond)

	summarizeResults(results, totalTime)
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
	discover := models.BuildDiscoverPacket(mac, &requestedIP)
	if _, err := conn.WriteTo(discover.Data, serverAddr); err != nil {
		fmt.Printf("[MAC %X] DISCOVER write error: %v\n", mac, err)
		return result
	}

	// Wait for OFFER
	offer, ok := waitForPacket(respCh, stepTimeout)
    if !ok {
        result.errReason = "Timeout waiting for OFFER"
        return result
    }
    if offer.DHCPMessageType != models.OFFER {
        result.errReason = fmt.Sprintf("Expected OFFER, got %v", offer.DHCPMessageType)
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
    if !ok {
        result.errReason = "Timeout waiting for ACK"
        return result
    }
    if ack.DHCPMessageType == models.NACKNOWLEDGE {
        result.errReason = "Server returned NACK"
        return result
    }
    if ack.DHCPMessageType != models.ACKNOWLEDGE {
        result.errReason = fmt.Sprintf("Expected ACK, got %v", ack.DHCPMessageType)
        return result
	}

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
	// Gather hardware info
	osName := runtime.GOOS
	arch := runtime.GOARCH
	numCPU := runtime.NumCPU()

	var successCount, failCount int
	var minDur, maxDur time.Duration
	var totalDur time.Duration
	failReasons := make(map[string]int)

	minDur = time.Hour // something large
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
            if r.errReason == "" {
                failReasons["UNKNOWN"]++
            } else {
                failReasons[r.errReason]++
            }
        }
    }

	if failCount > 0 {
        fmt.Printf("\nFailure reasons:\n")
        for reason, count := range failReasons {
            fmt.Printf("  %d - %s\n", count, reason)
        }
    }

	fmt.Printf("\n====== DHCP BENCHMARK SUMMARY ======\n")
    fmt.Printf("Hardware Info: OS=%s, ARCH=%s, CPUs=%d\n", osName, arch, numCPU)
    fmt.Printf("Total requests:    %d\n", len(results))
    fmt.Printf("Successful ACKs:   %d\n", successCount)
    fmt.Printf("Failures/timeouts: %d\n", failCount)
    fmt.Printf("Wall-clock time:   %v\n", total)

	if successCount > 0 {
        avgDur := time.Duration(int64(totalDur) / int64(successCount))
        fmt.Printf("\nMin handshake time: %v\n", minDur)
        fmt.Printf("Avg handshake time: %v\n", avgDur)
        fmt.Printf("Max handshake time: %v\n", maxDur)

        rps := float64(successCount) / total.Seconds()
        fmt.Printf("Approx throughput: %.2f requests/sec (ACKed only)\n", rps)
    } else {
        fmt.Println("\nNo successful handshakes to compute timing.")
    }

    fmt.Println("====================================")
}
