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

func main() {
	requestedIP := flag.String("ip4", "", "Requested IPv4 address")
	count := flag.Int("count", 1, "Number of DHCP requests to send concurrently")
	flag.Parse()

	fmt.Printf("~ ToyDHCP %s\n", time.Now().Format(time.RFC822))
	fmt.Printf("~ Will send %d DHCP request(s)\n\n", *count)

	serverAddr, _ := net.ResolveUDPAddr("udp4", "255.255.255.255:67")
	clientAddr, _ := net.ResolveUDPAddr("udp4", "0.0.0.0:68")

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
		respCh := make(chan models.DHCPPacket) // Channel for receiving packets for this MAC

		macCh[string(mac)] = respCh
		requests[i] = requestContext{mac, respCh}
	}

	go listenForDHCPPackets(conn, macCh)
	var wg sync.WaitGroup
	wg.Add(*count)

	// Fire off each DHCP handshake in its own goroutine
	for i := 0; i < *count; i++ {
		go func(rc requestContext) {
			defer wg.Done()
			runDHCPHandshake(conn, serverAddr, rc.mac, rc.ch, *requestedIP)
		}(requests[i])
	}

	// Wait for all requests to complete
	wg.Wait()

	fmt.Println("\nAll DHCP handshakes completed. Exiting.")
}

func listenForDHCPPackets(conn *net.UDPConn, macChannelMap map[string]chan models.DHCPPacket) {
	respBuffer := make([]byte, 2048)

	for {
		n, _, err := conn.ReadFrom(respBuffer)
		if err != nil {
			fmt.Printf("UDP read error: %v\n", err)
			return
		}
		if n == 0 {
			continue
		}

		// Parse the DHCP packet
		packet := models.ParsePacket(respBuffer[:n])

		// Match this packet’s ClientMAC to one of our request contexts
		macStr := string(packet.ClientMAC)
		if ch, ok := macChannelMap[macStr]; ok {
			// Forward packet to the specific goroutine waiting on this MAC
			ch <- packet
		} else {
			// If we get here, the packet doesn’t match any known MAC
		}
	}
}

func runDHCPHandshake(
	conn *net.UDPConn,
	serverAddr *net.UDPAddr,
	mac []byte,
	respCh chan models.DHCPPacket,
	requestedIP string,
) {
	// Build a DISCOVER packet for this unique MAC
	discoverPacket := models.BuildDiscoverPacket(mac, &requestedIP)

	// Send DISCOVER
	_, err := conn.WriteTo(discoverPacket.Data, serverAddr)
	if err != nil {
		fmt.Printf("DISCOVER write error (MAC %X): %v\n", mac, err)
		return
	}
	fmt.Printf("[MAC %X] Sent DISCOVER\n", mac)

	// Wait for OFFER (with timeout)
	offer, ok := waitForPacket(respCh, 5*time.Second)
	if !ok || offer.DHCPMessageType != models.OFFER {
		fmt.Printf("[MAC %X] Timed out or did not receive valid OFFER\n", mac)
		return
	}
	fmt.Printf("[MAC %X] Received OFFER for IP %s\n", mac, net.IP(offer.YourIP))

	// Build and send REQUEST
	request := models.BuildRequestPacket(mac, offer.YourIP, offer.ServerIP)
	_, err = conn.WriteTo(request.Data, serverAddr)
	if err != nil {
		fmt.Printf("[MAC %X] REQUEST write error: %v\n", mac, err)
		return
	}
	fmt.Printf("[MAC %X] Sent REQUEST for IP %s\n", mac, net.IP(offer.YourIP))

	// Wait for ACK
	ack, ok := waitForPacket(respCh, 5*time.Second)
	if !ok || ack.DHCPMessageType != models.ACKNOWLEDGE {
		fmt.Printf("[MAC %X] Timed out or did not receive ACK\n", mac)
		return
	}
	fmt.Printf("[MAC %X] Received ACK - Leased IP %s\n", mac, net.IP(ack.YourIP))
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
