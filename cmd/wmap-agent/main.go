package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	wmap_grpc "github.com/lcalzada-xor/wmap/api/proto"
	"github.com/lcalzada-xor/wmap/internal/adapters/sniffer"
	"github.com/lcalzada-xor/wmap/internal/geo"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	serverAddr := flag.String("server", "localhost:9000", "WMAP Server Address")
	iface := flag.String("i", "wlan0", "Monitor Interface")
	lat := flag.Float64("lat", 0.0, "Latitude")
	lng := flag.Float64("lng", 0.0, "Longitude")
	flag.Parse()

	// 1. Connect to gRPC Server
	conn, err := grpc.NewClient(*serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	client := wmap_grpc.NewWMapServiceClient(conn)

	// 2. Start Sniffer Manager
	// Parse interfaces from flag (comma separated)
	// We duplicate logic from config here or just use strings.Split since agent might not use full config package?
	// Agent main imports internal/config? No. It imports adapter/sniffer.
	// Let's just import strings and split.
	ifaceList := []string{}
	for _, i := range strings.Split(*iface, ",") {
		clean := strings.TrimSpace(i)
		if clean != "" {
			ifaceList = append(ifaceList, clean)
		}
	}

	if len(ifaceList) == 0 {
		log.Fatalf("No interfaces specified")
	}

	// Create Manager
	// Dwell time hardcoded/flag? currently implicit. Let's say 300ms default.
	manager := sniffer.NewManager(ifaceList, 300, false, geo.NewStaticProvider(*lat, *lng))
	// Override output channels to ours?
	// The manager creates its own output channels. We should use them.
	// But wait, NewManager creates them. We can just read from manager.Output / manager.Alerts

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go func() {
		if err := manager.Start(ctx); err != nil {
			log.Printf("Sniffer manager error: %v", err)
			cancel()
		}
	}()

	// Use manager's channels for the loop
	// We need to re-assign deviceChan and alertChan to point to manager's
	// But we declared them above. Let's just alias them or use manager.Output directly in the loop.

	// 3. Stream Data to Server
	stream, err := client.ReportTraffic(ctx)
	if err != nil {
		log.Fatalf("could not create stream: %v", err)
	}

	log.Printf("Agent started. Streaming to %s via %s", *serverAddr, *iface)

	for {
		select {
		case <-ctx.Done():
			stream.CloseSend()
			return
		case d := <-manager.Output:
			// Convert Domain Device to Proto Device
			req := &wmap_grpc.DeviceReport{
				Mac:           d.MAC,
				Vendor:        d.Vendor,
				Rssi:          int32(d.RSSI),
				Ssid:          d.SSID,
				ConnectedSsid: d.ConnectedSSID,
				Latitude:      d.Latitude,
				Longitude:     d.Longitude,
				IsRandomized:  d.IsRandomized,
				Type:          d.Type,
				Timestamp:     d.LastPacketTime.Unix(),
				Capabilities:  d.Capabilities,
			}
			// Proto repeated ints need casting if mismatched, here int32
			for _, tag := range d.IETags {
				req.IeTags = append(req.IeTags, int32(tag))
			}

			if err := stream.Send(req); err != nil {
				log.Printf("Failed to send: %v", err)
				// Reconnect logic would go here
			}
		case a := <-manager.Alerts:
			log.Printf("[ALERT] %s: %s -> %s (%s)", a.Type, a.DeviceMAC, a.TargetMAC, a.Subtype)
			// TODO: Send alerts to server
		}
	}
}
