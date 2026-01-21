package grpc

import (
	"io"
	"time"

	wmap_grpc "github.com/lcalzada-xor/wmap/api/proto"
	"github.com/lcalzada-xor/wmap/internal/core/domain"
	"github.com/lcalzada-xor/wmap/internal/core/ports"
	"google.golang.org/grpc"
)

// GrpcServer implements wmap.WMapServiceServer
type GrpcServer struct {
	wmap_grpc.UnimplementedWMapServiceServer
	service ports.NetworkService
}

func NewGrpcServer(svc ports.NetworkService) *grpc.Server {
	s := grpc.NewServer()
	wmap_grpc.RegisterWMapServiceServer(s, &GrpcServer{service: svc})
	return s
}

func (s *GrpcServer) ReportTraffic(stream wmap_grpc.WMapService_ReportTrafficServer) error {
	for {
		report, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&wmap_grpc.ReportSummary{
				DevicesProcessed: 0, // Todo: track count
			})
		}
		if err != nil {
			return err
		}

		// Convert Proto -> Domain
		// Note: We might trust the agent's timestamp or override it
		ts := time.Unix(report.Timestamp, 0)
		if report.Timestamp == 0 {
			ts = time.Now()
		}

		var tags []int
		for _, t := range report.IeTags {
			tags = append(tags, int(t))
		}

		device := domain.Device{
			MAC:            report.Mac,
			Vendor:         report.Vendor,
			RSSI:           int(report.Rssi),
			SSID:           report.Ssid,
			ConnectedSSID:  report.ConnectedSsid,
			Latitude:       report.Latitude,
			Longitude:      report.Longitude,
			IsRandomized:   report.IsRandomized,
			Type:           domain.DeviceType(report.Type),
			LastPacketTime: ts,
			LastSeen:       ts,
			Capabilities:   report.Capabilities,
			IETags:         tags,
			Security:       report.Security,
			Standard:       report.Standard,
			Model:          report.Model,
			Frequency:      int(report.Frequency),

			// Analytics
			DataTransmitted: report.DataTransmitted,
			DataReceived:    report.DataReceived,
			PacketsCount:    int(report.PacketsCount),
			RetryCount:      int(report.RetryCount),
			ChannelWidth:    int(report.ChannelWidth),

			// ProbedSSIDs: agent sends current state, we merge it in service
		}

		// If agent sends ProbedSSID in 'ssid' field for station, handle it?
		// The proto definition was simple. Ideally we'd send the full list.
		// For now, if it's a station and has SSID, treat as Probe.
		if device.Type == domain.DeviceTypeStation && device.SSID != "" {
			device.ProbedSSIDs = map[string]time.Time{
				device.SSID: ts,
			}
		}

		_ = s.service.ProcessDevice(stream.Context(), device)
	}
}
