package HoneyBadger

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/david415/HoneyBadger/types"
)

type DummyPacketLogger struct {
}

func NewDummyPacketLogger(str string, flow *types.TcpIpFlow, pcapNum int, pcapSize int) types.PacketLogger {
	m := DummyPacketLogger{}
	return types.PacketLogger(&m)
}

type DummyPacketLoggerFactory struct {
}

func (f DummyPacketLoggerFactory) Build(flow *types.TcpIpFlow) types.PacketLogger {
	return NewDummyPacketLogger("", flow, 10, 100)
}

func (m *DummyPacketLogger) WritePacket(rawPacket []byte, timestamp time.Time) {
}

func (m DummyPacketLogger) Start() {
}

func (m DummyPacketLogger) Stop() {
}

func (m DummyPacketLogger) Archive() {
}

func (m DummyPacketLogger) Remove() {
}

type TestLogger struct {
	eventList []types.Event
	count     int
}

func NewTestLogger() TestLogger {
	return TestLogger{}
}

func (t *TestLogger) Log(event *types.Event) {
	t.count += 1
}

func (t *TestLogger) Archive() {
}

func SetupAttackDetectionPcapInquisitor(pcapPath string, attackLogger *TestLogger) {
	tcpIdleTimeout, _ := time.ParseDuration("10m")
	dispatcherOptions := DispatcherOptions{
		BufferedPerConnection:    10,
		BufferedTotal:            100,
		LogDir:                   "",
		LogPackets:               true,
		TcpIdleTimeout:           tcpIdleTimeout,
		MaxRingPackets:           40,
		Logger:                   types.Logger(attackLogger),
		DetectHijack:             true,
		DetectInjection:          true,
		DetectCoalesceInjection:  true,
		MaxConcurrentConnections: 100,
	}

	wireDuration, _ := time.ParseDuration("3s")
	snifferOptions := types.SnifferDriverOptions{
		DAQ:          "libpcap",
		Device:       "",
		Filename:     pcapPath,
		WireDuration: wireDuration,
		Snaplen:      65536,
		Filter:       "tcp",
	}

	factory := &DefaultConnFactory{}
	dummyPacketLoggerFactory := DummyPacketLoggerFactory{}
	options := SupervisorOptions{
		SnifferDriverOptions: &snifferOptions,
		DispatcherOptions:    dispatcherOptions,
		SnifferFactory:       NewSniffer,
		ConnectionFactory:    factory,
		PacketLoggerFactory:  dummyPacketLoggerFactory,
	}

	supervisor := NewSupervisor(options)
	supervisor.Run()
	return
}

func PcapIsDetectInjection(pcapPath string) bool {
	logger := NewTestLogger()
	SetupAttackDetectionPcapInquisitor(pcapPath, &logger)
	if logger.count == 0 {
		return false
	} else {
		return true
	}
}

func TestAllPcapFiles(t *testing.T) {
	root := "pcap_archive/"
	absPathSymLink, err := filepath.Abs(root)
	if err != nil {
		panic(err)
	}
	var path string
	path, err = filepath.EvalSymlinks(absPathSymLink)
	if err != nil {
		t.Skip("skipping test because pcap_archive symlink is missing.")
	}
	walkpath := func(path string, f os.FileInfo, err error) error {
		if strings.HasSuffix(path, ".pcap") {
			fmt.Printf("HoneyBadger integration test with: %s\n", path)
			if !PcapIsDetectInjection(path) {
				t.Fatal("No injection attack detected in pcap file: %s\n", path)
			}
		}
		return nil
	}
	err = filepath.Walk(path, walkpath)
	if err != nil {
		panic(err)
	}
}
