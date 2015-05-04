package HoneyBadger

import (
	"fmt"
	"github.com/david415/HoneyBadger/types"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type DummyPacketLogger struct {
}

func NewDummyPacketLogger(str string, flow *types.TcpIpFlow) types.PacketLogger {
	m := DummyPacketLogger{}
	return types.PacketLogger(&m)
}

func (m *DummyPacketLogger) WritePacket(rawPacket []byte, timestamp time.Time) {
}

func (m DummyPacketLogger) Start() {
}

func (m DummyPacketLogger) Stop() {
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

func SetupAttackDetectionPcapInquisitor(pcapPath string, attackLogger *TestLogger) {
	tcpIdleTimeout, _ := time.ParseDuration("10m")
	inquisitorOptions := InquisitorOptions{
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
	snifferOptions := PcapSnifferOptions{
		Interface:    "",
		Filename:     pcapPath,
		WireDuration: wireDuration,
		Snaplen:      65536,
		Filter:       "tcp",
	}
	connOptions := ConnectionOptions{}
	connectionFactory := ConnectionFactory{
		options:              &connOptions,
		CreateConnectionFunc: NewConnection,
	}
	supervisor := NewBadgerSupervisor(&snifferOptions, &inquisitorOptions, NewPcapSniffer, &connectionFactory, NewDummyPacketLogger)
	supervisor.Run()
	return
}

func PcapIsDetectInjection(pcapPath string) bool {
	logger := NewTestLogger()
	SetupAttackDetectionPcapInquisitor(pcapPath, &logger)
	log.Print("after test")

	log.Printf("COUNT %d\n", logger.count)
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
		log.Print("err != nil")
	}
}
