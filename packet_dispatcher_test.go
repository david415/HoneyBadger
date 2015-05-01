package HoneyBadger

import (
	"github.com/david415/HoneyBadger/logging"
	"github.com/david415/HoneyBadger/types"
	"log"
	"os"
	"testing"
	"time"
)

type MockSniffer struct {
	supervisor  types.Supervisor
	startedChan chan bool
}

func NewMockSniffer(options *PcapSnifferOptions) types.PacketSource {
	var packetSource types.PacketSource = MockSniffer{
		startedChan: make(chan bool, 0),
	}
	return packetSource
}

func (s MockSniffer) Start() {
	log.Print("MockSniffer Start()")
	s.startedChan <- true
}
func (s MockSniffer) Stop() {
	log.Print("MockSniffer Stop()")
}
func (s MockSniffer) SetSupervisor(supervisor types.Supervisor) {
	s.supervisor = supervisor
}
func (s MockSniffer) GetStartedChan() chan bool {
	return s.startedChan
}

func TestInquisitorForceQuit(t *testing.T) {

	tcpIdleTimeout, _ := time.ParseDuration("10m")
	inquisitorOptions := InquisitorOptions{
		BufferedPerConnection:    10,
		BufferedTotal:            100,
		LogDir:                   ".",
		LogPackets:               true,
		TcpIdleTimeout:           tcpIdleTimeout,
		MaxRingPackets:           40,
		Logger:                   logging.NewAttackMetadataJsonLogger("."),
		DetectHijack:             true,
		DetectInjection:          true,
		DetectCoalesceInjection:  true,
		MaxConcurrentConnections: 100,
	}

	wireDuration, _ := time.ParseDuration("3s")
	snifferOptions := PcapSnifferOptions{
		Interface:    "myInterface",
		Filename:     "",
		WireDuration: wireDuration,
		Snaplen:      65536,
		Filter:       "tcp",
	}

	supervisor := NewBadgerSupervisor(&snifferOptions, &inquisitorOptions, NewMockSniffer)

	log.Print("supervisor before run")
	go supervisor.Run()
	log.Print("supervisor after run")

	sniffer := supervisor.GetSniffer()
	startedChan := sniffer.GetStartedChan()
	<-startedChan

	var sig os.Signal
	supervisor.forceQuitChan <- sig
}

func TestInquisitorSourceStopped(t *testing.T) {

	tcpIdleTimeout, _ := time.ParseDuration("10m")
	inquisitorOptions := InquisitorOptions{
		BufferedPerConnection:    10,
		BufferedTotal:            100,
		LogDir:                   ".",
		LogPackets:               true,
		TcpIdleTimeout:           tcpIdleTimeout,
		MaxRingPackets:           40,
		Logger:                   logging.NewAttackMetadataJsonLogger("."),
		DetectHijack:             true,
		DetectInjection:          true,
		DetectCoalesceInjection:  true,
		MaxConcurrentConnections: 100,
	}

	wireDuration, _ := time.ParseDuration("3s")
	snifferOptions := PcapSnifferOptions{
		Interface:    "myInterface",
		Filename:     "",
		WireDuration: wireDuration,
		Snaplen:      65536,
		Filter:       "tcp",
	}

	supervisor := NewBadgerSupervisor(&snifferOptions, &inquisitorOptions, NewMockSniffer)

	log.Print("supervisor before run")
	go supervisor.Run()
	log.Print("supervisor after run")

	sniffer := supervisor.GetSniffer()
	startedChan := sniffer.GetStartedChan()
	<-startedChan

	sniffer.Stop()
}
