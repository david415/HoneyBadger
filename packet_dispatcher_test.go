package HoneyBadger

import (
	"github.com/david415/HoneyBadger/logging"
	"github.com/david415/HoneyBadger/types"
	"github.com/google/gopacket/layers"
	"log"
	"net"
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

type MockConnection struct {
	options            *ConnectionOptions
	clientFlow         types.TcpIpFlow
	serverFlow         types.TcpIpFlow
	lastSeen           time.Time
	ClientStreamRing   *types.Ring
	packetObserverChan chan bool
}

func NewMockConnection(options *ConnectionOptions) ConnectionInterface {
	m := MockConnection{
		options:            options,
		packetObserverChan: make(chan bool, 0),
	}
	return ConnectionInterface(&m)
}

func (m *MockConnection) Start() {
	log.Print("MockConnection.Start()")
}

func (m *MockConnection) Stop() {
	log.Print("MockConnection.Stop()")
}

func (m MockConnection) Close() {
	log.Print("MockConnection.Close()")
}

func (m MockConnection) GetConnectionHash() types.ConnectionHash {
	return m.clientFlow.ConnectionHash()
}

func (m MockConnection) GetLastSeen() time.Time {
	return m.lastSeen
}

func (m MockConnection) ReceivePacket(p *types.PacketManifest) {
	log.Print("MockConnection.ReceivePacket:")
	m.packetObserverChan <- true
}

func (m MockConnection) SetPacketLogger(l types.PacketLogger) {
}

type MockPacketLogger struct {
}

func NewMockPacketLogger(str string, flow *types.TcpIpFlow) types.PacketLogger {
	m := MockPacketLogger{}
	return types.PacketLogger(&m)
}

func (m *MockPacketLogger) WritePacket(rawPacket []byte, timestamp time.Time) {
}

func (m MockPacketLogger) Start() {
}

func (m MockPacketLogger) Stop() {
}

func SetupTestInquisitor() (*BadgerSupervisor, PacketDispatcher, types.PacketSource) {
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
	connOptions := ConnectionOptions{}
	connectionFactory := ConnectionFactory{
		options:              &connOptions,
		CreateConnectionFunc: NewMockConnection,
	}
	supervisor := NewBadgerSupervisor(&snifferOptions, &inquisitorOptions, NewMockSniffer, &connectionFactory, NewMockPacketLogger)

	log.Print("supervisor before run")
	go supervisor.Run()
	log.Print("supervisor after run")

	sniffer := supervisor.GetSniffer()
	startedChan := sniffer.GetStartedChan()
	dispatcher := supervisor.GetDispatcher()
	<-startedChan
	log.Print("started.")
	return supervisor, dispatcher, sniffer
}

func TestInquisitorForceQuit(t *testing.T) {
	supervisor, _, _ := SetupTestInquisitor()
	var sig os.Signal
	supervisor.forceQuitChan <- sig
}

func TestInquisitorSourceStopped(t *testing.T) {
	_, _, sniffer := SetupTestInquisitor()
	sniffer.Stop()
}

func TestInquisitorSourceReceiveOne(t *testing.T) {

	_, dispatcher, sniffer := SetupTestInquisitor()
	//supervisor, dispatcher, sniffer := SetupTestInquisitor()

	ip := layers.IPv4{
		SrcIP:    net.IP{1, 2, 3, 4},
		DstIP:    net.IP{2, 3, 4, 5},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		Seq:     3,
		SYN:     false,
		SrcPort: 1,
		DstPort: 2,
	}
	flow := types.NewTcpIpFlowFromLayers(ip, tcp)
	p := types.PacketManifest{
		Timestamp: time.Now(),
		Flow:      flow,
		IP:        ip,
		TCP:       tcp,
		Payload:   []byte{1, 2, 3, 4, 5, 6, 7},
	}

	connsChan := dispatcher.GetObservedConnectionsChan(1)
	dispatcher.ReceivePacket(&p)

	<-connsChan
	// XXX we now have one connection
	conns := dispatcher.Connections()

	// assert conns len is 1
	if len(conns) != 1 {
		t.Fatalf("number of connections %d is not 1", len(conns))
	}

	conn := conns[0]
	mockConn := conn.(*MockConnection)

	log.Print("awaiting packet...")
	<-mockConn.packetObserverChan

	sniffer.Stop()
}
