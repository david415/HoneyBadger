package HoneyBadger

import (
	"log"
	"net"
	"os"
	"testing"
	"time"

	"github.com/david415/HoneyBadger/logging"
	"github.com/david415/HoneyBadger/types"
	"github.com/google/gopacket/layers"
)

type MockSniffer struct {
	supervisor  types.Supervisor
	startedChan chan bool
}

func NewMockSniffer(options *types.SnifferDriverOptions, dispatcher PacketDispatcher) types.PacketSource {
	var packetSource types.PacketSource = &MockSniffer{
		startedChan: make(chan bool, 0),
	}
	return packetSource
}

func (s *MockSniffer) Start() {
	log.Print("MockSniffer Start()")
	s.startedChan <- true
}
func (s *MockSniffer) Stop() {
	log.Print("MockSniffer Stop()")
}
func (s *MockSniffer) SetSupervisor(supervisor types.Supervisor) {
	s.supervisor = supervisor
}
func (s *MockSniffer) GetStartedChan() chan bool {
	return s.startedChan
}

type MockConnection struct {
	options            ConnectionOptions
	clientFlow         types.TcpIpFlow
	serverFlow         types.TcpIpFlow
	lastSeen           time.Time
	ClientStreamRing   *types.Ring
	packetObserverChan chan bool
	receiveChan        chan *types.PacketManifest
}

func (m MockConnection) Close() {
	log.Print("MockConnection.Close()")
	close(m.receiveChan)
}

func (m MockConnection) ReceivePacket(p *types.PacketManifest) {
	m.packetObserverChan <- true
}

func (m MockConnection) GetConnectionHash() types.ConnectionHash {
	return m.clientFlow.ConnectionHash()
}

func (m MockConnection) GetLastSeen() time.Time {
	return m.lastSeen
}

func (m MockConnection) SetPacketLogger(l types.PacketLogger) {
	log.Print("MockConnection.SetPacketLogger")
}

type mockConnFactory struct {
}

func (m *mockConnFactory) Build(options ConnectionOptions) ConnectionInterface {
	c := &MockConnection{
		options:            options,
		packetObserverChan: make(chan bool, 0),
	}

	return c
}

type MockPacketLoggerFactory struct {
	pcapNum  int
	pcapSize int
}

func (f MockPacketLoggerFactory) Build(flow *types.TcpIpFlow) types.PacketLogger {
	return NewMockPacketLogger("str", flow, 10, 50)
}

type MockPacketLogger struct {
	packetObserverChan chan bool
}

func NewMockPacketLogger(str string, flow *types.TcpIpFlow, pcapNum int, pcapSize int) types.PacketLogger {
	m := MockPacketLogger{
		packetObserverChan: make(chan bool, 0),
	}
	return types.PacketLogger(&m)
}

func (m *MockPacketLogger) WritePacket(rawPacket []byte, timestamp time.Time) {
	log.Print("MockPacketLogger.WritePacket")
	m.packetObserverChan <- true
}

func (m *MockPacketLogger) Start() {
	log.Print("MockPacketLogger.Start")
}

func (m *MockPacketLogger) Stop() {
	log.Print("MockPacketLogger.Stop")
}

func (m *MockPacketLogger) Archive() {
}

func (m *MockPacketLogger) Remove() {
}

func SetupTestInquisitor() (*Supervisor, PacketDispatcher, types.PacketSource) {
	tcpIdleTimeout, _ := time.ParseDuration("10m")
	dispatcherOptions := DispatcherOptions{
		BufferedPerConnection:    10,
		BufferedTotal:            100,
		LogDir:                   ".",
		LogPackets:               true,
		TcpIdleTimeout:           tcpIdleTimeout,
		MaxRingPackets:           40,
		Logger:                   logging.NewAttackMetadataJsonLogger("archives"),
		DetectHijack:             true,
		DetectInjection:          true,
		DetectCoalesceInjection:  true,
		MaxConcurrentConnections: 100,
	}

	wireDuration, _ := time.ParseDuration("3s")
	snifferOptions := types.SnifferDriverOptions{
		Device:       "myInterface",
		Filename:     "",
		WireDuration: wireDuration,
		Snaplen:      65536,
		Filter:       "tcp",
	}
	factory := mockConnFactory{}
	mockPacketLoggerFactory := MockPacketLoggerFactory{}
	options := SupervisorOptions{
		SnifferDriverOptions: &snifferOptions,
		DispatcherOptions:    dispatcherOptions,
		SnifferFactory:       NewMockSniffer,
		ConnectionFactory:    &factory,
		PacketLoggerFactory:  mockPacketLoggerFactory,
	}

	supervisor := NewSupervisor(options)
	go supervisor.Run()
	sniffer := supervisor.GetSniffer()
	startedChan := sniffer.GetStartedChan()
	dispatcher := supervisor.GetDispatcher()
	<-startedChan
	return supervisor, dispatcher, sniffer
}

func TestInquisitorForceQuit(t *testing.T) {
	supervisor, _, _ := SetupTestInquisitor()
	var sig os.Signal
	supervisor.forceQuitChan <- sig
}

func TestInquisitorSourceStopped(t *testing.T) {
	supervisor, _, sniffer := SetupTestInquisitor()
	sniffer.Stop()
	supervisor.Stopped()
}

func TestInquisitorSourceReceiveOne(t *testing.T) {

	_, dispatcher, sniffer := SetupTestInquisitor()

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

	log.Print("before receive packet")
	dispatcher.ReceivePacket(&p)
	log.Print("after receive packet")
	connsChan := dispatcher.GetObservedConnectionsChan(1)
	log.Print("fu1")
	<-connsChan
	log.Print("fu2")
	log.Print("after connsChan receive")
	conns := dispatcher.Connections()
	log.Print("fu3")
	if len(conns) != 1 {
		t.Fatalf("number of connections %d is not 1", len(conns))
	}
	conn := conns[0]
	mockConn := conn.(*MockConnection)
	log.Print("listen to packet observer chan")
	<-mockConn.packetObserverChan
	sniffer.Stop()
}

func TestInquisitorResetTwice(t *testing.T) {

	_, dispatcher, sniffer := SetupTestInquisitor()

	startSeq := 3
	ip1 := layers.IPv4{
		SrcIP:    net.IP{1, 2, 3, 4},
		DstIP:    net.IP{2, 3, 4, 5},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp1 := layers.TCP{
		Seq:     uint32(startSeq),
		SYN:     false,
		RST:     true,
		SrcPort: 1,
		DstPort: 2,
	}
	flow1 := types.NewTcpIpFlowFromLayers(ip1, tcp1)
	packet1 := types.PacketManifest{
		Timestamp: time.Now(),
		Flow:      flow1,
		IP:        ip1,
		TCP:       tcp1,
		Payload:   []byte{1, 2, 3, 4, 5, 6, 7},
	}

	ip2 := layers.IPv4{
		SrcIP:    net.IP{1, 2, 3, 4},
		DstIP:    net.IP{2, 3, 4, 5},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp2 := layers.TCP{
		Seq:     uint32(startSeq + len(packet1.Payload)),
		SYN:     false,
		RST:     true,
		SrcPort: 1,
		DstPort: 2,
	}
	flow2 := types.NewTcpIpFlowFromLayers(ip2, tcp2)
	packet2 := types.PacketManifest{
		Timestamp: time.Now(),
		Flow:      flow2,
		IP:        ip2,
		TCP:       tcp2,
		Payload:   []byte{1, 2, 3, 4, 5, 6, 7},
	}
	connsChan := dispatcher.GetObservedConnectionsChan(1)
	dispatcher.ReceivePacket(&packet1)
	<-connsChan
	conns := dispatcher.Connections()
	if len(conns) != 1 {
		t.Fatalf("number of connections %d is not 1", len(conns))
	}
	conn := conns[0]
	mockConn := conn.(*MockConnection)
	<-mockConn.packetObserverChan
	conns = dispatcher.Connections()
	if len(conns) != 1 {
		t.Fatalf("number of connections %d is not 1", len(conns))
	}
	conn = conns[0]
	mockConn = conn.(*MockConnection)
	dispatcher.ReceivePacket(&packet2)
	<-mockConn.packetObserverChan
	sniffer.Stop()
}

func SetupRealConnectionInquisitor() (*Supervisor, PacketDispatcher, types.PacketSource) {
	tcpIdleTimeout, _ := time.ParseDuration("10m")
	dispatcherOptions := DispatcherOptions{
		BufferedPerConnection:    10,
		BufferedTotal:            100,
		LogDir:                   ".",
		LogPackets:               true,
		TcpIdleTimeout:           tcpIdleTimeout,
		MaxRingPackets:           40,
		Logger:                   logging.NewAttackMetadataJsonLogger("archives"),
		DetectHijack:             true,
		DetectInjection:          true,
		DetectCoalesceInjection:  true,
		MaxConcurrentConnections: 100,
	}

	wireDuration, _ := time.ParseDuration("3s")
	snifferOptions := types.SnifferDriverOptions{
		Device:       "myInterface",
		Filename:     "",
		WireDuration: wireDuration,
		Snaplen:      65536,
		Filter:       "tcp",
	}

	factory := &DefaultConnFactory{}
	mockPacketLoggerFactory := MockPacketLoggerFactory{}
	options := SupervisorOptions{
		SnifferDriverOptions: &snifferOptions,
		DispatcherOptions:    dispatcherOptions,
		SnifferFactory:       NewMockSniffer,
		ConnectionFactory:    factory,
		PacketLoggerFactory:  mockPacketLoggerFactory,
	}
	supervisor := NewSupervisor(options)
	go supervisor.Run()
	sniffer := supervisor.GetSniffer()
	startedChan := sniffer.GetStartedChan()
	dispatcher := supervisor.GetDispatcher()
	<-startedChan
	return supervisor, dispatcher, sniffer
}
