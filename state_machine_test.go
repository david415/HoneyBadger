package HoneyBadger

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"net"
	"testing"
	"time"
)

func TestStateDataTransfer(t *testing.T) {
	conn := NewConnection(nil)
	conn.AttackLogger = NewDummyAttackLogger()

	conn.state = TCP_DATA_TRANSFER
	clientRingCount := 0
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
	p := PacketManifest{
		IP:      ip,
		TCP:     tcp,
		Payload: []byte{1, 2, 3, 4, 5, 6, 7},
	}
	flow := NewTcpIpFlowFromLayers(ip, tcp)
	conn.serverFlow = flow
	conn.clientFlow = flow.Reverse()
	conn.clientNextSeq = 9666
	conn.serverNextSeq = 3

	conn.receivePacket(p, flow, time.Now())
	if conn.state != TCP_DATA_TRANSFER {
		t.Error("invalid state transition\n")
		t.Fail()
	}
	conn.ClientStreamRing.Do(func(x interface{}) {
		_, ok := x.(Reassembly)
		if ok {
			clientRingCount += 1
		}
	})
	if clientRingCount != 1 {
		t.Errorf("clientRingCount %d not correct", clientRingCount)
		t.Fail()
	}

	// next set of tests
	tcp = layers.TCP{
		Seq:     10,
		SYN:     false,
		SrcPort: 1,
		DstPort: 2,
	}
	p = PacketManifest{
		IP:      ip,
		TCP:     tcp,
		Payload: []byte{1, 2, 3, 4, 5, 6, 7},
	}
	conn.receivePacket(p, flow, time.Now())
	if conn.state != TCP_DATA_TRANSFER {
		t.Error("invalid state transition\n")
		t.Fail()
	}
	clientRingCount = 0
	conn.ClientStreamRing.Do(func(x interface{}) {
		_, ok := x.(Reassembly)
		if ok {
			clientRingCount += 1
		}
	})
	if clientRingCount != 2 {
		t.Errorf("clientRingCount %d not correct", clientRingCount)
		t.Fail()
	}

	// next test
	tcp = layers.TCP{
		Seq:     5,
		SYN:     false,
		SrcPort: 1,
		DstPort: 2,
	}
	p = PacketManifest{
		IP:      ip,
		TCP:     tcp,
		Payload: []byte{1, 2, 3, 4, 5, 6, 7},
	}
	conn.receivePacket(p, flow, time.Now())
	if conn.state != TCP_DATA_TRANSFER {
		t.Error("invalid state transition\n")
		t.Fail()
	}
	clientRingCount = 0
	conn.ClientStreamRing.Do(func(x interface{}) {
		_, ok := x.(Reassembly)
		if ok {
			clientRingCount += 1
		}
	})
	if clientRingCount != 2 {
		t.Errorf("clientRingCount %d not correct", clientRingCount)
		t.Fail()
	}

}

func TestTCPConnect(t *testing.T) {
	conn := NewConnection(nil)
	ip := layers.IPv4{
		SrcIP:    net.IP{1, 2, 3, 4},
		DstIP:    net.IP{2, 3, 4, 5},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		Seq:     3,
		SYN:     true,
		ACK:     false,
		SrcPort: 1,
		DstPort: 2,
	}
	p := PacketManifest{
		IP:      ip,
		TCP:     tcp,
		Payload: []byte{},
	}
	tcp.SetNetworkLayerForChecksum(&ip)
	ipFlow, _ := gopacket.FlowFromEndpoints(layers.NewIPEndpoint(net.IPv4(1, 2, 3, 4)), layers.NewIPEndpoint(net.IPv4(2, 3, 4, 5)))
	tcpFlow, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(layers.TCPPort(1)), layers.NewTCPPortEndpoint(layers.TCPPort(2)))
	flow := NewTcpIpFlowFromFlows(ipFlow, tcpFlow)
	flowReversed := flow.Reverse()

	conn.clientFlow = flow
	conn.serverFlow = flowReversed
	conn.receivePacket(p, flow, time.Now())
	if conn.state != TCP_CONNECTION_REQUEST {
		t.Error("invalid state transition\n")
		t.Fail()
	}

	// next state transition test
	ip = layers.IPv4{
		SrcIP:    net.IP{2, 3, 4, 5},
		DstIP:    net.IP{1, 2, 3, 4},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp = layers.TCP{
		Seq:     9,
		SYN:     true,
		ACK:     true,
		Ack:     4,
		SrcPort: 2,
		DstPort: 1,
	}
	p = PacketManifest{
		IP:      ip,
		TCP:     tcp,
		Payload: []byte{},
	}
	conn.receivePacket(p, flowReversed, time.Now())
	if conn.state != TCP_CONNECTION_ESTABLISHED {
		t.Errorf("invalid state transition: current state %d\n", conn.state)
		t.Fail()
	}

	// next state transition test
	ip = layers.IPv4{
		SrcIP:    net.IP{1, 2, 3, 4},
		DstIP:    net.IP{2, 3, 4, 5},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp = layers.TCP{
		Seq:     4,
		SYN:     false,
		ACK:     true,
		Ack:     10,
		SrcPort: 1,
		DstPort: 2,
	}
	p = PacketManifest{
		IP:      ip,
		TCP:     tcp,
		Payload: []byte{},
	}
	conn.receivePacket(p, flow, time.Now())
	if conn.state != TCP_DATA_TRANSFER {
		t.Error("invalid state transition\n")
		t.Fail()
	}

}

func TestClientThreeWayClose(t *testing.T) {
	HelperTestThreeWayClose(true, t)
}

func TestServerThreeWayClose(t *testing.T) {
	HelperTestThreeWayClose(false, t)
}

func HelperTestThreeWayClose(isClient bool, t *testing.T) {
	var closerState, remoteState *uint8
	attackLogger := NewDummyAttackLogger()
	conn := NewConnection(nil)
	conn.AttackLogger = attackLogger
	conn.state = TCP_DATA_TRANSFER
	conn.serverNextSeq = 4666
	conn.clientNextSeq = 9666

	if isClient {
		closerState = &conn.clientState
		remoteState = &conn.serverState
	} else {
		closerState = &conn.serverState
		remoteState = &conn.clientState
	}

	ipFlow, _ := gopacket.FlowFromEndpoints(layers.NewIPEndpoint(net.IPv4(1, 2, 3, 4)), layers.NewIPEndpoint(net.IPv4(2, 3, 4, 5)))
	tcpFlow, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(layers.TCPPort(1)), layers.NewTCPPortEndpoint(layers.TCPPort(2)))

	ip := layers.IPv4{
		SrcIP:    net.IP{1, 2, 3, 4},
		DstIP:    net.IP{2, 3, 4, 5},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	tcp := layers.TCP{
		Seq:     9666,
		FIN:     true,
		SYN:     false,
		ACK:     false,
		SrcPort: 1,
		DstPort: 2,
	}
	p := PacketManifest{
		IP:      ip,
		TCP:     tcp,
		Payload: []byte{},
	}
	//flow := NewTcpIpFlowFromLayers(ip, tcp)
	flow := NewTcpIpFlowFromFlows(ipFlow, tcpFlow)
	conn.clientFlow = flow
	conn.serverFlow = flow.Reverse()

	conn.receivePacket(p, flow, time.Now())
	if conn.state != TCP_CONNECTION_CLOSING {
		t.Error("connection state must transition to TCP_CONNECTION_CLOSING\n")
		t.Fail()
	}
	if *closerState != TCP_FIN_WAIT1 {
		t.Error("closer state must be in TCP_FINE_WAIT1\n")
		t.Fail()
	}
	if *remoteState != TCP_CLOSE_WAIT {
		t.Error("remote state must be in TCP_CLOSE_WAIT\n")
		t.Fail()
	}

	// next state transition
	ip = layers.IPv4{
		SrcIP:    net.IP{2, 3, 4, 5},
		DstIP:    net.IP{1, 2, 3, 4},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp = layers.TCP{
		Seq:     4666,
		SYN:     false,
		FIN:     true,
		ACK:     true,
		Ack:     9667,
		SrcPort: 2,
		DstPort: 1,
	}
	p = PacketManifest{
		IP:      ip,
		TCP:     tcp,
		Payload: []byte{},
	}

	flow2 := flow.Reverse()
	conn.receivePacket(p, flow2, time.Now())
	if conn.state != TCP_CONNECTION_CLOSING {
		t.Error("connection state must transition to TCP_CONNECTION_CLOSING\n")
		t.Fail()
	}

	// next state transition
	ip = layers.IPv4{
		SrcIP:    net.IP{1, 2, 3, 4},
		DstIP:    net.IP{2, 3, 4, 5},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp = layers.TCP{
		Seq:     9667,
		SYN:     false,
		FIN:     false,
		ACK:     true,
		Ack:     4667,
		SrcPort: 1,
		DstPort: 2,
	}
	p = PacketManifest{
		IP:      ip,
		TCP:     tcp,
		Payload: []byte{},
	}

	conn.receivePacket(p, flow, time.Now())
	if conn.state != TCP_CLOSED {
		t.Errorf("failed to close; current state == %d\n", conn.state)
	}
}

func TestClosePanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("failed to panic")
			t.Fail()
		}
	}()
	conn := NewConnection(nil)
	conn.Close()
	conn.Close()
}

func TestTCPHijack(t *testing.T) {
	attackLogger := NewDummyAttackLogger()
	conn := NewConnection(nil)
	conn.AttackLogger = attackLogger

	ip := layers.IPv4{
		SrcIP:    net.IP{1, 2, 3, 4},
		DstIP:    net.IP{2, 3, 4, 5},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		Seq:     3,
		SYN:     true,
		ACK:     false,
		SrcPort: 1,
		DstPort: 2,
	}
	p := PacketManifest{
		IP:      ip,
		TCP:     tcp,
		Payload: []byte{},
	}
	tcp.SetNetworkLayerForChecksum(&ip)
	ipFlow, _ := gopacket.FlowFromEndpoints(layers.NewIPEndpoint(net.IPv4(1, 2, 3, 4)), layers.NewIPEndpoint(net.IPv4(2, 3, 4, 5)))
	tcpFlow, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(layers.TCPPort(1)), layers.NewTCPPortEndpoint(layers.TCPPort(2)))
	flow := NewTcpIpFlowFromFlows(ipFlow, tcpFlow)
	flowReversed := flow.Reverse()

	conn.clientFlow = flow
	conn.serverFlow = flowReversed
	conn.receivePacket(p, flow, time.Now())
	if conn.state != TCP_CONNECTION_REQUEST {
		t.Error("invalid state transition\n")
		t.Fail()
	}

	// next state transition test
	ip = layers.IPv4{
		SrcIP:    net.IP{2, 3, 4, 5},
		DstIP:    net.IP{1, 2, 3, 4},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp = layers.TCP{
		Seq:     9,
		SYN:     true,
		ACK:     true,
		Ack:     4,
		SrcPort: 2,
		DstPort: 1,
	}
	p = PacketManifest{
		IP:      ip,
		TCP:     tcp,
		Payload: []byte{},
	}
	conn.receivePacket(p, flowReversed, time.Now())
	if conn.state != TCP_CONNECTION_ESTABLISHED {
		t.Errorf("invalid state transition: current state %d\n", conn.state)
		t.Fail()
	}

	// test hijack in TCP_CONNECTION_ESTABLISHED state
	ip = layers.IPv4{
		SrcIP:    net.IP{2, 3, 4, 5},
		DstIP:    net.IP{1, 2, 3, 4},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp = layers.TCP{
		Seq:     6699,
		SYN:     true,
		ACK:     true,
		Ack:     4,
		SrcPort: 2,
		DstPort: 1,
	}
	p = PacketManifest{
		IP:      ip,
		TCP:     tcp,
		Payload: []byte{},
	}
	conn.receivePacket(p, flowReversed, time.Now())
	if attackLogger.Count != 1 {
		t.Error("hijack detection fail")
		t.Fail()
	}

	// next state transition test
	ip = layers.IPv4{
		SrcIP:    net.IP{1, 2, 3, 4},
		DstIP:    net.IP{2, 3, 4, 5},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp = layers.TCP{
		Seq:     4,
		SYN:     false,
		ACK:     true,
		Ack:     10,
		SrcPort: 1,
		DstPort: 2,
	}
	p = PacketManifest{
		IP:      ip,
		TCP:     tcp,
		Payload: []byte{},
	}
	conn.receivePacket(p, flow, time.Now())
	if conn.state != TCP_DATA_TRANSFER {
		t.Error("invalid state transition\n")
		t.Fail()
	}

	// test hijack in TCP_DATA_TRANSFER state
	ip = layers.IPv4{
		SrcIP:    net.IP{2, 3, 4, 5},
		DstIP:    net.IP{1, 2, 3, 4},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp = layers.TCP{
		Seq:     7711,
		SYN:     true,
		ACK:     true,
		Ack:     4,
		SrcPort: 2,
		DstPort: 1,
	}
	p = PacketManifest{
		IP:      ip,
		TCP:     tcp,
		Payload: []byte{},
	}
	conn.receivePacket(p, flowReversed, time.Now())
	if attackLogger.Count != 2 {
		t.Error("hijack detection fail")
		t.Fail()
	}

}
