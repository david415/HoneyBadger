package HoneyBadger

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	//"log"
	"net"
	"testing"
	"time"
)

func TestConnectionPool(t *testing.T) {

	connPool := NewConnectionPool()
	conn := NewConnection(connPool)

	ipFlow, _ := gopacket.FlowFromEndpoints(layers.NewIPEndpoint(net.IPv4(1, 2, 3, 4)), layers.NewIPEndpoint(net.IPv4(2, 3, 4, 5)))
	tcpFlow, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(layers.TCPPort(1)), layers.NewTCPPortEndpoint(layers.TCPPort(2)))
	flow := NewTcpIpFlowFromFlows(ipFlow, tcpFlow)

	connPool.Put(flow, conn)

	if len(connPool.connectionMap) != 1 {
		t.Error("failed to add connection to pool")
		t.Fail()
	}

	connPool.Delete(flow)
	if len(connPool.connectionMap) != 0 {
		t.Error("failed to delete connection from pool")
		t.Fail()
	}

	// test CloseAllConnections
	conn.clientFlow = flow
	connPool.Put(flow, conn)

	ipFlow, _ = gopacket.FlowFromEndpoints(layers.NewIPEndpoint(net.IPv4(1, 9, 3, 4)), layers.NewIPEndpoint(net.IPv4(2, 9, 4, 5)))
	tcpFlow, _ = gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(layers.TCPPort(1)), layers.NewTCPPortEndpoint(layers.TCPPort(2)))
	flow = NewTcpIpFlowFromFlows(ipFlow, tcpFlow)
	conn = NewConnection(connPool)
	conn.clientFlow = flow

	connPool.Put(flow, conn)

	connPool.CloseAllConnections()

	if len(connPool.connectionMap) != 0 {
		t.Errorf("failed to close all connections from pool: %d\n", len(connPool.connectionMap))
		t.Fail()
	}

	// check nil case of connectionsLocked
	connPool.Lock()
	conns := connPool.connectionsLocked()
	connPool.Unlock()
	if len(conns) != 0 {
		t.Error("connectionsLocked() should failed to return zero")
		t.Fail()
	}

	// test zero case of CloseOlderThan
	count := connPool.CloseOlderThan(time.Now())
	if count != 0 {
		t.Error("CloseOlderThan fail")
		t.Fail()
	}

	// test close one case of CloseOlderThan
	conn = NewConnection(connPool)
	conn.clientFlow = flow
	connPool.Put(flow, conn)
	count = connPool.CloseOlderThan(time.Now())
	if count != 1 {
		t.Error("CloseOlderThan fail")
		t.Fail()
	}

	timeDuration := time.Minute * 5
	timestamp1 := time.Now()
	timestamp2 := timestamp1.Add(timeDuration)

	conn = NewConnection(connPool)
	conn.clientFlow = flow
	connPool.Put(flow, conn)
	conn.state = TCP_DATA_TRANSFER
	packetManifest := PacketManifest{}
	conn.receivePacket(packetManifest, flow, timestamp1)
	count = connPool.CloseOlderThan(time.Now())
	if count != 1 {
		t.Error("CloseOlderThan fail")
		t.Fail()
	}

	conn = NewConnection(connPool)
	conn.clientFlow = flow
	connPool.Put(flow, conn)
	conn.state = TCP_DATA_TRANSFER
	packetManifest = PacketManifest{}
	conn.receivePacket(packetManifest, flow, timestamp2)
	count = connPool.CloseOlderThan(timestamp1)
	if count != 0 {
		t.Error("CloseOlderThan fail")
		t.Fail()
	}

}
