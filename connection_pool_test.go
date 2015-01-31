package HoneyBadger

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"net"
	"testing"
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

	// more tests
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

}
