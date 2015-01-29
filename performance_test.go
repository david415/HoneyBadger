package HoneyBadger

import (
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/tcpassembly"
	"net"
	"testing"
)

func BenchmarkSingleOneWayDataTransfer(b *testing.B) {
	conn := NewConnection(nil)
	conn.AttackLogger = NewDummyAttackLogger()
	conn.state = TCP_DATA_TRANSFER
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
		Payload: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
	}
	flow := NewTcpIpFlowFromLayers(ip, tcp)
	conn.serverFlow = flow
	conn.clientFlow = flow.Reverse()
	conn.clientNextSeq = 9666
	conn.serverNextSeq = 3

	for i := 0; i < b.N; i++ {
		conn.receivePacket(p, flow)
		if conn.state != TCP_DATA_TRANSFER {
			panic("state transition error")
		}
		p.TCP.Seq += 10
	}
}

func BenchmarkSingleOneWayDataTransferOccasionalInjection(b *testing.B) {
	conn := NewConnection(nil)
	conn.AttackLogger = NewDummyAttackLogger()
	conn.state = TCP_DATA_TRANSFER
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
		Payload: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
	}
	flow := NewTcpIpFlowFromLayers(ip, tcp)
	conn.serverFlow = flow
	conn.clientFlow = flow.Reverse()
	conn.clientNextSeq = 9666
	conn.serverNextSeq = 3

	for i := 0; i < b.N; i++ {
		conn.receivePacket(p, flow)
		if conn.state != TCP_DATA_TRANSFER {
			panic("state transition error")
		}
		if i%10 == 9 {
			p.TCP.Seq += 4
		} else {
			p.TCP.Seq += 10
		}
	}
}

func BenchmarkSingleTwoWayDataTransfer(b *testing.B) {
	conn := NewConnection(nil)
	conn.AttackLogger = NewDummyAttackLogger()
	conn.state = TCP_DATA_TRANSFER
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
	serverPacket := PacketManifest{
		IP:      ip,
		TCP:     tcp,
		Payload: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
	}

	clientPacket := PacketManifest{
		IP:      ip,
		TCP:     tcp,
		Payload: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
	}
	clientPacket.IP.SrcIP = net.IP{2, 3, 4, 5}
	clientPacket.IP.DstIP = net.IP{1, 2, 3, 4}
	clientPacket.TCP.SrcPort = 2
	clientPacket.TCP.DstPort = 1
	clientPacket.TCP.Seq = 9666

	serverFlow := NewTcpIpFlowFromLayers(serverPacket.IP, serverPacket.TCP)
	clientFlow := serverFlow.Reverse()

	conn.serverFlow = serverFlow
	conn.clientFlow = clientFlow
	conn.clientNextSeq = tcpassembly.Sequence(clientPacket.TCP.Seq)
	conn.serverNextSeq = tcpassembly.Sequence(serverPacket.TCP.Seq)

	for i := 0; i < b.N; i++ {
		conn.receivePacket(serverPacket, serverFlow)
		if conn.state != TCP_DATA_TRANSFER {
			panic("state transition error")
		}
		serverPacket.TCP.Seq += 11

		conn.receivePacket(clientPacket, clientFlow)
		if conn.state != TCP_DATA_TRANSFER {
			panic("state transition error")
		}
		clientPacket.TCP.Seq += 10
	}
}

func BenchmarkSingleTwoWayDataTransferWithOccasionalInjection(b *testing.B) {
	conn := NewConnection(nil)
	conn.AttackLogger = NewDummyAttackLogger()
	conn.state = TCP_DATA_TRANSFER
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
	serverPacket := PacketManifest{
		IP:      ip,
		TCP:     tcp,
		Payload: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
	}

	clientPacket := PacketManifest{
		IP:      ip,
		TCP:     tcp,
		Payload: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
	}
	clientPacket.IP.SrcIP = net.IP{2, 3, 4, 5}
	clientPacket.IP.DstIP = net.IP{1, 2, 3, 4}
	clientPacket.TCP.SrcPort = 2
	clientPacket.TCP.DstPort = 1
	clientPacket.TCP.Seq = 9666

	serverFlow := NewTcpIpFlowFromLayers(serverPacket.IP, serverPacket.TCP)
	clientFlow := serverFlow.Reverse()

	conn.serverFlow = serverFlow
	conn.clientFlow = clientFlow
	conn.clientNextSeq = tcpassembly.Sequence(clientPacket.TCP.Seq)
	conn.serverNextSeq = tcpassembly.Sequence(serverPacket.TCP.Seq)

	for i := 0; i < b.N; i++ {
		conn.receivePacket(serverPacket, serverFlow)
		if conn.state != TCP_DATA_TRANSFER {
			panic("state transition error")
		}
		if i%10 == 9 {
			serverPacket.TCP.Seq += 4
		} else {
			serverPacket.TCP.Seq += 10
		}
		conn.receivePacket(clientPacket, clientFlow)
		if conn.state != TCP_DATA_TRANSFER {
			panic("state transition error")
		}
		clientPacket.TCP.Seq += 10
	}
}
