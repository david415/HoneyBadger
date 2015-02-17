package HoneyBadger

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"container/ring"
	"net"
	"testing"
	"time"
)

func TestOrderedCoalesce(t *testing.T) {
	maxBufferedPagesTotal := 1024
	maxBufferedPagesPerFlow := 1024
	streamRing := ring.New(40)
	pager := NewPager()

	ipFlow, _ := gopacket.FlowFromEndpoints(layers.NewIPEndpoint(net.IPv4(1, 2, 3, 4)), layers.NewIPEndpoint(net.IPv4(2, 3, 4, 5)))
	tcpFlow, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(layers.TCPPort(1)), layers.NewTCPPortEndpoint(layers.TCPPort(2)))
	flow := NewTcpIpFlowFromFlows(ipFlow, tcpFlow)

	var nextSeq Sequence = Sequence(1)
	ret := []Reassembly{}
	coalesce := NewOrderedCoalesce(ret, &flow, pager, streamRing, maxBufferedPagesTotal, maxBufferedPagesPerFlow)

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
		Timestamp: time.Now(),
		Flow:      flow,
		IP:        ip,
		TCP:       tcp,
		Payload:   []byte{1, 2, 3, 4, 5, 6, 7},
	}

	coalesce.Start()
	coalesce.insert(p, nextSeq)

	if coalesce.pager.Used() != 1 {
		t.Errorf("coalesce.pager.Used() not equal to 1\n")
		t.Fail()
	}

	coalesce.Stop()
}
