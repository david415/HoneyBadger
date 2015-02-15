package HoneyBadger

import (
	"bytes"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"net"
	"testing"
	"time"
)

func makeTestPacket() []byte {
	var testSeq uint32 = 12345
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	eth := layers.Ethernet{
		SrcMAC: net.HardwareAddr{0xde, 0xad, 0xbe, 0xee, 0xee, 0xff},
		DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}
	ip := layers.IPv4{
		SrcIP:    net.IP{1, 2, 3, 4},
		DstIP:    net.IP{2, 3, 4, 5},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		SYN:       true,
		SrcPort:   1,
		DstPort:   2,
		Seq:       testSeq,
		BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3}},
	}
	tcp.SetNetworkLayerForChecksum(&ip)
	gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp)
	packetData := buf.Bytes()
	return packetData
}

func TestPcapLogger(t *testing.T) {
	ipFlow, _ := gopacket.FlowFromEndpoints(layers.NewIPEndpoint(net.IPv4(1, 2, 3, 4)), layers.NewIPEndpoint(net.IPv4(2, 3, 4, 5)))
	tcpFlow, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(layers.TCPPort(1)), layers.NewTCPPortEndpoint(layers.TCPPort(2)))
	flow := NewTcpIpFlowFromFlows(ipFlow, tcpFlow)

	pcapLogger := NewPcapLogger("fake-dir", flow)
	testWriter := NewTestSignalWriter()
	pcapLogger.fileWriter = testWriter

	go pcapLogger.Start()

	<-testWriter.signalChan

	// test pcap header
	want := []byte("\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01\x00\x00\x00")
	if !bytes.Equal(testWriter.lastWrite, want) {
		t.Errorf("pcap header is wrong")
		t.Fail()
	}

	// test pcap packet
	rawPacket := makeTestPacket()
	testWriter.lastWrite = make([]byte, 0)
	go pcapLogger.WritePacket(rawPacket, time.Now())

	<-testWriter.signalChan

	if !bytes.Equal(testWriter.lastWrite, rawPacket) {
		t.Errorf("pcap packet is wrong")
		t.Fail()
	}

	go pcapLogger.Stop()
}
