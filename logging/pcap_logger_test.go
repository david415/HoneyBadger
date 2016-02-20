package logging

import (
	"bytes"
	"github.com/david415/HoneyBadger/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"log"
	"net"
	"testing"
	"encoding/hex"
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

type TestPcapWriter struct {
	lastWrite []byte
}

func NewTestPcapWriter() *TestPcapWriter {
	return &TestPcapWriter{}
}

func (w *TestPcapWriter) Write(data []byte) (int, error) {
	w.lastWrite = data
	return len(data), nil
}

func (w *TestPcapWriter) Close() error {
	return nil
}

func TestPcapLogger(t *testing.T) {
	ipFlow, _ := gopacket.FlowFromEndpoints(layers.NewIPEndpoint(net.IPv4(1, 2, 3, 4)), layers.NewIPEndpoint(net.IPv4(2, 3, 4, 5)))
	tcpFlow, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(layers.TCPPort(1)), layers.NewTCPPortEndpoint(layers.TCPPort(2)))
	flow := types.NewTcpIpFlowFromFlows(ipFlow, tcpFlow)

	pcapLogger := NewPcapLogger("log-dir", "archive-dir", &flow, 1, 10)
	ackChan := make(chan bool)
	pcapLogger.AckChan = &ackChan
	testWriter := NewTestPcapWriter()
	pcapLogger.SetFileWriter(testWriter)
	//testWriter.lastWrite = make([]byte, 0)

	pcapLogger.Start()

	rawPacket := makeTestPacket()
	pcapLogger.WritePacket(rawPacket, time.Now())

	<- ackChan

	log.Printf("before hex dump of %d len bytes\n", len(testWriter.lastWrite))
	log.Print(hex.Dump(testWriter.lastWrite))
	log.Print("post hex\n")

	// XXX TODO test our rotating quota logger for pcap header output on each log file
	//want := []byte("\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01\x00\x00\x00")
	//if !bytes.Equal(testWriter.lastWrite, want) {
	//	t.Errorf("pcap header is wrong")
	//	t.Fail()
	//}

	if !bytes.Equal(testWriter.lastWrite, rawPacket) {
		t.Errorf("pcap packet is wrong")
		t.Fail()
	}

	pcapLogger.Stop()
}
