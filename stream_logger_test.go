package HoneyBadger

import (
	"bytes"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"net"
	"testing"
)

func TestStreamLogger(t *testing.T) {
	ipFlow, _ := gopacket.FlowFromEndpoints(layers.NewIPEndpoint(net.IPv4(1, 2, 3, 4)), layers.NewIPEndpoint(net.IPv4(2, 3, 4, 5)))
	tcpFlow, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(layers.TCPPort(1)), layers.NewTCPPortEndpoint(layers.TCPPort(2)))
	flow := NewTcpIpFlowFromFlows(ipFlow, tcpFlow)

	testWriter := NewTestSignalWriter()

	streamLogger := NewStreamLogger("meow", flow)
	streamLogger.writer = testWriter
	streamLogger.Start()

	want := []byte{1, 2, 3, 4, 5, 6, 7}
	res := []Reassembly{
		Reassembly{
			Bytes: want,
		},
	}

	go streamLogger.Reassembled(res)
	<-testWriter.signalChan

	if !bytes.Equal(testWriter.lastWrite, want) {
		t.Errorf("stream log entry is wrong")
		t.Fail()
	}

	go streamLogger.ReassemblyComplete()
	<-testWriter.closeChan

	go streamLogger.Stop()
}
