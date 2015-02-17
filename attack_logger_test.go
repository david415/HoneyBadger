package HoneyBadger

import (
	"bytes"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestAttackJsonLogger(t *testing.T) {
	logger := NewAttackJsonLogger(".")
	testWriter := NewTestSignalWriter()
	logger.writer = testWriter
	logger.Start()

	ipFlow, _ := gopacket.FlowFromEndpoints(layers.NewIPEndpoint(net.IPv4(1, 2, 3, 4)), layers.NewIPEndpoint(net.IPv4(2, 3, 4, 5)))
	tcpFlow, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(layers.TCPPort(1)), layers.NewTCPPortEndpoint(layers.TCPPort(2)))
	flow := NewTcpIpFlowFromFlows(ipFlow, tcpFlow)

	timestamp := time.Now()

	// these sloppy unit test could be improved!
	// by properly decoding the json and looking for certain values in certain fields

	// test ReportHijackAttack
	logger.ReportHijackAttack(timestamp, flow, 101, 103)
	<-testWriter.signalChan

	timeText, err := timestamp.MarshalText()
	if err != nil {
		panic("time marshal fail")
	}

	want := fmt.Sprintf("{\"Type\":\"hijack\",\"Flow\":\"1.2.3.4:1-2.3.4.5:2\",\"Time\":\"%s\",\"HijackSeq\":101,\"HijackAck\":103,\"Payload\":\"\",\"Overlap\":\"\",\"StartSequence\":0,\"EndSequence\":0,\"OverlapStart\":0,\"OverlapEnd\":0}\n", timeText)

	if !bytes.Equal(testWriter.lastWrite, []byte(want)) {
		t.Errorf("handshake hijack report is wrong")
		t.Fail()
	}

	testWriter.lastWrite = []byte{}

	// ReportInjectionAttack
	logger.ReportInjectionAttack("injection", timestamp, flow, []byte{1, 2, 3, 4, 5}, []byte{5, 6, 7}, 7, 77, 3, 33)
	<-testWriter.signalChan

	want = fmt.Sprintf("{\"Type\":\"injection\",\"Flow\":\"1.2.3.4:1-2.3.4.5:2\",\"Time\":\"%s\",\"HijackSeq\":0,\"HijackAck\":0,\"Payload\":\"AQIDBAU=\",\"Overlap\":\"BQYH\",\"StartSequence\":7,\"EndSequence\":77,\"OverlapStart\":3,\"OverlapEnd\":33}\n", timeText)

	if !bytes.Equal(testWriter.lastWrite, []byte(want)) {
		t.Errorf("injection attack report is wrong\n%s", testWriter.lastWrite)
		t.Fail()
	}

	logger.Stop()
}
