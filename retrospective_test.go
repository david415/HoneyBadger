package HoneyBadger

import (
	"bytes"
	"log"
	"net"
	"testing"

	"github.com/david415/HoneyBadger/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type reassemblyInput struct {
	Seq     uint32
	Payload []byte
}

type TestOverlapBytesWant struct {
	bytes       []byte
	startOffset int
	endOffset   int
}

type DummyAttackLogger struct {
	Count int
}

func NewDummyAttackLogger() *DummyAttackLogger {
	a := DummyAttackLogger{
		Count: 0,
	}
	return &a
}

func (d *DummyAttackLogger) Log(event *types.Event) {
	d.Count += 1
}

func (d *DummyAttackLogger) Archive() {
}

func TestInjectionDetector(t *testing.T) {
	log.Print("TestInjectionDetector")
	attackLogger := NewDummyAttackLogger()
	options := ConnectionOptions{
		MaxBufferedPagesTotal:         0,
		MaxBufferedPagesPerConnection: 0,
		MaxRingPackets:                40,
		PageCache:                     nil,
		LogDir:                        "fake-log-dir",
		AttackLogger:                  attackLogger,
	}

	f := &DefaultConnFactory{}
	conn := f.Build(options).(*Connection)
	reassembly := types.Reassembly{
		Seq:   types.Sequence(5),
		Bytes: []byte{1, 2, 3, 4, 5},
	}
	conn.ClientStreamRing.Reassembly = &reassembly
	conn.ClientStreamRing = conn.ClientStreamRing.Next()

	p := types.PacketManifest{
		IP: layers.IPv4{
			SrcIP:    net.IP{1, 2, 3, 4},
			DstIP:    net.IP{2, 3, 4, 5},
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
		},
		TCP: layers.TCP{
			Seq:     7,
			SrcPort: 1,
			DstPort: 2,
		},
		Payload: []byte{1, 2, 3, 4, 5, 6, 7},
	}

	ipFlow, _ := gopacket.FlowFromEndpoints(layers.NewIPEndpoint(net.IPv4(1, 2, 3, 4)), layers.NewIPEndpoint(net.IPv4(2, 3, 4, 5)))
	tcpFlow, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(layers.TCPPort(1)), layers.NewTCPPortEndpoint(layers.TCPPort(2)))
	serverFlow := types.NewTcpIpFlowFromFlows(ipFlow, tcpFlow)
	conn.serverFlow = serverFlow
	clientFlow := serverFlow.Reverse()
	conn.clientFlow = clientFlow
	conn.detectInjection(&p, serverFlow)

	if attackLogger.Count != 1 {
		t.Errorf("detectInjection failed; count == %d\n", attackLogger.Count)
		t.Fail()
	}

	// next test case
	p.TCP = layers.TCP{
		Seq:     7,
		SrcPort: 1,
		DstPort: 2,
	}
	p.Payload = []byte{3, 4, 5}
	conn.detectInjection(&p, serverFlow)
	if attackLogger.Count == 0 {
		t.Error("failed to detect injection\n")
		t.Fail()
	}

	// next test case
	attackLogger.Count = 0
	p.TCP = layers.TCP{
		Seq:     1,
		SrcPort: 1,
		DstPort: 2,
	}
	p.Payload = []byte{1, 2, 3, 4, 5, 6}
	conn.detectInjection(&p, serverFlow)
	if attackLogger.Count == 0 {
		t.Error("failed to detect injection\n")
		t.Fail()
	}

	// next test case
	attackLogger.Count = 0
	p.TCP = layers.TCP{
		Seq:     1,
		SrcPort: 1,
		DstPort: 2,
	}
	p.Payload = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17}
	conn.detectInjection(&p, serverFlow)
	if attackLogger.Count != 1 {
		t.Error("injection detection failure\n")
		t.Fail()
	}
}

func TestGetRingSlice(t *testing.T) {
	options := ConnectionOptions{
		MaxBufferedPagesTotal:         0,
		MaxBufferedPagesPerConnection: 0,
		MaxRingPackets:                40,
		PageCache:                     nil,
		LogDir:                        "fake-log-dir",
	}

	f := &DefaultConnFactory{}
	conn := f.Build(options).(*Connection)
	for j := 5; j < 40; j += 5 {
		reassembly := types.Reassembly{
			Seq:   types.Sequence(j),
			Bytes: []byte{1, 2, 3, 4, 5},
		}

		conn.ClientStreamRing.Reassembly = &reassembly
		conn.ClientStreamRing = conn.ClientStreamRing.Next()
	}
	var startSeq uint32 = 5
	p := types.PacketManifest{
		IP: layers.IPv4{
			SrcIP:    net.IP{1, 2, 3, 4},
			DstIP:    net.IP{2, 3, 4, 5},
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
		},
		TCP: layers.TCP{
			Seq:     startSeq,
			SrcPort: 1,
			DstPort: 2,
		},
		Payload: []byte{1, 2, 3, 4, 5, 6, 7},
	}

	ipFlow, _ := gopacket.FlowFromEndpoints(layers.NewIPEndpoint(net.IPv4(1, 2, 3, 4)), layers.NewIPEndpoint(net.IPv4(2, 3, 4, 5)))
	tcpFlow, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(layers.TCPPort(1)), layers.NewTCPPortEndpoint(layers.TCPPort(2)))
	serverFlow := types.NewTcpIpFlowFromFlows(ipFlow, tcpFlow)
	clientFlow := serverFlow.Reverse()
	conn.serverFlow = serverFlow
	conn.clientFlow = clientFlow

	head, tail := getOverlapRings(&p, serverFlow, conn.ClientStreamRing)

	if head == nil {
		t.Fatal()
	}
	if tail == nil {
		t.Fatal()
	}

	ringSlice := getRingSlice(head, tail, 0, 1)
	if !bytes.Equal(ringSlice, []byte{1, 2, 3, 4, 5, 1}) {
		t.Error("byte comparison failed")
		t.Fail()
	}

	ringSlice = getRingSlice(head, tail, 0, 3)
	if !bytes.Equal(ringSlice, []byte{1, 2, 3, 4, 5, 1, 2, 3}) {
		t.Error("byte comparison failed")
		t.Fail()
	}

	ringSlice = getRingSlice(head, tail, 0, 1)
	if !bytes.Equal(ringSlice, []byte{1, 2, 3, 4, 5, 1}) {
		t.Error("byte comparison failed")
		t.Fail()
	}

	ringSlice = getRingSlice(head, tail, 1, 0)
	if !bytes.Equal(ringSlice, []byte{2, 3, 4, 5}) {
		t.Error("byte comparison failed")
		t.Fail()
	}

	ringSlice = getRingSlice(head, tail, 1, 1)
	if !bytes.Equal(ringSlice, []byte{2, 3, 4, 5, 1}) {
		t.Error("byte comparison failed")
		t.Fail()
	}

	ringSlice = getRingSlice(head, tail, 2, 0)
	if !bytes.Equal(ringSlice, []byte{3, 4, 5}) {
		t.Error("byte comparison failed")
		t.Fail()
	}
	ringSlice = getRingSlice(head, tail, 2, 3)
	if !bytes.Equal(ringSlice, []byte{3, 4, 5, 1, 2, 3}) {
		t.Error("byte comparison failed")
		t.Fail()
	}

	startSeq = 1
	p = types.PacketManifest{
		IP: layers.IPv4{
			SrcIP:    net.IP{1, 2, 3, 4},
			DstIP:    net.IP{2, 3, 4, 5},
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
		},
		TCP: layers.TCP{
			Seq:     startSeq,
			SrcPort: 1,
			DstPort: 2,
		},
		Payload: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
	}

	head, tail = getOverlapRings(&p, serverFlow, conn.ClientStreamRing)

	log.Printf("sequence of head %d", head.Reassembly.Seq)
	log.Printf("and tail %d", tail.Reassembly.Seq)

	ringSlice = getRingSlice(head, tail, 0, 2)

	if !bytes.Equal(ringSlice, []byte{1, 2, 3, 4, 5, 1, 2}) {
		t.Errorf("ringSlice is %x\n", ringSlice)
		t.Fail()
	}

	ringSlice = getRingSlice(head, tail, 2, 4)
	if !bytes.Equal(ringSlice, []byte{3, 4, 5, 1, 2, 3, 4}) {
		t.Errorf("ringSlice is %x\n", ringSlice) //XXX
		t.Fail()
	}
}

func TestGetRingSlicePanic1(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("failed to panic")
			t.Fail()
		}
	}()

	head := types.NewRing(3)
	head.Reassembly = &types.Reassembly{
		Seq:   types.Sequence(2),
		Bytes: []byte{1, 2, 3, 4, 5},
	}
	_ = getRingSlice(head, nil, 6, 0)
}

func TestGetRingSlicePanic3(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("failed to panic")
			t.Fail()
		}
	}()

	head := types.NewRing(3)
	head.Reassembly = &types.Reassembly{
		Seq:   types.Sequence(2),
		Bytes: []byte{1, 2, 3, 4, 5},
	}

	tail := types.NewRing(3)
	tail.Reassembly = &types.Reassembly{
		Seq:   types.Sequence(2),
		Bytes: []byte{1, 2, 3, 4, 5},
	}
	_ = getRingSlice(head, tail, 0, 6)
}

func TestGetRingSlicePanic4(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("failed to panic")
			t.Fail()
		}
	}()

	head := types.NewRing(3)
	head.Reassembly = &types.Reassembly{
		Seq:   types.Sequence(2),
		Bytes: []byte{1, 2, 3, 4, 5},
	}
	_ = getRingSlice(head, head, 0, 0)
}

func TestGetStartSequence(t *testing.T) {
	var start types.Sequence = 4
	var head *types.Ring = types.NewRing(10)
	head.Reassembly = &types.Reassembly{
		Seq:   3,
		Bytes: []byte{1, 2, 3, 4, 5, 6, 7},
	}
	startSeq := getStartSequence(head, start)
	if startSeq.Difference(start) != 0 {
		t.Errorf("startSeq %d != start %d\n", startSeq, start)
		t.Fail()
	}

	start = 2
	startSeq = getStartSequence(head, start)
	if startSeq != start.Add(1) {
		t.Errorf("startSeq %d != start %d\n", startSeq, start.Add(1))
		t.Fail()
	}
}

func TestGetOverlapBytes(t *testing.T) {
	overlapBytesTests := []struct {
		in   reassemblyInput
		want TestOverlapBytesWant
	}{
		{ //0
			reassemblyInput{3, []byte{2, 3, 4}}, TestOverlapBytesWant{
				bytes:       []byte{6},
				startOffset: 2,
				endOffset:   3,
			},
		},
		{ //1
			reassemblyInput{4, []byte{2, 3, 4}}, TestOverlapBytesWant{
				bytes:       []byte{6, 7},
				startOffset: 1,
				endOffset:   3,
			},
		},
		{ //2
			reassemblyInput{5, []byte{2, 3, 4}}, TestOverlapBytesWant{
				bytes:       []byte{6, 7, 8},
				startOffset: 0,
				endOffset:   3,
			},
		},
		{ //3
			reassemblyInput{6, []byte{1, 2, 3}}, TestOverlapBytesWant{
				bytes:       []byte{7, 8, 9},
				startOffset: 0,
				endOffset:   3,
			},
		},
		{ //4
			reassemblyInput{4, []byte{91, 92, 93, 94, 95, 96, 97}}, TestOverlapBytesWant{
				bytes:       []byte{6, 7, 8, 9, 10, 11},
				startOffset: 1,
				endOffset:   7,
			},
		},
		{
			reassemblyInput{4, []byte{91, 92, 93, 94, 95, 96, 97, 98}}, TestOverlapBytesWant{
				bytes:       []byte{6, 7, 8, 9, 10, 11, 12},
				startOffset: 1,
				endOffset:   8,
			},
		},
		{
			reassemblyInput{4, []byte{91, 92, 93, 94, 95, 96, 97, 98, 99}}, TestOverlapBytesWant{
				bytes:       []byte{6, 7, 8, 9, 10, 11, 12, 13},
				startOffset: 1,
				endOffset:   9,
			},
		},
		{
			reassemblyInput{3, []byte{1, 2, 3, 4, 5, 6, 7}}, TestOverlapBytesWant{
				bytes:       []byte{6, 7, 8, 9, 10},
				startOffset: 2,
				endOffset:   7,
			},
		},
		{
			reassemblyInput{34, []byte{1, 2, 3, 4, 5, 6, 7}}, TestOverlapBytesWant{
				bytes:       []byte{35, 36, 37, 38, 39, 40},
				startOffset: 0,
				endOffset:   6,
			},
		},
		{
			reassemblyInput{34, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}}, TestOverlapBytesWant{
				bytes:       []byte{35, 36, 37, 38, 39, 40},
				startOffset: 0,
				endOffset:   6,
			},
		},
		{
			reassemblyInput{5, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}}, TestOverlapBytesWant{
				bytes:       []byte{6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40},
				startOffset: 0,
				endOffset:   35,
			},
		},

		{
			reassemblyInput{5, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}}, TestOverlapBytesWant{
				bytes:       []byte{6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40},
				startOffset: 0,
				endOffset:   35,
			},
		},

		{
			reassemblyInput{5, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}}, TestOverlapBytesWant{
				bytes:       []byte{6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40},
				startOffset: 0,
				endOffset:   35,
			},
		},

		{
			reassemblyInput{4, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}}, TestOverlapBytesWant{
				bytes:       []byte{6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40},
				startOffset: 1,
				endOffset:   36,
			},
		},

		{
			reassemblyInput{3, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}}, TestOverlapBytesWant{
				bytes:       []byte{6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40},
				startOffset: 2,
				endOffset:   37,
			},
		},

		{
			reassemblyInput{4, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}}, TestOverlapBytesWant{
				bytes:       []byte{6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40},
				startOffset: 1,
				endOffset:   36,
			},
		},
	}

	options := ConnectionOptions{
		MaxBufferedPagesTotal:         0,
		MaxBufferedPagesPerConnection: 0,
		MaxRingPackets:                40,
		PageCache:                     nil,
		LogDir:                        "fake-log-dir",
	}

	f := &DefaultConnFactory{}
	conn := f.Build(options).(*Connection)

	for j := 5; j < 40; j += 5 {
		reassembly := types.Reassembly{
			Seq:   types.Sequence(j),
			Bytes: []byte{byte(j + 1), byte(j + 2), byte(j + 3), byte(j + 4), byte(j + 5)},
		}
		conn.ClientStreamRing.Reassembly = &reassembly
		conn.ClientStreamRing = conn.ClientStreamRing.Next()
	}
	for i := 0; i < len(overlapBytesTests); i++ {
		var startSeq uint32 = overlapBytesTests[i].in.Seq
		start := types.Sequence(startSeq)
		end := start.Add(len(overlapBytesTests[i].in.Payload) - 1)
		p := types.PacketManifest{
			IP: layers.IPv4{
				SrcIP:    net.IP{1, 2, 3, 4},
				DstIP:    net.IP{2, 3, 4, 5},
				Version:  4,
				TTL:      64,
				Protocol: layers.IPProtocolTCP,
			},
			TCP: layers.TCP{
				Seq:     startSeq,
				SrcPort: 1,
				DstPort: 2,
			},
			Payload: overlapBytesTests[i].in.Payload,
		}

		ipFlow, _ := gopacket.FlowFromEndpoints(layers.NewIPEndpoint(net.IPv4(1, 2, 3, 4)), layers.NewIPEndpoint(net.IPv4(2, 3, 4, 5)))
		tcpFlow, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(layers.TCPPort(1)), layers.NewTCPPortEndpoint(layers.TCPPort(2)))
		serverFlow := types.NewTcpIpFlowFromFlows(ipFlow, tcpFlow)
		clientFlow := serverFlow.Reverse()
		conn.serverFlow = serverFlow
		conn.clientFlow = clientFlow

		head, tail := getOverlapRings(&p, serverFlow, conn.ClientStreamRing)
		if head == nil || tail == nil {
			t.Errorf("%d getOverlapRings returned a nil\n", i)
			t.Fail()
			continue
		}

		log.Printf("test #%d", i)
		overlapBytes, startOffset, endOffset := getOverlapBytes(head, tail, start, end)

		if startOffset != overlapBytesTests[i].want.startOffset {
			t.Errorf("test %d startOffset %d does not match want.startOffset %d\n", i, startOffset, overlapBytesTests[i].want.startOffset)
			t.Fail()
		}
		if endOffset != overlapBytesTests[i].want.endOffset {
			t.Errorf("test %d endOffset %d does not match want.endOffset %d\n", i, endOffset, overlapBytesTests[i].want.endOffset)
			t.Fail()
		}
		if len(overlapBytes) != len(overlapBytesTests[i].want.bytes) {
			t.Errorf("test %d overlapBytes len %d not equal to want.bytes len %d\n", i, len(overlapBytes), len(overlapBytesTests[i].want.bytes))
			t.Fail()
		}
		if !bytes.Equal(overlapBytes, overlapBytesTests[i].want.bytes) {
			t.Errorf("test %d overlapBytes %x not equal to want.bytes %x\n", i, overlapBytes, overlapBytesTests[i].want.bytes)
			t.Fail()
		}
	}
}

func TestGetOverlapRingsWithZeroRings(t *testing.T) {
	ip := layers.IPv4{
		SrcIP:    net.IP{1, 2, 3, 4},
		DstIP:    net.IP{2, 3, 4, 5},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		SYN:     true,
		SrcPort: 1,
		DstPort: 2,
	}
	tcp.SetNetworkLayerForChecksum(&ip)
	payload := gopacket.Payload([]byte{1, 2, 3, 4})
	p := types.PacketManifest{
		IP:      ip,
		TCP:     tcp,
		Payload: payload,
	}
	options := ConnectionOptions{
		MaxBufferedPagesTotal:         0,
		MaxBufferedPagesPerConnection: 0,
		MaxRingPackets:                40,
		PageCache:                     nil,
		LogDir:                        "fake-log-dir",
	}

	f := &DefaultConnFactory{}
	conn := f.Build(options).(*Connection)

	ipFlow, _ := gopacket.FlowFromEndpoints(layers.NewIPEndpoint(net.IPv4(1, 2, 3, 4)), layers.NewIPEndpoint(net.IPv4(2, 3, 4, 5)))
	tcpFlow, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(layers.TCPPort(1)), layers.NewTCPPortEndpoint(layers.TCPPort(2)))
	serverFlow := types.NewTcpIpFlowFromFlows(ipFlow, tcpFlow)
	clientFlow := serverFlow.Reverse()
	conn.serverFlow = serverFlow
	conn.clientFlow = clientFlow

	head, tail := getOverlapRings(&p, serverFlow, conn.ClientStreamRing)
	if head == nil || tail == nil {
		return
	} else {
		t.Fail()
	}
	return
}

func TestGetOverlapRings(t *testing.T) {
	overlapTests := []struct {
		in   reassemblyInput
		want []*types.Reassembly
	}{
		{
			reassemblyInput{7, []byte{1, 2}}, []*types.Reassembly{
				{
					Seq: 5,
				},
				{
					Seq: 5,
				},
			},
		},
		{
			reassemblyInput{7, []byte{6, 7}}, []*types.Reassembly{
				{
					Seq: 5,
				},
				{
					Seq: 5,
				},
			},
		},
		{
			reassemblyInput{5, []byte{1, 2, 3, 4, 5}}, []*types.Reassembly{
				{
					Seq: 5,
				},
				{
					Seq: 5,
				},
			},
		},
		{
			reassemblyInput{5, []byte{1, 2, 3, 4, 5, 6}}, []*types.Reassembly{
				{
					Seq: 5,
				},
				{
					Seq: 10,
				},
			},
		},
		{
			reassemblyInput{6, []byte{1, 2, 3, 4, 5}}, []*types.Reassembly{
				{
					Seq: 5,
				},
				{
					Seq: 10,
				},
			},
		},
		{
			reassemblyInput{7, []byte{1, 2, 3, 4, 5}}, []*types.Reassembly{
				{
					Seq: 5,
				},
				{
					Seq: 10,
				},
			},
		},
		{
			reassemblyInput{32, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}}, []*types.Reassembly{
				{
					Seq: 30,
				},
				{
					Seq: 35,
				},
			},
		},
		{
			reassemblyInput{0, []byte{1, 2, 3}}, []*types.Reassembly{
				nil,
				nil,
			},
		},
		{
			reassemblyInput{0, []byte{1, 2, 3, 4, 5, 6, 7, 8}}, []*types.Reassembly{
				{
					Seq: 5,
				},
				{
					Seq: 5,
				},
			},
		},
		{
			reassemblyInput{0, []byte{1, 2, 3, 4, 5, 6}}, []*types.Reassembly{
				{
					Seq: 5,
				},
				{
					Seq: 5,
				},
			},
		},
		{
			reassemblyInput{0, []byte{1, 2, 3}}, []*types.Reassembly{
				nil,
				nil,
			},
		},
		{
			reassemblyInput{0, []byte{1, 2, 3, 4, 5}}, []*types.Reassembly{
				nil,
				nil,
			},
		},
		{
			reassemblyInput{0, []byte{1, 2, 3, 4, 5, 6}}, []*types.Reassembly{
				{
					Seq: 5,
				},
				{
					Seq: 5,
				},
			},
		},
		{
			reassemblyInput{40, []byte{1}}, []*types.Reassembly{
				nil,
				nil,
			},
		},
		{
			reassemblyInput{42, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}}, []*types.Reassembly{
				nil,
				nil,
			},
		},
		{
			reassemblyInput{38, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}}, []*types.Reassembly{
				{
					Seq: 35,
				},
				{
					Seq: 35,
				},
			},
		},
	}

	ip := layers.IPv4{
		SrcIP:    net.IP{1, 2, 3, 4},
		DstIP:    net.IP{2, 3, 4, 5},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	options := ConnectionOptions{
		MaxBufferedPagesTotal:         0,
		MaxBufferedPagesPerConnection: 0,
		MaxRingPackets:                40,
		PageCache:                     nil,
		LogDir:                        "fake-log-dir",
	}

	f := &DefaultConnFactory{}
	conn := f.Build(options).(*Connection)

	for j := 5; j < 40; j += 5 {
		reassembly := types.Reassembly{
			Skip:  0,
			Seq:   types.Sequence(j),
			Bytes: []byte{1, 2, 3, 4, 5},
		}
		conn.ClientStreamRing.Reassembly = &reassembly
		conn.ClientStreamRing = conn.ClientStreamRing.Next()
	}

	for i := 0; i < len(overlapTests); i++ {
		log.Printf("test # %d", i)
		tcp := layers.TCP{
			Seq:     overlapTests[i].in.Seq,
			SYN:     false,
			SrcPort: 1,
			DstPort: 2,
		}
		p := types.PacketManifest{
			IP:      ip,
			TCP:     tcp,
			Payload: overlapTests[i].in.Payload,
		}

		ipFlow, _ := gopacket.FlowFromEndpoints(layers.NewIPEndpoint(net.IPv4(1, 2, 3, 4)), layers.NewIPEndpoint(net.IPv4(2, 3, 4, 5)))
		tcpFlow, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(layers.TCPPort(1)), layers.NewTCPPortEndpoint(layers.TCPPort(2)))
		serverFlow := types.NewTcpIpFlowFromFlows(ipFlow, tcpFlow)
		clientFlow := serverFlow.Reverse()
		conn.serverFlow = serverFlow
		conn.clientFlow = clientFlow

		head, tail := getOverlapRings(&p, serverFlow, conn.ClientStreamRing)

		log.Printf("head %v tail %v", head, tail)

		log.Printf("want %v", overlapTests[i].want[0])

		if overlapTests[i].want[0] == nil {
			log.Print("want nil results")

			if head != nil {
				t.Error("getOverlapRings did not return a nil ring segment head\n")
				t.Fail()
			}
			if tail != nil {
				t.Error("getOverlapRings did not return a nil ring segment tail\n")
				t.Fail()
			}
		} else {
			if overlapTests[i].want[0] != nil {
				if head == nil || tail == nil {
					t.Error("head or tail is nil\n")
					t.Fail()
				}
			}
			if overlapTests[i].want[0] != nil {
				if head.Reassembly.Seq.Difference(overlapTests[i].want[0].Seq) != 0 {
					t.Errorf("test %d: reassembly.Seq %d != want.Seq %d\n", i, head.Reassembly.Seq, overlapTests[i].want[0].Seq)
					t.Fail()
				}
			}
			if overlapTests[i].want[1] != nil {
				if tail.Reassembly.Seq.Difference(overlapTests[i].want[1].Seq) != 0 {
					t.Errorf("test num %d in.Seq %d != want.Seq %d\n", i, head.Reassembly.Seq, overlapTests[i].want[1].Seq)
					t.Fail()
				}
			}
		}
	}
	return
}
