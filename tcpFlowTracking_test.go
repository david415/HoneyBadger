package HoneyBadger

import (
	"bytes"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/tcpassembly"
	"container/ring"
	"net"
	"testing"
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

func TestInjectionDetector(t *testing.T) {
	conn := NewConnection()
	conn.ClientStreamRing.Value = Reassembly{
		Seq:   tcpassembly.Sequence(5),
		Bytes: []byte{1, 2, 3, 4, 5},
	}
	conn.ClientStreamRing = conn.ClientStreamRing.Next()

	p := PacketManifest{
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
	flow := NewTcpIpFlowFromLayers(p.IP, p.TCP)

	if !conn.isInjection(p, flow) {
		t.Error("isInjection failed: false positive\n")
		t.Fail()
	}

	p.TCP = layers.TCP{
		Seq:     7,
		SrcPort: 1,
		DstPort: 2,
	}
	p.Payload = []byte{3, 4, 5}

	if conn.isInjection(p, flow) {
		t.Error("isInjection failed: false negative\n")
		t.Fail()
	}
}

func TestGetRingSlice(t *testing.T) {
	conn := NewConnection()
	for j := 5; j < 40; j += 5 {
		conn.ClientStreamRing.Value = Reassembly{
			Seq:   tcpassembly.Sequence(j),
			Bytes: []byte{1, 2, 3, 4, 5},
		}
		conn.ClientStreamRing = conn.ClientStreamRing.Next()
	}
	var startSeq uint32 = 5
	p := PacketManifest{
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
	flow := NewTcpIpFlowFromLayers(p.IP, p.TCP)
	head, tail := conn.getOverlapRings(p, flow)

	ringSlice := getRingSlice(head, tail, 0, 1)
	if !bytes.Equal(ringSlice, []byte{1, 2, 3, 4, 5, 1}) {
		t.Error("1\n")
		t.Fail()
	}

	ringSlice = getRingSlice(head, tail, 0, 3)
	if !bytes.Equal(ringSlice, []byte{1, 2, 3, 4, 5, 1, 2, 3}) {
		t.Error("1\n")
		t.Fail()
	}

	ringSlice = getRingSlice(head, tail, 0, 0)
	if !bytes.Equal(ringSlice, []byte{1, 2, 3, 4, 5}) {
		t.Error("1\n")
		t.Fail()
	}

	ringSlice = getRingSlice(head, tail, 1, 0)
	if !bytes.Equal(ringSlice, []byte{2, 3, 4, 5}) {
		t.Error("1\n")
		t.Fail()
	}

	ringSlice = getRingSlice(head, tail, 2, 0)
	if !bytes.Equal(ringSlice, []byte{3, 4, 5}) {
		t.Error("1\n")
		t.Fail()
	}

	startSeq = 0
	p = PacketManifest{
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
	head, tail = conn.getOverlapRings(p, flow)
	ringSlice = getRingSlice(head, tail, 1, 3)
	if !bytes.Equal(ringSlice, []byte{2, 3}) {
		t.Errorf("ringSlice is %x\n", ringSlice)
		t.Fail()
	}

	ringSlice = getRingSlice(head, tail, 2, 4)
	if !bytes.Equal(ringSlice, []byte{3, 4}) {
		t.Errorf("ringSlice is %x\n", ringSlice) //XXX
		t.Fail()
	}
}

func TestGetEndSequence(t *testing.T) {
	var tail *ring.Ring = ring.New(10)
	var end tcpassembly.Sequence

	end = 9
	tail.Value = Reassembly{
		Seq:   5,
		Bytes: []byte{1, 2, 3, 4, 5},
	}
	endSeq := getEndSequence(tail, end)
	if endSeq.Difference(end) != 0 {
		t.Errorf("endSeq %d != end %d\n", endSeq, end)
		t.Fail()
	}

	end = 9
	tail.Value = Reassembly{
		Seq:   5,
		Bytes: []byte{1, 2, 3, 4, 5},
	}
	endSeq = getEndSequence(tail, end.Add(1))
	if endSeq.Difference(end) != 0 {
		t.Errorf("endSeq %d != end %d\n", endSeq, end)
		t.Fail()
	}
}

func TestGetStartSequence(t *testing.T) {
	var start tcpassembly.Sequence = 4
	var head *ring.Ring = ring.New(10)
	head.Value = Reassembly{
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
		{
			reassemblyInput{5, []byte{2, 3, 4}}, TestOverlapBytesWant{
				bytes:       []byte{6, 7, 8},
				startOffset: 0,
				endOffset:   0,
			},
		},
		{
			reassemblyInput{2, []byte{1, 2, 3, 4, 5, 6, 7}}, TestOverlapBytesWant{
				bytes:       []byte{3, 4, 5, 1, 2, 3, 4},
				startOffset: 0,
				endOffset:   0,
			},
		},
		{
			reassemblyInput{3, []byte{1, 2, 3, 4, 5, 6, 7}}, TestOverlapBytesWant{
				bytes:       []byte{4, 5, 1, 2, 3, 4, 5},
				startOffset: 0,
				endOffset:   0,
			},
		},
		{
			reassemblyInput{34, []byte{1, 2, 3, 4, 5, 6, 7}}, TestOverlapBytesWant{
				bytes:       []byte{5, 1, 2, 3, 4, 5},
				startOffset: 0,
				endOffset:   1,
			},
		},
	}
	conn := NewConnection()
	for j := 5; j < 40; j += 5 {
		conn.ClientStreamRing.Value = Reassembly{
			Seq:   tcpassembly.Sequence(j),
			Bytes: []byte{byte(j + 1), byte(j + 2), byte(j + 3), byte(j + 4), byte(j + 5)},
		}
		conn.ClientStreamRing = conn.ClientStreamRing.Next()
	}
	for i := 0; i < len(overlapBytesTests); i++ {
		var startSeq uint32 = overlapBytesTests[i].in.Seq
		start := tcpassembly.Sequence(startSeq)
		end := start.Add(len(overlapBytesTests[i].in.Payload) - 1)
		p := PacketManifest{
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
		flow := NewTcpIpFlowFromLayers(p.IP, p.TCP)
		head, tail := conn.getOverlapRings(p, flow)
		if head == nil || tail == nil {
			t.Errorf("%d getOverlapRings returned a nil\n", i)
			t.Fail()
			continue
		}

		overlapBytes, startOffset, endOffset := conn.getOverlapBytes(head, tail, start, end)
		if startOffset != overlapBytesTests[i].want.startOffset {
			t.Errorf("startOffset %d does not match want.startOffset %d\n", startOffset, overlapBytesTests[i].want.startOffset)
			t.Fail()
		}
		if endOffset != overlapBytesTests[i].want.endOffset {
			t.Errorf("%d endOffset %d does not match want.endOffset %d\n", i, endOffset, overlapBytesTests[i].want.endOffset)
			t.Fail()
		}
		if len(overlapBytes) != len(overlapBytesTests[i].want.bytes) {
			t.Errorf("overlapBytes len %d not equal to want.bytes len %d\n", len(overlapBytes), len(overlapBytesTests[i].want.bytes))
			t.Fail()
		}
		if !bytes.Equal(overlapBytes, overlapBytesTests[i].want.bytes) {
			t.Errorf("overlapBytes %x not equal to want.bytes %x\n", overlapBytes, overlapBytesTests[i].want.bytes)
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
	flow := NewTcpIpFlowFromLayers(ip, tcp)
	p := PacketManifest{
		IP:      ip,
		TCP:     tcp,
		Payload: payload,
	}
	conn := NewConnection()
	head, tail := conn.getOverlapRings(p, flow)
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
		want []*Reassembly
	}{
		{
			reassemblyInput{7, []byte{1, 2}}, []*Reassembly{
				&Reassembly{
					Seq: 5,
				},
				&Reassembly{
					Seq: 5,
				},
			},
		},
		{
			reassemblyInput{7, []byte{1, 2, 3, 4, 5}}, []*Reassembly{
				&Reassembly{
					Seq: 5,
				},
				&Reassembly{
					Seq: 10,
				},
			},
		},
		{
			reassemblyInput{32, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}}, []*Reassembly{
				&Reassembly{
					Seq: 30,
				},
				&Reassembly{
					Seq: 35,
				},
			},
		},
		{
			reassemblyInput{0, []byte{1, 2, 3}}, []*Reassembly{
				nil,
				nil,
			},
		},
		{
			reassemblyInput{0, []byte{1, 2, 3, 4, 5, 6, 7, 8}}, []*Reassembly{
				&Reassembly{
					Seq: 5,
				},
				&Reassembly{
					Seq: 5,
				},
			},
		},
		{
			reassemblyInput{0, []byte{1, 2, 3, 4, 5, 6}}, []*Reassembly{
				&Reassembly{
					Seq: 5,
				},
				&Reassembly{
					Seq: 5,
				},
			},
		},
		{
			reassemblyInput{0, []byte{1, 2, 3, 4, 5}}, []*Reassembly{
				nil,
				nil,
			},
		},
		{
			reassemblyInput{42, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}}, []*Reassembly{
				nil,
				nil,
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

	conn := NewConnection()
	for j := 5; j < 40; j += 5 {
		conn.ClientStreamRing.Value = Reassembly{
			Seq:   tcpassembly.Sequence(j),
			Bytes: []byte{1, 2, 3, 4, 5},
		}
		conn.ClientStreamRing = conn.ClientStreamRing.Next()
	}

	for i := 0; i < len(overlapTests); i++ {
		tcp := layers.TCP{
			Seq:     overlapTests[i].in.Seq,
			SYN:     false,
			SrcPort: 1,
			DstPort: 2,
		}
		flow := NewTcpIpFlowFromLayers(ip, tcp)
		p := PacketManifest{
			IP:      ip,
			TCP:     tcp,
			Payload: overlapTests[i].in.Payload,
		}
		head, tail := conn.getOverlapRings(p, flow)

		if overlapTests[i].want[0] == nil {
			if head != nil {
				t.Error("getOverlapRings did not return a nil ring segment head\n")
				t.Fail()
			}
			if tail != nil {
				t.Error("getOverlapRings did not return a nil ring segment tail\n")
				t.Fail()
			}
			continue
		}
		if head == nil || tail == nil {
			t.Error("head or tail is nil\n")
			t.Fail()
		}
		reassembly, ok := head.Value.(Reassembly)
		if overlapTests[i].want[0] != nil {
			if ok {
				if reassembly.Seq.Difference(overlapTests[i].want[0].Seq) != 0 {
					t.Errorf("in.Seq %d != want.Seq %d\n", reassembly.Seq, overlapTests[i].want[0].Seq)
					t.Fail()
				}
			} else {
				t.Error("head.Value is not a Reassembly\n")
				t.Fail()
			}
		}
		reassembly, ok = tail.Value.(Reassembly)
		if overlapTests[i].want[1] != nil {
			if ok {
				if reassembly.Seq.Difference(overlapTests[i].want[1].Seq) != 0 {
					t.Errorf("test num %d in.Seq %d != want.Seq %d\n", i, reassembly.Seq, overlapTests[i].want[1].Seq)
					t.Fail()
				}
			} else {
				t.Error("tail.Value is not a Reassembly\n")
				t.Fail()
			}
		}
	}
	return
}

func TestSequenceFromPacket(t *testing.T) {
	var testSeq uint32 = 12345
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
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
	gopacket.SerializeLayers(buf, opts, &ip, &tcp)
	packetData := buf.Bytes()
	seq, err := SequenceFromPacket(packetData)
	if err == nil && seq == testSeq {
		return
	} else {
		t.Fail()
		return
	}
}
