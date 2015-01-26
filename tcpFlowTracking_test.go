package HoneyBadger

import (
	"bytes"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/tcpassembly"
	"container/ring"
	//"fmt"
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

	// next test case
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

	// next test case
	p.TCP = layers.TCP{
		Seq:     1,
		SrcPort: 1,
		DstPort: 2,
	}
	p.Payload = []byte{1, 2, 3, 4, 5, 6}
	if !conn.isInjection(p, flow) {
		t.Error("isInjection failed\n")
		t.Fail()
	}

	// next test case
	p.TCP = layers.TCP{
		Seq:     1,
		SrcPort: 1,
		DstPort: 2,
	}
	p.Payload = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17}
	if !conn.isInjection(p, flow) {
		t.Error("isInjection failed\n")
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
		Payload: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
	}

	head, tail = conn.getOverlapRings(p, flow)
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

func TestGetHeadRingOffset(t *testing.T) {
	head := ring.New(3)
	head.Value = Reassembly{
		Seq:   3,
		Bytes: []byte{1, 2, 3, 4, 5, 6, 7},
	}
	offset := getHeadRingOffset(head, 5)
	if offset < 0 {
		t.Error("offset less than zero\n")
		t.Fail()
	}
	if offset != 2 {
		t.Error("offset incorrect\n")
		t.Fail()
	}
	offset = getHeadRingOffset(head, 3)
	if offset != 0 {
		t.Error("offset incorrect\n")
		t.Fail()
	}

	offset = getHeadRingOffset(head, 4)
	if offset != 1 {
		t.Error("offset incorrect\n")
		t.Fail()
	}
}

func TestGetTailRingOffset(t *testing.T) {
	tail := ring.New(3)
	tail.Value = Reassembly{
		Seq:   3,
		Bytes: []byte{1, 2, 3, 4, 5, 6, 7},
	}

	offset := getTailRingOffset(tail, 4)
	if offset != 5 {
		t.Errorf("want 5 got %d\n", offset)
		t.Fail()
	}

	offset = getTailRingOffset(tail, 5)
	if offset != 4 {
		t.Errorf("want 4 got %d\n", offset)
		t.Fail()
	}

	offset = getTailRingOffset(tail, 6)
	if offset != 3 {
		t.Errorf("want 3 got %d\n", offset)
		t.Fail()
	}
}

func TestGetStartOverlapSequenceAndOffset(t *testing.T) {
	var start tcpassembly.Sequence = 3
	head := ring.New(3)
	head.Value = Reassembly{
		Seq:   3,
		Bytes: []byte{1, 2, 3, 4, 5, 6, 7},
	}
	sequence, offset := getStartOverlapSequenceAndOffset(head, start)
	if offset != 0 {
		t.Error("offset != 0\n")
		t.Fail()
	}
	if sequence != 3 {
		t.Error("incorrect sequence")
		t.Fail()
	}

	start = 4
	sequence, offset = getStartOverlapSequenceAndOffset(head, start)
	if offset != 0 {
		t.Errorf("offset %d != 1\n", offset)
		t.Fail()
	}
	if sequence != 4 {
		t.Error("incorrect sequence")
		t.Fail()
	}

	start = 2
	sequence, offset = getStartOverlapSequenceAndOffset(head, start)
	if offset != 1 {
		t.Errorf("offset %d != 1\n", offset)
		t.Fail()
	}
	if sequence != 3 {
		t.Error("incorrect sequence")
		t.Fail()
	}

	start = 1
	sequence, offset = getStartOverlapSequenceAndOffset(head, start)
	if offset != 2 {
		t.Errorf("offset %d != 2\n", offset)
		t.Fail()
	}
	if sequence != 3 {
		t.Error("incorrect sequence")
		t.Fail()
	}
}

func TestGetEndOverlapSequenceAndOffset(t *testing.T) {
	var end tcpassembly.Sequence = 3
	tail := ring.New(3)
	tail.Value = Reassembly{
		Seq:   3,
		Bytes: []byte{1, 2, 3, 4, 5, 6, 7},
	}
	sequence, offset := getEndOverlapSequenceAndOffset(tail, end)
	if offset != 0 {
		t.Error("offset != 0\n")
		t.Fail()
	}
	if sequence != 3 {
		t.Error("incorrect sequence")
		t.Fail()
	}

	end = 9
	sequence, offset = getEndOverlapSequenceAndOffset(tail, end)
	if offset != 0 {
		t.Error("offset != 0\n")
		t.Fail()
	}
	if sequence != end {
		t.Error("incorrect sequence")
		t.Fail()
	}

	end = 10
	sequence, offset = getEndOverlapSequenceAndOffset(tail, end)
	if offset != 1 {
		t.Error("offset != 1\n")
		t.Fail()
	}
	if sequence != end-1 {
		t.Error("incorrect sequence")
		t.Fail()
	}

	end = 11
	sequence, offset = getEndOverlapSequenceAndOffset(tail, end)
	if offset != 2 {
		t.Error("offset != 2\n")
		t.Fail()
	}
	if sequence != end-2 {
		t.Error("incorrect sequence")
		t.Fail()
	}
}

func TestGetOverlapBytes(t *testing.T) {
	overlapBytesTests := []struct {
		in   reassemblyInput
		want TestOverlapBytesWant
	}{
		{
			reassemblyInput{3, []byte{2, 3, 4}}, TestOverlapBytesWant{
				bytes:       []byte{6},
				startOffset: 2,
				endOffset:   3,
			},
		},
		{
			reassemblyInput{4, []byte{2, 3, 4}}, TestOverlapBytesWant{
				bytes:       []byte{6, 7},
				startOffset: 1,
				endOffset:   3,
			},
		},
		{
			reassemblyInput{5, []byte{2, 3, 4}}, TestOverlapBytesWant{
				bytes:       []byte{6, 7, 8},
				startOffset: 0,
				endOffset:   3,
			},
		},
		{
			reassemblyInput{6, []byte{1, 2, 3}}, TestOverlapBytesWant{
				bytes:       []byte{7, 8, 9},
				startOffset: 0,
				endOffset:   3,
			},
		},
		{
			reassemblyInput{4, []byte{1, 2, 3, 4, 5, 6, 7}}, TestOverlapBytesWant{
				bytes:       []byte{6, 7, 8, 9, 10, 11},
				startOffset: 1,
				endOffset:   7,
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
			reassemblyInput{5, []byte{1, 2, 3, 4, 5}}, []*Reassembly{
				&Reassembly{
					Seq: 5,
				},
				&Reassembly{
					Seq: 5,
				},
			},
		},
		{
			reassemblyInput{5, []byte{1, 2, 3, 4, 5, 6}}, []*Reassembly{
				&Reassembly{
					Seq: 5,
				},
				&Reassembly{
					Seq: 10,
				},
			},
		},
		{
			reassemblyInput{6, []byte{1, 2, 3, 4, 5}}, []*Reassembly{
				&Reassembly{
					Seq: 5,
				},
				&Reassembly{
					Seq: 10,
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
			reassemblyInput{0, []byte{1, 2, 3}}, []*Reassembly{
				nil,
				nil,
			},
		},
		{
			reassemblyInput{0, []byte{1, 2, 3, 4, 5}}, []*Reassembly{
				nil,
				nil,
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
			reassemblyInput{40, []byte{1}}, []*Reassembly{
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
		{
			reassemblyInput{38, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}}, []*Reassembly{
				&Reassembly{
					Seq: 35,
				},
				&Reassembly{
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

func TestStateDataTransfer(t *testing.T) {
	conn := NewConnection()
	conn.state = TCP_DATA_TRANSFER
	clientRingCount := 0
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
		Payload: []byte{1, 2, 3, 4, 5, 6, 7},
	}
	flow := NewTcpIpFlowFromLayers(ip, tcp)
	conn.serverFlow = flow
	conn.clientFlow = flow.Reverse()
	conn.clientNextSeq = 9666
	conn.serverNextSeq = 3

	conn.receivePacket(p, flow)
	if conn.state != TCP_DATA_TRANSFER {
		t.Error("invalid state transition\n")
		t.Fail()
	}
	conn.ClientStreamRing.Do(func(x interface{}) {
		_, ok := x.(Reassembly)
		if ok {
			clientRingCount += 1
		}
	})
	if clientRingCount != 1 {
		t.Errorf("clientRingCount %d not correct", clientRingCount)
		t.Fail()
	}

	// next set of tests
	tcp = layers.TCP{
		Seq:     10,
		SYN:     false,
		SrcPort: 1,
		DstPort: 2,
	}
	p = PacketManifest{
		IP:      ip,
		TCP:     tcp,
		Payload: []byte{1, 2, 3, 4, 5, 6, 7},
	}
	conn.receivePacket(p, flow)
	if conn.state != TCP_DATA_TRANSFER {
		t.Error("invalid state transition\n")
		t.Fail()
	}
	clientRingCount = 0
	conn.ClientStreamRing.Do(func(x interface{}) {
		_, ok := x.(Reassembly)
		if ok {
			clientRingCount += 1
		}
	})
	if clientRingCount != 2 {
		t.Errorf("clientRingCount %d not correct", clientRingCount)
		t.Fail()
	}

	// next test
	tcp = layers.TCP{
		Seq:     5,
		SYN:     false,
		SrcPort: 1,
		DstPort: 2,
	}
	p = PacketManifest{
		IP:      ip,
		TCP:     tcp,
		Payload: []byte{1, 2, 3, 4, 5, 6, 7},
	}
	conn.receivePacket(p, flow)
	if conn.state != TCP_DATA_TRANSFER {
		t.Error("invalid state transition\n")
		t.Fail()
	}
	clientRingCount = 0
	conn.ClientStreamRing.Do(func(x interface{}) {
		_, ok := x.(Reassembly)
		if ok {
			clientRingCount += 1
		}
	})
	if clientRingCount != 2 {
		t.Errorf("clientRingCount %d not correct", clientRingCount)
		t.Fail()
	}

}

func TestTCPConnect(t *testing.T) {
	conn := NewConnection()
	ip := layers.IPv4{
		SrcIP:    net.IP{1, 2, 3, 4},
		DstIP:    net.IP{2, 3, 4, 5},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		Seq:     3,
		SYN:     true,
		ACK:     false,
		SrcPort: 1,
		DstPort: 2,
	}
	p := PacketManifest{
		IP:      ip,
		TCP:     tcp,
		Payload: []byte{},
	}
	flow := NewTcpIpFlowFromLayers(ip, tcp)
	conn.clientFlow = flow
	conn.serverFlow = flow.Reverse()
	conn.receivePacket(p, flow)
	if conn.state != TCP_CONNECTION_REQUEST {
		t.Error("invalid state transition\n")
		t.Fail()
	}

	// next state transition test
	ip = layers.IPv4{
		SrcIP:    net.IP{2, 3, 4, 5},
		DstIP:    net.IP{1, 2, 3, 4},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp = layers.TCP{
		Seq:     9,
		SYN:     true,
		ACK:     true,
		Ack:     4,
		SrcPort: 2,
		DstPort: 1,
	}
	p = PacketManifest{
		IP:      ip,
		TCP:     tcp,
		Payload: []byte{},
	}
	flow = NewTcpIpFlowFromLayers(ip, tcp)
	conn.receivePacket(p, flow)
	if conn.state != TCP_CONNECTION_ESTABLISHED {
		t.Error("invalid state transition\n")
		t.Fail()
	}

	// next state transition test
	ip = layers.IPv4{
		SrcIP:    net.IP{1, 2, 3, 4},
		DstIP:    net.IP{2, 3, 4, 5},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp = layers.TCP{
		Seq:     4,
		SYN:     false,
		ACK:     true,
		Ack:     10,
		SrcPort: 1,
		DstPort: 2,
	}
	p = PacketManifest{
		IP:      ip,
		TCP:     tcp,
		Payload: []byte{},
	}
	flow = NewTcpIpFlowFromLayers(ip, tcp)
	conn.receivePacket(p, flow)
	if conn.state != TCP_DATA_TRANSFER {
		t.Error("invalid state transition\n")
		t.Fail()
	}

}

func TestClientThreeWayClose(t *testing.T) {
	HelperTestThreeWayClose(true, t)
}

func TestServerThreeWayClose(t *testing.T) {
	HelperTestThreeWayClose(false, t)
}

func HelperTestThreeWayClose(isClient bool, t *testing.T) {
	var closerState, remoteState *uint8

	conn := NewConnection()
	conn.state = TCP_DATA_TRANSFER
	conn.serverNextSeq = 4666
	conn.clientNextSeq = 9666

	if isClient {
		closerState = &conn.clientState
		remoteState = &conn.serverState
	} else {
		closerState = &conn.serverState
		remoteState = &conn.clientState
	}

	ip := layers.IPv4{
		SrcIP:    net.IP{1, 2, 3, 4},
		DstIP:    net.IP{2, 3, 4, 5},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		Seq:     9666,
		FIN:     true,
		SYN:     false,
		ACK:     false,
		SrcPort: 1,
		DstPort: 2,
	}
	p := PacketManifest{
		IP:      ip,
		TCP:     tcp,
		Payload: []byte{},
	}
	flow := NewTcpIpFlowFromLayers(ip, tcp)

	conn.clientFlow = flow
	conn.serverFlow = flow.Reverse()

	conn.receivePacket(p, flow)
	if conn.state != TCP_CONNECTION_CLOSING {
		t.Error("connection state must transition to TCP_CONNECTION_CLOSING\n")
		t.Fail()
	}
	if *closerState != TCP_FIN_WAIT1 {
		t.Error("closer state must be in TCP_FINE_WAIT1\n")
		t.Fail()
	}
	if *remoteState != TCP_CLOSE_WAIT {
		t.Error("remote state must be in TCP_CLOSE_WAIT\n")
		t.Fail()
	}

	// next state transition
	ip = layers.IPv4{
		SrcIP:    net.IP{2, 3, 4, 5},
		DstIP:    net.IP{1, 2, 3, 4},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp = layers.TCP{
		Seq:     4666,
		SYN:     false,
		FIN:     true,
		ACK:     true,
		Ack:     9667,
		SrcPort: 2,
		DstPort: 1,
	}
	p = PacketManifest{
		IP:      ip,
		TCP:     tcp,
		Payload: []byte{},
	}
	flow = NewTcpIpFlowFromLayers(ip, tcp)

	conn.receivePacket(p, flow)
	if conn.state != TCP_CONNECTION_CLOSING {
		t.Error("connection state must transition to TCP_CONNECTION_CLOSING\n")
		t.Fail()
	}

	// next state transition
	ip = layers.IPv4{
		SrcIP:    net.IP{1, 2, 3, 4},
		DstIP:    net.IP{2, 3, 4, 5},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp = layers.TCP{
		Seq:     9667,
		SYN:     false,
		FIN:     false,
		ACK:     true,
		Ack:     4667,
		SrcPort: 1,
		DstPort: 2,
	}
	p = PacketManifest{
		IP:      ip,
		TCP:     tcp,
		Payload: []byte{},
	}
	flow = NewTcpIpFlowFromLayers(ip, tcp)

	conn.receivePacket(p, flow)
	if conn.state != TCP_CLOSED {
		t.Error("failed to close")
	}
}

func BenchmarkSingleOneWayDataTransfer(b *testing.B) {
	conn := NewConnection()
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
	conn := NewConnection()
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
	conn := NewConnection()
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
	conn := NewConnection()
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
