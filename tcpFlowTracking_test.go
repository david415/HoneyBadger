package HoneyBadger

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/tcpassembly"
	"fmt"
	"net"
	"testing"
)

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

type reassemblyInput struct {
	Seq     uint32
	Payload []byte
}

type OverlapTest struct {
	in   reassemblyInput
	want []Reassembly
}

func TestGetOverlapRings(t *testing.T) {
	overlapTests := []struct {
		in   reassemblyInput
		want []Reassembly
	}{
		{
			reassemblyInput{7, []byte{1, 2}}, []Reassembly{
				Reassembly{
					Seq: 5,
				},
				Reassembly{
					Seq: 5,
				},
			},
		},
		{
			reassemblyInput{7, []byte{1, 2, 3, 4, 5}}, []Reassembly{
				Reassembly{
					Seq: 5,
				},
				Reassembly{
					Seq: 10,
				},
			},
		},
		{
			reassemblyInput{0, []byte{1, 2, 3, 4, 5}}, []Reassembly{
				Reassembly{
					Seq: 0,
				},
				Reassembly{
					Seq: 0,
				},
			},
		},
		{
			reassemblyInput{4, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}}, []Reassembly{
				Reassembly{
					Seq: 0,
				},
				Reassembly{
					Seq: 10,
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
	for j := 0; j < 40; j += 5 {
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
		if head == nil || tail == nil {
			t.Fail()
		}
		reassembly, ok := head.Value.(Reassembly)
		if ok {
			if reassembly.Seq != overlapTests[i].want[0].Seq {
				t.Fail()
			}
		} else {
			t.Fail()
		}
		reassembly, ok = tail.Value.(Reassembly)
		if ok {
			if reassembly.Seq != overlapTests[i].want[1].Seq {
				t.Fail()
			}
		} else {
			t.Fail()
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
