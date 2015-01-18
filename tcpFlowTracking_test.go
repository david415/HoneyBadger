package HoneyBadger

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"net"
	"testing"
)

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
