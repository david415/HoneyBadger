package main

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/examples/util"
	"code.google.com/p/gopacket/layers"
	"log"
	"net"
)

func main() {
	defer util.Run()()

	// XXX create tcp/ip packet
	//	srcIP := net.ParseIP("192.168.0.20")
	dstIP := net.ParseIP("192.168.0.1")
	dstIPaddr := net.IPAddr{
		IP: dstIP,
	}
	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(666),
		DstPort: layers.TCPPort(22),
		SYN:     true,
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	err := gopacket.SerializeLayers(buf, opts, ipLayer, tcpLayer)
	if err != nil {
		panic(err)
	}
	// XXX end of packet creation

	// XXX send packet
	ipConn, err := net.ListenPacket("ip4:tcp", "192.168.0.20")
	if err != nil {
		panic(err)
	}
	_, err = ipConn.WriteTo(buf.Bytes(), &dstIPaddr)
	if err != nil {
		panic(err)
	}
	log.Print("packet sent!\n")
}
