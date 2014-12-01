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

	var srcIP, dstIP net.IP
	var srcIPstr string = "127.0.0.1"
	var dstIPstr string = "127.0.0.1"

	// source ip
	srcIP = net.ParseIP(srcIPstr)
	if srcIP == nil {
		log.Printf("non-ip target: %q\n", srcIPstr)
	}
	srcIP = srcIP.To4()
	if srcIP == nil {
		log.Printf("non-ipv4 target: %q\n", srcIPstr)
	}

	// destination ip
	dstIP = net.ParseIP(dstIPstr)
	if dstIP == nil {
		log.Printf("non-ip target: %q\n", dstIPstr)
	}
	dstIP = dstIP.To4()
	if dstIP == nil {
		log.Printf("non-ipv4 target: %q\n", dstIPstr)
	}

	// build tcp/ip packet
	ip := layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	srcport := layers.TCPPort(645)
	dstport := layers.TCPPort(22)
	tcp := layers.TCP{
		SrcPort: srcport,
		DstPort: dstport,

		Seq:    1105024978,
		Ack:    0,
		ACK:    false,
		SYN:    true,
		FIN:    false,
		RST:    false,
		URG:    false,
		ECE:    false,
		CWR:    false,
		NS:     false,
		PSH:    false,
		Window: 14600,
	}

	payload := gopacket.Payload([]byte("meowmeowmeowXXXhoho"))
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		//		FixLengths:       true,
		ComputeChecksums: true,
	}
	tcp.SetNetworkLayerForChecksum(&ip)
	err := gopacket.SerializeLayers(buf, opts,
		&ip,
		&tcp,
		payload)
	if err != nil {
		panic(err)
	}
	packetData := buf.Bytes()
	// XXX end of packet creation

	// XXX send packet
	ipConn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		panic(err)
	}

	dstIPaddr := net.IPAddr{
		IP: dstIP,
	}

	_, err = ipConn.WriteTo(packetData, &dstIPaddr)
	if err != nil {
		panic(err)
	}
	log.Print("packet sent!\n")
}
