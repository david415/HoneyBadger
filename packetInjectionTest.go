package main

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/examples/util"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"flag"
	"log"
	"net"
	"time"
)

var iface = flag.String("i", "wlan0", "Interface to get packets from")
var filter = flag.String("f", "tcp", "BPF filter for pcap")
var flushAfter = flag.String("flush_after", "2m", "")
var snaplen = flag.Int("s", 65536, "SnapLen for pcap packet capture")

func main() {
	defer util.Run()()

	var shouldSend bool = true

	var eth layers.Ethernet
	var dot1q layers.Dot1Q
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var ip6extensions layers.IPv6ExtensionSkipper
	var tcp layers.TCP
	var payload gopacket.Payload
	decoded := make([]gopacket.LayerType, 0, 4)

	flushDuration, err := time.ParseDuration(*flushAfter)
	if err != nil {
		log.Fatal("invalid flush duration: ", *flushAfter)
	}
	handle, err := pcap.OpenLive(*iface, int32(*snaplen), true, flushDuration/2)
	if err != nil {
		log.Fatal("error opening pcap handle: ", err)
	}
	if err := handle.SetBPFFilter(*filter); err != nil {
		log.Fatal("error setting BPF filter: ", err)
	}

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		&eth, &dot1q, &ip4, &ip6, &ip6extensions, &tcp, &payload)

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

		log.Printf("decoded the following layers: %v", decoded)
		log.Printf("packet of size %d\n", len(data))
		log.Printf("tcp seq %d\n", tcp.Seq)

		if shouldSend {
			// XXX create tcp/ip packet
			ipLayer := &layers.IPv4{
				SrcIP:    ip4.SrcIP,
				DstIP:    ip4.DstIP,
				Protocol: layers.IPProtocolTCP,
			}
			tcpLayer := &layers.TCP{
				SrcPort: tcp.SrcPort,
				DstPort: tcp.DstPort,
				Seq:     tcp.Seq,
				SYN:     tcp.SYN,
				Window:  tcp.Window,
			}
			tcpLayer.SetNetworkLayerForChecksum(ipLayer)
			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{
				ComputeChecksums: true,
				FixLengths:       true,
			}
			err = gopacket.SerializeLayers(buf, opts,
				ipLayer,
				tcpLayer,
				gopacket.Payload([]byte("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXxxx")))
			if err != nil {
				panic(err)
			}
			// XXX end of packet creation

			// XXX send packet
			dstIP := net.IPAddr{
				IP: ip4.DstIP,
			}
			// get an IPConn instance
			// replace 0.0.0.0 with ip4.SrcIP???
			ipConn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
			if err != nil {
				panic(err)
			}

			for {
				time.Sleep(time.Duration(10) * time.Second)

				_, err = ipConn.WriteTo(buf.Bytes(), &dstIP)
				if err != nil {
					panic(err)
				}
				log.Print("packet sent!\n")
			}
			// XXX end of send packet section
		}

	}

}
