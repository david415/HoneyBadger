package main

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/examples/util"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"flag"
	"golang.org/x/net/ipv4"
	"log"
	"net"
	"time"
)

var iface = flag.String("i", "wlan0", "Interface to get packets from")
var filter = flag.String("f", "tcp", "BPF filter for pcap")
var flushAfter = flag.String("flush_after", "2m", "")
var snaplen = flag.Int("s", 65536, "SnapLen for pcap packet capture")

type TCPFlowID struct {
	SrcIP   net.IP
	SrcPort layers.TCPPort
	DstIP   net.IP
	DstPort layers.TCPPort
}

type TCPStreamInjector struct {
	flowId        *TCPFlowID
	packetConn    net.PacketConn
	rawConn       *ipv4.RawConn
	ipHeader      *ipv4.Header
	ip            layers.IPv4
	tcp           layers.TCP
	ipBuf         gopacket.SerializeBuffer
	tcpPayloadBuf gopacket.SerializeBuffer
}

func (i *TCPStreamInjector) Init(netInterface string) error {
	var err error
	i.packetConn, err = net.ListenPacket("ip4:tcp", netInterface)
	if err != nil {
		return err
	}
	i.rawConn, err = ipv4.NewRawConn(i.packetConn)
	return err
}

func (i *TCPStreamInjector) SetFlow(flowId *TCPFlowID) {
	i.flowId = flowId
}

func (i *TCPStreamInjector) PrepareIPLayer() error {
	i.ip = layers.IPv4{
		SrcIP:    i.flowId.SrcIP,
		DstIP:    i.flowId.DstIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	i.ipBuf = gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := i.ip.SerializeTo(i.ipBuf, opts)
	if err != nil {
		return err
	}
	i.ipHeader, err = ipv4.ParseHeader(i.ipBuf.Bytes())
	if err != nil {
		return err
	}
	return nil
}

func (i *TCPStreamInjector) Write(payload []byte) error {
	i.tcp = layers.TCP{
		SrcPort: i.flowId.SrcPort,
		DstPort: i.flowId.DstPort,
		Window:  1505,
		Urgent:  0,
		Seq:     11050,
		Ack:     0,
		ACK:     false,
		SYN:     false,
		FIN:     false,
		RST:     false,
		URG:     false,
		ECE:     false,
		CWR:     false,
		NS:      false,
		PSH:     false,
	}
	i.tcp.SetNetworkLayerForChecksum(&i.ip)
	i.tcpPayloadBuf = gopacket.NewSerializeBuffer()
	packetPayload := gopacket.Payload(payload)
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(i.tcpPayloadBuf, opts, &i.tcp, packetPayload)
	if err != nil {
		return err
	}
	err = i.rawConn.WriteTo(i.ipHeader, i.tcpPayloadBuf.Bytes(), nil)
	return err
}

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

			tcpFlowId := TCPFlowID{
				SrcIP:   ip4.SrcIP,
				DstIP:   ip4.DstIP,
				SrcPort: tcp.SrcPort,
				DstPort: tcp.DstPort,
			}

			// reuse ip head
			streamInjector := TCPStreamInjector{}
			err = streamInjector.Init("0.0.0.0")
			if err != nil {
				panic(err)
			}
			streamInjector.SetFlow(&tcpFlowId)
			err = streamInjector.PrepareIPLayer()
			if err != nil {
				panic(err)
			}
			err = streamInjector.Write([]byte("meowmeowmeow"))
			if err != nil {
				panic(err)
			}

			log.Print("packet sent!\n")
			// XXX end of send packet section
		}

	}

}
