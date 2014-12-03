package honeybadger

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/tcpassembly"
	"golang.org/x/net/ipv4"
	"net"
)

// used as keys into our dictionary of tracked flows
// this is perhaps not has versatile because the fields in
// TCPFlow and IPFlow are non-exportable
type TCPIPFlow struct {
	TCPFlow gopacket.Flow
	IPFlow  gopacket.Flow
}

// used by TCPStreamInjector below
type TCPFlowID struct {
	SrcIP   net.IP
	SrcPort layers.TCPPort
	DstIP   net.IP
	DstPort layers.TCPPort
}

func (f *TCPIPFlow) Set(ip layers.IPv4, tcp layers.TCP) {
	f.TCPFlow = tcp.TransportFlow()
	f.IPFlow = ip.NetworkFlow()
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
	Payload       gopacket.Payload
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

func (i *TCPStreamInjector) SetIPLayer(iplayer layers.IPv4) error {
	i.ip = iplayer
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

func (i *TCPStreamInjector) SetTCPLayer(tcpLayer layers.TCP) {
	i.tcp = tcpLayer
}

func (i *TCPStreamInjector) SpraySequenceRangePackets(start uint32, count int) error {
	var err error

	currentSeq := tcpassembly.Sequence(start)
	stopSeq := currentSeq.Add(count)

	for ; currentSeq.Difference(stopSeq) != 0; currentSeq = currentSeq.Add(1) {
		err = i.Write(uint32(currentSeq))
		if err != nil {
			return err
		}
	}
	return nil
}

func (i *TCPStreamInjector) Write(seq uint32) error {
	i.tcp.Seq = seq
	i.tcp.SetNetworkLayerForChecksum(&i.ip)
	i.tcpPayloadBuf = gopacket.NewSerializeBuffer()
	packetPayload := gopacket.Payload(i.Payload)
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
