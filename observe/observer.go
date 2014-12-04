package observe

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"fmt"
	"log"
)

// used as keys into our dictionary of tracked flows
// this is perhaps not has versatile because the fields in
// TCPFlow and IPFlow are non-exportable
type TCPIPFlow struct {
	TCPFlow gopacket.Flow
	IPFlow  gopacket.Flow
}

func (f *TCPIPFlow) Set(ip layers.IPv4, tcp layers.TCP) {
	f.TCPFlow = tcp.TransportFlow()
	f.IPFlow = ip.NetworkFlow()
}

// dispatch packets to their FlowObserver
// using a map from TCPIPFlow to FlowObserver
type MultiTCPFlowObserver struct {
	pcapHandle   *pcap.Handle
	trackedFlows map[TCPIPFlow]FlowObserver
}

type PacketManifest struct {
	IP      layers.IPv4
	TCP     layers.TCP
	Payload gopacket.Payload
}

type FlowObserver struct {
	packetManifestChannel chan PacketManifest
}

func (o FlowObserver) Start() {
	var p PacketManifest
	o.packetManifestChannel = make(chan PacketManifest, 1)
	defer o.Stop()
	go func() {
		for {
			p = <-o.packetManifestChannel
			o.ProcessFlowPacket(p)
		}
	}()
}

func (o FlowObserver) Stop() {
	close(o.packetManifestChannel)
}

func (o FlowObserver) ProcessFlowPacket(p PacketManifest) {
	fmt.Printf("payload size %d, tcp header size %d\n", len(p.Payload))
}

func (m *MultiTCPFlowObserver) Start(iface string, snaplen int32, bpf string) error {
	var err error
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var tcp layers.TCP
	var payload gopacket.Payload
	decoded := make([]gopacket.LayerType, 0, 4)

	m.pcapHandle, err = pcap.OpenLive(iface, int32(snaplen), true, pcap.BlockForever)
	if err != nil {
		return err
	}

	m.trackedFlows = make(map[TCPIPFlow]FlowObserver)
	defer m.Stop()

	if err = m.pcapHandle.SetBPFFilter(bpf); err != nil {
		return err
	}
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp, &payload)

	for {
		data, _, err := m.pcapHandle.ReadPacketData()
		if err != nil {
			log.Printf("error reading packet1: %v", err)
			continue
		}
		err = parser.DecodeLayers(data, &decoded)
		if err != nil {
			log.Printf("error decoding packet2: %v", err)
			continue
		}
		fmt.Printf("tcp.Seq %d\n", tcp.Seq)
		packetManifest := PacketManifest{
			IP:      ip4,
			TCP:     tcp,
			Payload: payload,
		}
		m.dispatchToFlowObserver(packetManifest)
	}
}

func (m *MultiTCPFlowObserver) Stop() {
	m.pcapHandle.Close()
	for _, flowObserver := range m.trackedFlows {
		flowObserver.Stop()
	}
}

func (m *MultiTCPFlowObserver) dispatchToFlowObserver(p PacketManifest) {
	flow := TCPIPFlow{}
	flow.Set(p.IP, p.TCP)
	_, isTracked := m.trackedFlows[flow]
	if !isTracked {
		m.trackedFlows[flow] = FlowObserver{}
		m.trackedFlows[flow].Start()
	}
	m.trackedFlows[flow].packetManifestChannel <- p
}
