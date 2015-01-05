/*
 *    observer.go
 *    Copyright (C) 2014  David Stainton
 *
 *    This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU Affero General Public License as
 *    published by the Free Software Foundation, either version 3 of the
 *    License, or (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU Affero General Public License for more details.
 *
 *    You should have received a copy of the GNU Affero General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
	packetManifestChannel chan *PacketManifest
}

func (o FlowObserver) Start() {
	log.Printf("FlowObserver.Start()\n")
	var p *PacketManifest
	o.packetManifestChannel = make(chan *PacketManifest, 1)
	go func() {
		defer o.Stop()
		var ok bool
		for {
			p, ok = <-o.packetManifestChannel
			if ok == false {
				panic("failed to read packetManifestChannel")
			}
			o.ProcessFlowPacket(p)
		}
	}()
}

func (o FlowObserver) Stop() {
	close(o.packetManifestChannel)
}

func (o FlowObserver) ProcessFlowPacket(p *PacketManifest) {
	fmt.Printf("ProcessFlowPacket: p.TCP.Seq %d\n", p.TCP.Seq)
}

func (m *MultiTCPFlowObserver) Start(iface string, snaplen int32, bpf string) error {
	var err error
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var tcp layers.TCP
	var payload gopacket.Payload
	decoded := make([]gopacket.LayerType, 0, 4)

	log.Printf("iface %s, snaplen %d, bpf %s\n", iface, snaplen, bpf)

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
			log.Printf("error reading packet: %v", err)
			continue
		}
		err = parser.DecodeLayers(data, &decoded)
		if err != nil {
			log.Printf("error decoding packet: %v", err)
			continue
		}
		packetManifest := PacketManifest{
			IP:      ip4,
			TCP:     tcp,
			Payload: payload,
		}
		m.dispatchToFlowObserver(&packetManifest)
	}
}

func (m *MultiTCPFlowObserver) Stop() {
	m.pcapHandle.Close()
	for _, flowObserver := range m.trackedFlows {
		flowObserver.Stop()
	}
}

func (m *MultiTCPFlowObserver) dispatchToFlowObserver(p *PacketManifest) {
	flow := TCPIPFlow{}
	flow.Set(p.IP, p.TCP)
	_, isTracked := m.trackedFlows[flow]
	if !isTracked {
		log.Print("flow not yet tracked\n")
		m.trackedFlows[flow] = FlowObserver{}
		m.trackedFlows[flow].Start()
	} else {
		log.Print("flow is yet tracked\n")
	}
	m.trackedFlows[flow].packetManifestChannel <- p
}