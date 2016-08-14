/*
 *    injector.go - TCP stream injector API - "integration tests" for HoneyBadger
 *    Copyright (C) 2014, 2015  David Stainton
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package inference

import (
	"bytes"
	"fmt"
	"net"
	"time"

	"github.com/david415/HoneyBadger/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
)

type TCPStreamInjector struct {
	router       routing.Router
	patsyIP      net.IP
	targetIP     net.IP
	targetPort   uint16
	iface        *net.Interface
	handle       *pcap.Handle
	dst, gw, src net.IP
	opts         gopacket.SerializeOptions
	buf          gopacket.SerializeBuffer

	eth     layers.Ethernet
	dot1q   layers.Dot1Q
	ipv4    layers.IPv4
	ipv6    layers.IPv6
	tcp     layers.TCP
	Payload gopacket.Payload
}

func NewTCPStreamInjector(patsyIP, targetIP net.IP, targetPort uint16) *TCPStreamInjector {
	i := TCPStreamInjector{
		patsyIP:    patsyIP,
		targetIP:   targetIP,
		targetPort: targetPort,
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		buf: gopacket.NewSerializeBuffer(),
	}
	i.ipv4 = layers.IPv4{
		SrcIP:    patsyIP,
		DstIP:    targetIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	i.tcp = layers.TCP{
		SrcPort: layers.TCPPort(targetPort),
		DstPort: 34576,
		SYN:     true,
	}
	i.tcp.SetNetworkLayerForChecksum(&i.ipv4)

	return &i
}

func (i *TCPStreamInjector) SprayTest() error {
	if err := i.send(&i.eth, &i.ipv4, &i.tcp); err != nil {
		return err
	}
	return nil
}

func (i *TCPStreamInjector) Open(ifaceName string, snaplen int32) error {
	var err error = nil
	i.handle, err = pcap.OpenLive(ifaceName, snaplen, true, pcap.BlockForever)
	return err
}

// getHwAddr is a hacky but effective way to get the destination hardware
// address for our packets.  It does an ARP request for our gateway (if there is
// one) or destination IP (if no gateway is necessary), then waits for an ARP
// reply.  This is pretty slow right now, since it blocks on the ARP
// request/reply.
func (i *TCPStreamInjector) getHwAddr() (net.HardwareAddr, error) {
	start := time.Now()
	arpDst := i.dst
	if i.gw != nil {
		arpDst = i.gw
	}
	// Prepare the layers to send for an ARP request.
	eth := layers.Ethernet{
		SrcMAC:       i.iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(i.iface.HardwareAddr),
		SourceProtAddress: []byte(i.src),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(arpDst),
	}
	// Send a single ARP request packet (we never retry a send, since this
	// is just an example ;)
	if err := i.send(&eth, &arp); err != nil {
		return nil, err
	}
	// Wait 3 seconds for an ARP reply.
	for {
		if time.Since(start) > time.Second*3 {
			return nil, fmt.Errorf("timeout getting ARP reply")
		}
		data, _, err := i.handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			return nil, err
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			if bytes.Equal(arp.SourceProtAddress, arpDst) {
				return net.HardwareAddr(arp.SourceHwAddress), nil
			}
		}
	}
}

func (i *TCPStreamInjector) SetEthernetToAutoHWAddr() error {
	var iface *net.Interface
	var gw, src net.IP
	var err error

	i.router, err = routing.New()
	if err != nil {
		return err
	}

	// Figure out the route to the IP.
	iface, gw, src, err = i.router.Route(i.targetIP)
	if err != nil {
		return err
	}
	log.Noticef("scanning ip %v with interface %v, gateway %v, src %v", i.targetIP, iface.Name, gw, src)
	i.gw, i.src, i.iface = gw, src, iface

	hwAddr := net.HardwareAddr{}
	hwAddr, err = i.getHwAddr()
	if err != nil {
		return err
	}
	eth := layers.Ethernet{
		SrcMAC:       i.iface.HardwareAddr,
		DstMAC:       hwAddr,
		EthernetType: layers.EthernetTypeIPv4,
	}
	i.SetEthernetLayer(&eth)
	return nil
}

func (i *TCPStreamInjector) SetEthernetToHWAddr(source, target net.HardwareAddr) {
	eth := layers.Ethernet{
		SrcMAC:       source,
		DstMAC:       target,
		EthernetType: layers.EthernetTypeIPv4,
	}
	i.SetEthernetLayer(&eth)
}

func (i *TCPStreamInjector) SetEthernetLayer(eth *layers.Ethernet) {
	i.eth = *eth
}

func (i *TCPStreamInjector) SetIPToAddr(src, dst net.IP) {
}

func (i *TCPStreamInjector) SetIPv4Layer(iplayer layers.IPv4) {
	i.ipv4 = iplayer
}

func (i *TCPStreamInjector) SetIPv6Layer(iplayer layers.IPv6) {
	i.ipv6 = iplayer
}

func (i *TCPStreamInjector) SetTCPLayer(tcpLayer layers.TCP) {
	i.tcp = tcpLayer
}

func (i *TCPStreamInjector) SpraySequenceRangePackets(start uint32, count int) error {
	var err error

	currentSeq := types.Sequence(start)
	stopSeq := currentSeq.Add(count)

	for ; currentSeq.Difference(stopSeq) != 0; currentSeq = currentSeq.Add(1) {
		i.tcp.Seq = uint32(currentSeq)
		err = i.Write()
		if err != nil {
			return err
		}
	}
	return nil
}

// SprayFutureAndFillGapPackets is used to perform an ordered coalesce injection attack;
// that is we first inject packets with future sequence numbers and then we fill the gap.
// The gap being the range from state machine's "next Sequence" to the earliest Sequence we
// transmitted in our future sequence series of packets.
func (i *TCPStreamInjector) SprayFutureAndFillGapPackets(start uint32, gap_payload, attack_payload []byte, overlap_future_packet bool) error {
	var err error = nil

	// send future packet
	nextSeq := types.Sequence(start)
	i.tcp.Seq = uint32(nextSeq.Add(len(gap_payload)))
	i.Payload = attack_payload

	err = i.Write()
	if err != nil {
		return err
	}

	if overlap_future_packet == true {
		// overlapping future injection
		i.tcp.Seq = uint32(nextSeq.Add(len(gap_payload) + 7))
		i.Payload = attack_payload

		err = i.Write()
		if err != nil {
			return err
		}
	}

	// fill in gap
	i.tcp.Seq = start
	i.Payload = gap_payload
	err = i.Write()
	if err != nil {
		return err
	}
	return nil
}

// send sends the given layers as a single packet on the network.
func (i *TCPStreamInjector) send(l ...gopacket.SerializableLayer) error {
	if err := gopacket.SerializeLayers(i.buf, i.opts, l...); err != nil {
		return err
	}
	return i.handle.WritePacketData(i.buf.Bytes())
}

func (i *TCPStreamInjector) Write() error {
	log.Info("Write")
	var err error = nil

	i.tcp.SetNetworkLayerForChecksum(&i.ipv4)
	packetBuf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(packetBuf, i.opts, &i.eth, &i.ipv4, &i.tcp, i.Payload)
	if err != nil {
		log.Info("wtf. failed to encode ipv4 packet")
		return err
	}
	if err := i.handle.WritePacketData(packetBuf.Bytes()); err != nil {
		log.Infof("Failed to send packet: %s\n", err)
		return err
	}
	return err
}
