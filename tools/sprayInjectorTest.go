/*
 *    sprayInjectorTest.go - probabalistic TCP stream injection based on observed TCP sequences
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

package main

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/examples/util"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"flag"
	"fmt"
	"github.com/david415/HoneyBadger/inject"
	"log"
	"net"
)

var iface = flag.String("i", "lo", "Interface to get packets from")
var filter = flag.String("f", "tcp", "BPF filter for pcap")
var snaplen = flag.Int("s", 65536, "SnapLen for pcap packet capture")
var serviceIPstr = flag.String("d", "127.0.0.1", "target TCP flows from this IP address")
var servicePort = flag.Int("e", 2666, "target TCP flows from this port")

func main() {
	defer util.Run()()

	var eth layers.Ethernet
	var dot1q layers.Dot1Q
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var ip6extensions layers.IPv6ExtensionSkipper
	var tcp layers.TCP
	var payload gopacket.Payload
	decoded := make([]gopacket.LayerType, 0, 4)

	serviceIP := net.ParseIP(*serviceIPstr)
	if serviceIP == nil {
		panic(fmt.Sprintf("non-ip target: %q\n", serviceIPstr))
	}
	serviceIP = serviceIP.To4()
	if serviceIP == nil {
		panic(fmt.Sprintf("non-ipv4 target: %q\n", serviceIPstr))
	}

	streamInjector := inject.TCPStreamInjector{}
	err := streamInjector.Init("0.0.0.0")
	if err != nil {
		panic(err)
	}
	streamInjector.Payload = []byte("meowmeowmeow")

	handle, err := pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
	if err != nil {
		log.Fatal("error opening pcap handle: ", err)
	}
	if err := handle.SetBPFFilter(*filter); err != nil {
		log.Fatal("error setting BPF filter: ", err)
	}
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		&eth, &dot1q, &ip4, &ip6, &ip6extensions, &tcp, &payload)

	log.Print("collecting packets...\n")

	data, ci, err := handle.ZeroCopyReadPacketData()
	if err != nil {
		log.Printf("error getting packet: %v %s", err, ci)
		return
	}
	err = parser.DecodeLayers(data, &decoded)
	if err != nil {
		log.Printf("error decoding packet: %v", err)
		return
	}

	tcpFlowId := inject.TCPFlowID{
		SrcIP:   ip4.SrcIP,
		DstIP:   ip4.DstIP,
		SrcPort: tcp.SrcPort,
		DstPort: tcp.DstPort,
	}
	streamInjector.SetFlow(&tcpFlowId)
	err = streamInjector.SetIPLayer(ip4)
	if err != nil {
		panic(err)
	}
	streamInjector.SetTCPLayer(tcp)
	err = streamInjector.SpraySequenceRangePackets(tcp.Seq, 3)
	if err != nil {
		panic(err)
	}
	log.Print("packet spray sent!\n")
}
