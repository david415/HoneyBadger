/*
 *    inference.go - inference TCP injector
 *    Copyright (C) 2016  David Anthony Stainton
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
	"fmt"
	"net"
	"strings"

	//"github.com/david415/HoneyBadger/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("tcpInference")

type TCPInferenceSideChannel struct {
	ifaceName string
	snaplen   int32

	conn       net.Conn
	targetIP   net.IP
	targetPort uint16

	handle  *pcap.Handle
	parser  *gopacket.DecodingLayerParser
	eth     *layers.Ethernet
	dot1q   *layers.Dot1Q
	ip4     *layers.IPv4
	ip6     *layers.IPv6
	tcp     *layers.TCP
	payload *gopacket.Payload
}

func NewTCPInferenceSideChannel(ifaceName string, snaplen int32, targetIP net.IP, targetPort uint16) *TCPInferenceSideChannel {
	t := TCPInferenceSideChannel{
		ifaceName:  ifaceName,
		snaplen:    snaplen,
		targetIP:   targetIP,
		targetPort: targetPort,
		eth:        &layers.Ethernet{},
		ip4:        &layers.IPv4{},
		ip6:        &layers.IPv6{},
		tcp:        &layers.TCP{},
		payload:    &gopacket.Payload{},
	}
	return &t
}

func (t *TCPInferenceSideChannel) Start() error {
	var err error
	t.conn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", t.targetIP, t.targetPort))
	if err != nil {
		panic(err)
	}
	_, err = t.conn.Write([]byte("hello\n"))
	if err != nil {
		panic(err)
	}
	log.Warning("sent target a hello")

	// get the connection's TCP 4-tuple here
	remoteAddr := t.conn.RemoteAddr()
	localAddr := t.conn.LocalAddr()
	fields := strings.Split(remoteAddr.String(), ":")
	remoteIP := fields[0]
	remotePort := fields[1]
	fields = strings.Split(localAddr.String(), ":")
	localIP := fields[0]
	localPort := fields[1]
	log.Noticef("%s %s -> %s %s", localIP, localPort, remoteIP, remotePort)

	t.handle, err = pcap.OpenLive(t.ifaceName, t.snaplen, true, pcap.BlockForever)
	filter := fmt.Sprintf("ip host %s and tcp port %s", remoteIP, remotePort)
	log.Warning("attempting to us the following filter to sniff the connection:")
	log.Warning(filter)
	err = t.handle.SetBPFFilter(filter)
	if err != nil {
		log.Warning("failed to set pcap bpf filter")
		return err
	}
	t.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		t.eth, t.dot1q, t.ip4, t.ip6, t.tcp, t.payload)

	go t.readLoop()
	return nil
}

func (t *TCPInferenceSideChannel) Close() {
}

func (t *TCPInferenceSideChannel) readLoop() {
	decoded := make([]gopacket.LayerType, 0, 4)
	for {
		data, ci, err := t.handle.ReadPacketData()
		if err != nil {
			log.Warningf("error getting packet: %v %s", err, ci)
			continue
		}
		err = t.parser.DecodeLayers(data, &decoded)
		if err != nil {
			log.Warningf("error decoding packet: %v", err)
			continue
		}

		srcIP := net.IP{}
		dstIP := net.IP{}
		if t.ip4 == nil {
			srcIP = t.ip6.SrcIP
			dstIP = t.ip6.DstIP
		} else {
			srcIP = t.ip4.SrcIP
			dstIP = t.ip4.DstIP
		}

		log.Noticef("%s:%d -> %s:%d", srcIP, t.tcp.SrcPort, dstIP, t.tcp.DstPort)
	}
}
