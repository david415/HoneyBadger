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
	"strconv"
	"strings"

	"github.com/david415/HoneyBadger/types"
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
	decoded []gopacket.LayerType
	parser  *gopacket.DecodingLayerParser
	eth     *layers.Ethernet
	dot1q   *layers.Dot1Q
	ip4     *layers.IPv4
	ip6     *layers.IPv6
	tcp     *layers.TCP
	payload *gopacket.Payload

	seqChan    chan uint32
	currentSeq uint32
	sendFlow   types.TcpIpFlow
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
		seqChan:    make(chan uint32, 0),
		decoded:    make([]gopacket.LayerType, 0, 4),
	}
	t.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		t.eth, t.dot1q, t.ip4, t.ip6, t.tcp, t.payload)
	return &t
}

func (t *TCPInferenceSideChannel) getTCP4Tuple(conn net.Conn) (net.IP, int, net.IP, int) {
	remoteAddr := conn.RemoteAddr()
	localAddr := conn.LocalAddr()
	fields := strings.Split(remoteAddr.String(), ":")
	remoteIP := fields[0]
	remotePortStr := fields[1]
	fields = strings.Split(localAddr.String(), ":")
	localIP := fields[0]
	localPortStr := fields[1]
	localPort, err := strconv.Atoi(localPortStr)
	if err != nil {
		panic(err)
	}
	remotePort, err := strconv.Atoi(remotePortStr)
	if err != nil {
		panic(err)
	}
	return net.ParseIP(localIP), localPort, net.ParseIP(remoteIP), remotePort
}

func (t *TCPInferenceSideChannel) EnsureDialed() error {
	var err error
	log.Notice("before Dial")
	if t.conn == nil {
		addr := fmt.Sprintf("%s:%d", t.targetIP, t.targetPort)
		log.Noticef("about to dial addr %s", addr)
		t.conn, err = net.Dial("tcp", addr)
		if err != nil {
			return err
		}
	}
	log.Notice("after Dial")

	// target flow
	localIP, localPort, remoteIP, remotePort := t.getTCP4Tuple(t.conn)
	netLayer := layers.IPv4{
		SrcIP: localIP,
		DstIP: remoteIP,
	}
	tcpLayer := layers.TCP{
		SrcPort: layers.TCPPort(localPort),
		DstPort: layers.TCPPort(remotePort),
	}
	//netFlow := netLayer.NetworkFlow()
	//tcpFlow := tcpLayer.TransportFlow()
	//t.sendFlow = types.NewTcpIpFlowFromFlows(netFlow, tcpFlow)
	flow := types.NewTcpIpFlowFromLayers(netLayer, tcpLayer)
	t.sendFlow = *flow

	return nil
}

func (t *TCPInferenceSideChannel) EnsureOpenedPcap() error {
	var err error
	if t.conn == nil {
		panic("wtf, t.conn is nil")
	}
	localIP, localPort, remoteIP, remotePort := t.getTCP4Tuple(t.conn)
	filter := fmt.Sprintf("ip host %s and tcp port %d", remoteIP, remotePort)

	log.Noticef("connection 4-tuple %s %d -> %s %d", localIP, localPort, remoteIP, remotePort)
	log.Warning("attempting to us the following filter to sniff the connection:")
	log.Warning(filter)

	t.handle, err = pcap.OpenLive(t.ifaceName, t.snaplen, true, pcap.BlockForever)
	err = t.handle.SetBPFFilter(filter)
	if err != nil {
		log.Warning("failed to set pcap bpf filter")
		return err
	}
	return nil
}

func (t *TCPInferenceSideChannel) Start() error {
	err := t.GetCurrentSequence()
	return err
}

func (t *TCPInferenceSideChannel) GetCurrentSequence() error {
	var err error

	err = t.EnsureDialed()
	if err != nil {
		return err
	}
	log.Notice("AFTER DIALED")
	err = t.EnsureOpenedPcap()
	if err != nil {
		panic(err)
	}

	go t.sniffSequence()
	t.SendToConn()
	t.currentSeq = <-t.seqChan

	log.Noticef("TCP Sequence %d", t.currentSeq)
	return nil
}

func (t *TCPInferenceSideChannel) SendToConn() {

	_, err := t.conn.Write([]byte("hello\n"))
	if err != nil {
		log.Notice("SendToConn failed")
		panic(err)
	}
	log.Notice("SendToConn success.")
}

func (t *TCPInferenceSideChannel) Close() {
	t.handle.Close()
}

func (t *TCPInferenceSideChannel) sniffSequence() {
	for {
		data, ci, err := t.handle.ReadPacketData()
		if err != nil {
			log.Warningf("error getting packet: %v %s", err, ci)
		}

		err = t.parser.DecodeLayers(data, &t.decoded)
		if err != nil {
			log.Warningf("error decoding packet: %v", err)
		}

		// flow of received packet
		flow := &types.TcpIpFlow{}
		if t.ip4 == nil {
			// XXX ipv6 compatibility fix me
			//flow = types.NewTcpIpFlowFromLayers(*t.ip6, t.tcp)
			panic("ipv6 not yet supported")
		} else {
			flow = types.NewTcpIpFlowFromLayers(*t.ip4, *t.tcp)
		}

		// XXX
		if t.sendFlow.Equal(flow) {
			log.Warningf("matching flow! %s", flow)
			t.seqChan <- t.tcp.Seq
			return
		}
	}
}
