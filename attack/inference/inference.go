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

package inference

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

	opts gopacket.SerializeOptions
	buf  gopacket.SerializeBuffer

	handle  *pcap.Handle
	decoded []gopacket.LayerType
	parser  *gopacket.DecodingLayerParser
	eth     *layers.Ethernet
	dot1q   *layers.Dot1Q
	ip4     *layers.IPv4
	ip6     *layers.IPv6
	tcp     *layers.TCP
	payload *gopacket.Payload

	packetChan    chan types.PacketManifest
	currentPacket types.PacketManifest
	sendFlow      types.TcpIpFlow
	probeFlow     types.TcpIpFlow
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
		seqChan:    make(chan types.PacketManifest, 0),
		decoded:    make([]gopacket.LayerType, 0, 4),
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		buf: gopacket.NewSerializeBuffer(),
	}
	t.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		t.eth, t.dot1q, t.ip4, t.ip6, t.tcp, t.payload)
	return &t
}

// getTCP4Tuple returns a TCP/IP 4-tuple given a net.Conn
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
	if net.ParseIP(localIP).To4() == nil {
		return net.ParseIP(localIP).To16(), localPort, net.ParseIP(remoteIP).To16(), remotePort
	}
	return net.ParseIP(localIP).To4(), localPort, net.ParseIP(remoteIP).To4(), remotePort
}

// getFlowFromConn returns a flow and a nil error given a net.Conn otherwise returns an error
func (t *TCPInferenceSideChannel) getFlowFromConn(conn net.Conn) (types.TcpIpFlow, error) {
	var flow types.TcpIpFlow
	localIP, localPort, remoteIP, remotePort := t.getTCP4Tuple(conn)
	srcIPEndpoint := layers.NewIPEndpoint(localIP)
	dstIPEndpoint := layers.NewIPEndpoint(remoteIP)
	srcTCPEndpoint := layers.NewTCPPortEndpoint(layers.TCPPort(localPort))
	dstTCPEndpoint := layers.NewTCPPortEndpoint(layers.TCPPort(remotePort))
	netFlow, err := gopacket.FlowFromEndpoints(srcIPEndpoint, dstIPEndpoint)
	if err != nil {
		return flow, err
	}
	tcpFlow, err := gopacket.FlowFromEndpoints(srcTCPEndpoint, dstTCPEndpoint)
	if err != nil {
		return flow, err
	}
	flow = types.NewTcpIpFlowFromFlows(netFlow, tcpFlow)
	return flow, nil
}

// EnsureDialed dials the target TCP endpoint and then
// saves a copy of the outbound connection flow
func (t *TCPInferenceSideChannel) EnsureDialed() error {
	var err error
	if t.conn == nil {
		addr := fmt.Sprintf("%s:%d", t.targetIP, t.targetPort)
		log.Noticef("about to dial addr %s", addr)
		t.conn, err = net.Dial("tcp", addr)
		if err != nil {
			return err
		}
	}
	t.sendFlow = t.getFlowFromConn(t.conn)

	return nil
}

// EnsureOpenedPcap ensures we have an open handle for sending and receiving raw packets
func (t *TCPInferenceSideChannel) EnsureOpenedPcap() error {
	var err error
	if t.conn == nil {
		panic("wtf, t.conn is nil")
	}
	localIP, localPort, remoteIP, remotePort := t.getTCP4Tuple(t.conn)
	filter := fmt.Sprintf("ip host %s and tcp port %d", remoteIP, remotePort)

	log.Noticef("connection 4-tuple %s %d -> %s %d", localIP, localPort, remoteIP, remotePort)
	log.Warningf("attempting to use this filter to sniff the connection: %s", filter)

	t.handle, err = pcap.OpenLive(t.ifaceName, t.snaplen, true, pcap.BlockForever)
	err = t.handle.SetBPFFilter(filter)
	if err != nil {
		log.Warning("failed to set pcap bpf filter")
		return err
	}
	return nil
}

// Start initiates usage of the TCP inference side-channel
func (t *TCPInferenceSideChannel) Start() error {
	err := t.GetCurrentSequence()
	if err != nil {
		log.Warningf("TCPInferenceSideChannel Start failure: %s", err)
		return err
	}

	t.SendProbe()

	return nil
}

// GetCurrentProbeManifest synchronously retreives the outbound types.PacketManifest
// from the TCP connection we will use for the inference side-channel
func (t *TCPInferenceSideChannel) GetCurrentProbeManifest() error {
	var err error

	err = t.EnsureDialed()
	if err != nil {
		return err
	}

	err = t.EnsureOpenedPcap()
	if err != nil {
		panic(err)
	}

	go t.sniffSequence()
	t.SendToConn()
	t.currentPacket = <-t.packetChan

	log.Noticef("current TCP Sequence %d", t.currentPacket.TCP.Seq)
	return nil
}

func (t *TCPInferenceSideChannel) sendProbe() {
	copy := t.currentPacket
	copy.TCP.Seq += 10

	if err := i.send(&copy.Eth, &copy.IPv4, &copy.TCP); err != nil {
		return err
	}
}

// send sends the given layers as a single packet on the network.
func (i *TCPInferenceSideChannel) send(l ...gopacket.SerializableLayer) error {
	if err := gopacket.SerializeLayers(i.buf, i.opts, l...); err != nil {
		return err
	}
	return i.handle.WritePacketData(i.buf.Bytes())
}

// XXX todo: think of a better method receiver name
func (t *TCPInferenceSideChannel) SendToConn() {
	_, err := t.conn.Write([]byte("hello\n"))
	if err != nil {
		panic(err)
	}
}

func (t *TCPInferenceSideChannel) Close() {
	t.handle.Close()
}

func (t *TCPInferenceSideChannel) sniffProbe() {
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
			flow = types.NewTcpIp6FlowFromLayers(*t.ip6, *t.tcp)
		} else {
			flow = types.NewTcpIp4FlowFromLayers(*t.ip4, *t.tcp)
		}

		if t.probeFlow.Equal(flow) {
			log.Warningf("matching probe flow! %s", flow)
			return
		}
	}
}

// sniffSequence is essentially an ethernet sniffer
// written in crash-only style (no shutdown code-path).
// It's decodes packets into types.PacketManifest in
// an IPv4 and IPv6 compatible manner and sends them
// asynchronously on a channel.
func (t *TCPInferenceSideChannel) sniffSequence() {
	for {
		data, captureInfo, err := t.handle.ReadPacketData()
		if err != nil {
			log.Warningf("error getting packet: %v %s", err, ci)
		}

		err = t.parser.DecodeLayers(data, &t.decoded)
		if err != nil {
			log.Warningf("error decoding packet: %v", err)
			continue
		}

		// flow of received packet
		flow := &types.TcpIpFlow{}
		if t.ip4 == nil {
			flow = types.NewTcpIp6FlowFromLayers(*t.ip6, *t.tcp)
		} else {
			flow = types.NewTcpIp4FlowFromLayers(*t.ip4, *t.tcp)
		}

		if t.sendFlow.Equal(flow) {
			log.Warningf("matching flow! %s", flow)

			packetManifest := types.PacketManifest{
				Timestamp: captureInfo.Timestamp,
				Payload:   t.payload,
				IPv6:      &layers.IPv6{},
				IPv4:      &layers.IPv4{},
				TCP:       &layers.TCP{},
			}

			for _, typ := range t.decoded {
				switch typ {
				case layers.LayerTypeIPv4:
					*packetManifest.IPv4 = ip4
					foundNetLayer = true
				case layers.LayerTypeIPv6:
					*packetManifest.IPv6 = ip6
					foundNetLayer = true
				case layers.LayerTypeTCP:
					if foundNetLayer {
						packetManifest.Flow = &flow
						*packetManifest.TCP = tcp
						t.packetChan <- packetManifest
						return
					} else {
						log.Error("could not find IPv4 or IPv6 layer, inoring")
					}
				} // switch typ {
			} // for _, typ := range t.decoded {
		} // if t.sendFlow.Equal(flow) {
	} // for {
}
