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
	"golang.org/x/net/ipv4"
	"net"
)

type TCPStreamInjector struct {
	packetConn    net.PacketConn
	rawConn       *ipv4.RawConn
	ipHeader      *ipv4.Header
	ip            layers.IPv4
	tcp           layers.TCP
	ipBuf         gopacket.SerializeBuffer
	tcpPayloadBuf gopacket.SerializeBuffer
	Payload       gopacket.Payload
}

func (i *TCPStreamInjector) Init(netInterface string) error {
	var err error
	i.packetConn, err = net.ListenPacket("ip4:tcp", netInterface)
	if err != nil {
		return err
	}
	i.rawConn, err = ipv4.NewRawConn(i.packetConn)
	return err
}

func (i *TCPStreamInjector) SetIPLayer(iplayer layers.IPv4) error {
	i.ip = iplayer
	i.ipBuf = gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := i.ip.SerializeTo(i.ipBuf, opts)
	if err != nil {
		return err
	}
	i.ipHeader, err = ipv4.ParseHeader(i.ipBuf.Bytes())
	if err != nil {
		return err
	}
	return nil
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

func (i *TCPStreamInjector) Write() error {
	i.tcp.SetNetworkLayerForChecksum(&i.ip)
	i.tcpPayloadBuf = gopacket.NewSerializeBuffer()
	//	packetPayload := gopacket.Payload(i.Payload)
	packetPayload := i.Payload
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(i.tcpPayloadBuf, opts, &i.tcp, packetPayload)
	if err != nil {
		return err
	}
	err = i.rawConn.WriteTo(i.ipHeader, i.tcpPayloadBuf.Bytes(), nil)
	return err
}
