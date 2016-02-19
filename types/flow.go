/*
 *    HoneyBadger core library for detecting TCP injection attacks
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

package types

import (
	"fmt"
	"encoding/binary"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)


// TcpIpFlow is used for tracking unidirectional TCP flows
type TcpIpFlow struct {
	ipFlow  gopacket.Flow
	tcpFlow gopacket.Flow
}

// NewTcpIpFlowFromLayers given IPv4 and TCP layers it returns a TcpIpFlow
func NewTcpIpFlowFromLayers(ipLayer layers.IPv4, tcpLayer layers.TCP) *TcpIpFlow {
	return &TcpIpFlow{
		ipFlow:  ipLayer.NetworkFlow(),
		tcpFlow: tcpLayer.TransportFlow(),
	}
}

// NewTcpIpFlowFromFlows given an IP flow and TCP flow returns a TcpIpFlow
func NewTcpIpFlowFromFlows(ipFlow gopacket.Flow, tcpFlow gopacket.Flow) *TcpIpFlow {
	// XXX todo: check that the flow types are correct
	return &TcpIpFlow{
		ipFlow:  ipFlow,
		tcpFlow: tcpFlow,
	}
}


// ConnectionHash returns a hash of the flow A->B such
// that it is guaranteed to collide with flow B->A
func (t *TcpIpFlow) ConnectionHash() HashedTcpIpFlow {
	return NewHashedTcpIpFlow(t).Sorted()
}

// String returns the string representation of a TcpIpFlow
func (t TcpIpFlow) String() string {
	return fmt.Sprintf("%s:%s-%s:%s", t.ipFlow.Src().String(), t.tcpFlow.Src().String(), t.ipFlow.Dst().String(), t.tcpFlow.Dst().String())
}

// Reverse returns a reversed TcpIpFlow, that is to say the resulting
// TcpIpFlow flow will be made up of a reversed IP flow and a reversed
// TCP flow.
func (t *TcpIpFlow) Reverse() *TcpIpFlow {
	return NewTcpIpFlowFromFlows(t.ipFlow.Reverse(), t.tcpFlow.Reverse())
}

// Equal returns true if TcpIpFlow structs t and s are equal. False otherwise.
func (t *TcpIpFlow) Equal(s *TcpIpFlow) bool {
	return t.ipFlow == s.ipFlow && t.tcpFlow == s.tcpFlow
}

// getPacketFlow returns a TcpIpFlow struct given a byte array packet
func NewTcpIpFlowFromPacket(packet []byte) (*TcpIpFlow, error) {
	var ip layers.IPv4
	var tcp layers.TCP
	decoded := []gopacket.LayerType{}
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip, &tcp)
	err := parser.DecodeLayers(packet, &decoded)
	if err != nil {
		return &TcpIpFlow{}, err
	}
	return &TcpIpFlow{
		ipFlow:  ip.NetworkFlow(),
		tcpFlow: tcp.TransportFlow(),
	}, nil
}

// Flows returns the component flow structs IPv4, TCP
func (t *TcpIpFlow) Flows() (gopacket.Flow, gopacket.Flow) {
	return t.ipFlow, t.tcpFlow
}

type HashedTcpIpFlow struct {
	Src uint64
	Dst uint64
}

// NewHashedTcpIpFlow returns a comparable struct given a flow struct
func NewHashedTcpIpFlow(flow *TcpIpFlow) *HashedTcpIpFlow {
	hash := HashedTcpIpFlow{}

	ipFlow, tcpFlow := flow.Flows()
	src := make([]byte, 8)
	copy(src, ipFlow.Src().Raw())
	copy(src[len(ipFlow.Src().Raw()):], tcpFlow.Src().Raw())
	hash.Src = binary.BigEndian.Uint64(src)

	dst := make([]byte, 8)
	copy(dst, ipFlow.Dst().Raw())
	copy(dst[len(ipFlow.Dst().Raw()):], tcpFlow.Dst().Raw())
	hash.Dst = binary.BigEndian.Uint64(dst)

	return &hash
}

func (h *HashedTcpIpFlow) Sorted() HashedTcpIpFlow {
	if h.Src > h.Dst {
		return HashedTcpIpFlow {
			Src: h.Src,
			Dst: h.Dst,
		}
	} else {
		return HashedTcpIpFlow {
			Src: h.Dst,
			Dst: h.Src,
		}
	}
}
