/*
 *    tcpFlowTracking.go - HoneyBadger core library for detecting TCP attacks
 *    such as handshake-hijack, segment veto and sloppy injection.
 *
 *    Copyright (C) 2014  David Stainton
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

package HoneyBadger

import (
	"bytes"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"code.google.com/p/gopacket/tcpassembly"
	"container/ring"
	"fmt"
	"log"
)

const (
	// Size of the ring buffers which stores the latest
	// reassembled streams
	MAX_CONN_PACKETS = 40

	// Stop looking for handshake hijack after several
	// packets have traversed the connection after entering
	// into TCP_DATA_TRANSFER state
	FIRST_FEW_PACKETS = 12

	// TCP states
	TCP_LISTEN                 = 0
	TCP_CONNECTION_REQUEST     = 1
	TCP_CONNECTION_ESTABLISHED = 2
	TCP_DATA_TRANSFER          = 3
	TCP_CONNECTION_CLOSING     = 4
	TCP_CLOSED                 = 5

	// initiating TCP closing finite state machine
	TCP_FIN_WAIT1 = 0
	TCP_FIN_WAIT2 = 1
	TCP_TIME_WAIT = 2
	TCP_CLOSING   = 3

	// initiated TCP closing finite state machine
	TCP_CLOSE_WAIT = 0
	TCP_LAST_ACK   = 1
)

// SequenceFromPacket returns a Sequence number and nil error if the given
// packet is able to be parsed. Otherwise returns 0 and an error.
func SequenceFromPacket(packet []byte) (uint32, error) {
	var ip layers.IPv4
	var tcp layers.TCP
	decoded := []gopacket.LayerType{}
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip, &tcp)
	err := parser.DecodeLayers(packet, &decoded)
	if err != nil {
		return 0, err
	}
	return tcp.Seq, nil
}

// TcpIpFlow is used for tracking unidirectional TCP flows
type TcpIpFlow struct {
	ipFlow  gopacket.Flow
	tcpFlow gopacket.Flow
}

// NewTcpIpFlowFromLayers given IPv4 and TCP layers it returns a TcpIpFlow
func NewTcpIpFlowFromLayers(ipLayer layers.IPv4, tcpLayer layers.TCP) TcpIpFlow {
	return TcpIpFlow{
		ipFlow:  ipLayer.NetworkFlow(),
		tcpFlow: tcpLayer.TransportFlow(),
	}
}

// NewTcpIpFlowFromFlows given an IP flow and TCP flow returns a TcpIpFlow
func NewTcpIpFlowFromFlows(ipFlow gopacket.Flow, tcpFlow gopacket.Flow) TcpIpFlow {
	// XXX todo: check that the flow types are correct
	return TcpIpFlow{
		ipFlow:  ipFlow,
		tcpFlow: tcpFlow,
	}
}

// Reverse returns a reversed TcpIpFlow, that is to say the resulting
// TcpIpFlow flow will be made up of a reversed IP flow and a reversed
// TCP flow.
func (t *TcpIpFlow) Reverse() TcpIpFlow {
	return NewTcpIpFlowFromFlows(t.ipFlow.Reverse(), t.tcpFlow.Reverse())
}

// Equal returns true if TcpIpFlow structs t and s are equal. False otherwise.
func (t *TcpIpFlow) Equal(s TcpIpFlow) bool {
	return t.ipFlow == s.ipFlow && t.tcpFlow == s.tcpFlow
}

// getPacketFlow returns a TcpIpFlow struct given a byte array packet
func NewTcpIpFlowFromPacket(packet []byte) (TcpIpFlow, error) {
	var ip layers.IPv4
	var tcp layers.TCP
	decoded := []gopacket.LayerType{}
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip, &tcp)
	err := parser.DecodeLayers(packet, &decoded)
	if err != nil {
		return TcpIpFlow{
			ipFlow: ip.NetworkFlow(),
		}, err
	}
	return TcpIpFlow{
		ipFlow:  ip.NetworkFlow(),
		tcpFlow: tcp.TransportFlow(),
	}, nil
}

// Flows returns the component flow structs IPv4, TCP
func (t *TcpIpFlow) Flows() (gopacket.Flow, gopacket.Flow) {
	return t.ipFlow, t.tcpFlow
}

// PacketManifest is used to send parsed packets via channels to other goroutines
type PacketManifest struct {
	IP      layers.IPv4
	TCP     layers.TCP
	Payload gopacket.Payload
}

// Reassembly is inspired by gopacket.tcpassembly this struct can be used
// to represent ordered segments of a TCP stream.
type Reassembly struct {
	Start bool
	End   bool
	Seq   tcpassembly.Sequence
	Bytes []byte
}

func (r *Reassembly) String() string {
	return fmt.Sprintf("Reassembly: Seq %d Bytes len %d data %s\n", r.Seq, len(r.Bytes), string(r.Bytes))
}

// Connection is used to track client and server flows for a given TCP connection.
// We implement a basic TCP finite state machine and track state in order to detect
// hanshake hijack and other TCP attacks such as segment veto and stream injection.
type Connection struct {
	state            uint8
	clientState      uint8
	serverState      uint8
	clientFlow       TcpIpFlow
	serverFlow       TcpIpFlow
	closingFlow      TcpIpFlow
	clientNextSeq    tcpassembly.Sequence
	serverNextSeq    tcpassembly.Sequence
	hijackNextAck    tcpassembly.Sequence
	ClientStreamRing *ring.Ring
	ServerStreamRing *ring.Ring
	packetCount      uint64
}

// NewConnection returns a new Connection struct
func NewConnection() Connection {
	return Connection{
		state:            TCP_LISTEN,
		ClientStreamRing: ring.New(MAX_CONN_PACKETS),
		ServerStreamRing: ring.New(MAX_CONN_PACKETS),
	}
}

// isHijack checks for duplicate SYN/ACK indicating handshake hijake
func (c *Connection) isHijack(p PacketManifest, flow TcpIpFlow) bool {
	// check for duplicate SYN/ACK indicating handshake hijake
	if flow.Equal(c.serverFlow) {
		if p.TCP.ACK && p.TCP.SYN {
			if tcpassembly.Sequence(p.TCP.Ack).Difference(c.hijackNextAck) == 0 {
				return true
			}
		}
	}
	return false
}

// getOverlapRings returns the head and tail ring elements corresponding to the first and last
// overlapping ring segments... that overlap with the given packet (PacketManifest).
func (c *Connection) getOverlapRings(p PacketManifest, flow TcpIpFlow) (*ring.Ring, *ring.Ring) {
	var ringPtr, head, tail, prev, current *ring.Ring
	start := tcpassembly.Sequence(p.TCP.Seq)
	end := start.Add(len(p.Payload) - 1)
	if flow.Equal(c.clientFlow) {
		ringPtr = c.ServerStreamRing
	} else {
		ringPtr = c.ClientStreamRing
	}
	current = ringPtr.Prev()
	_, ok := current.Value.(Reassembly)
	if !ok { // do we NOT have any data in our ring buffer?
		return nil, nil
	}
	if start.Difference(current.Value.(Reassembly).Seq.Add(len(current.Value.(Reassembly).Bytes)-1)) < 0 {
		return nil, nil
	}
	for current != ringPtr {
		if !ok {
			if prev.Value.(Reassembly).Seq.Difference(end) < 0 {
				return nil, nil
			}
			head = prev
			break
		}
		diff := current.Value.(Reassembly).Seq.Difference(start)
		if diff == 0 {
			head = current
			break
		} else if diff > 0 {
			diff = start.Difference(current.Value.(Reassembly).Seq.Add(len(current.Value.(Reassembly).Bytes) - 1))
			if diff == 0 {
				head = current
				break
			} else if diff > 0 {
				head = current
				break
			} else {
				return nil, nil
				break
			}
		}
		prev = current
		current = current.Prev()
		_, ok = current.Value.(Reassembly)
	}
	current = head
	for {
		diff := current.Value.(Reassembly).Seq.Add(len(current.Value.(Reassembly).Bytes) - 1).Difference(end)
		if diff <= 0 {
			tail = current
			break
		}
		prev = current
		current = current.Next()
		_, ok = current.Value.(Reassembly)
		if !ok {
			tail = prev
			break
		}
	}
	return head, tail
}

func getStartSequence(head *ring.Ring, start tcpassembly.Sequence) tcpassembly.Sequence {
	var startSeq tcpassembly.Sequence
	diff := head.Value.(Reassembly).Seq.Difference(start)
	if diff >= 0 {
		startSeq = start
	} else {
		startSeq = head.Value.(Reassembly).Seq
	}
	return startSeq
}

func getEndSequence(tail *ring.Ring, end tcpassembly.Sequence) tcpassembly.Sequence {
	var seqEnd tcpassembly.Sequence
	diff := tail.Value.(Reassembly).Seq.Add(len(tail.Value.(Reassembly).Bytes) - 1).Difference(end)
	if diff <= 0 {
		seqEnd = end
	} else {
		seqEnd = tail.Value.(Reassembly).Seq.Add(len(tail.Value.(Reassembly).Bytes) - 1)
	}
	return seqEnd
}

// getRingSlice returns a byte slice from the ring buffer given the head
// and tail of the ring segment. sliceStart indicates the zero-indexed byte offset into
// the head that we should copy from; sliceEnd indicates the number of bytes into tail.
func getRingSlice(head, tail *ring.Ring, sliceStart, sliceEnd int) []byte {
	var overlapBytes []byte
	if sliceStart < 0 || sliceEnd < 0 {
		panic("sliceStart < 0 || sliceEnd < 0")
	}
	if sliceStart >= len(head.Value.(Reassembly).Bytes) {
		panic(fmt.Sprintf("getRingSlice: sliceStart %d >= head len %d", sliceStart, len(head.Value.(Reassembly).Bytes)))
	}
	if sliceEnd > len(tail.Value.(Reassembly).Bytes) {
		panic("impossible; sliceEnd is greater than ring segment")
	}
	if head == tail {
		panic("head == tail")
	}

	overlapBytes = append(overlapBytes, head.Value.(Reassembly).Bytes[sliceStart:]...)
	current := head
	current = current.Next()
	for current.Value.(Reassembly).Seq != tail.Value.(Reassembly).Seq {
		overlapBytes = append(overlapBytes, current.Value.(Reassembly).Bytes...)
		current = current.Next()
	}
	overlapBytes = append(overlapBytes, tail.Value.(Reassembly).Bytes[:sliceEnd]...)
	return overlapBytes
}

func getHeadRingOffset(head *ring.Ring, start tcpassembly.Sequence) int {
	return head.Value.(Reassembly).Seq.Difference(start)
}

func getStartOverlapSequenceAndOffset(head *ring.Ring, start tcpassembly.Sequence) (tcpassembly.Sequence, int) {
	seqStart := getStartSequence(head, start)
	offset := int(start.Difference(seqStart))
	return seqStart, offset
}

func getRingSegmentLastSequence(segment *ring.Ring) tcpassembly.Sequence {
	return segment.Value.(Reassembly).Seq.Add(len(segment.Value.(Reassembly).Bytes) - 1)
}

func getTailRingOffset(tail *ring.Ring, end tcpassembly.Sequence) int {
	tailEndSequence := getRingSegmentLastSequence(tail)
	return end.Difference(tailEndSequence)
}

func getEndOverlapSequenceAndOffset(tail *ring.Ring, end tcpassembly.Sequence) (tcpassembly.Sequence, int) {
	seqEnd := getEndSequence(tail, end)
	offset := int(seqEnd.Difference(end))
	return seqEnd, offset
}

// getOverlapBytes returns the overlap byte array; that is the contiguous data stored in our ring buffer
// that overlaps with the stream segment specified by the start and end Sequence boundaries.
// The other return values are the slice offsets of the original packet payload that can be used to derive
// the new overlapping portion of the stream segment.
func (c *Connection) getOverlapBytes(head, tail *ring.Ring, start, end tcpassembly.Sequence) ([]byte, int, int) {
	var overlapStartSlice, overlapEndSlice int
	var overlapBytes []byte
	if head == nil || tail == nil {
		panic("wtf; head or tail is nil\n")
	}
	sequenceStart, overlapStartSlice := getStartOverlapSequenceAndOffset(head, start)
	headOffset := getHeadRingOffset(head, sequenceStart)

	sequenceEnd, overlapEndOffset := getEndOverlapSequenceAndOffset(tail, end)
	tailOffset := getTailRingOffset(tail, sequenceEnd)

	if int(head.Value.(Reassembly).Seq) == int(tail.Value.(Reassembly).Seq) {
		endOffset := len(head.Value.(Reassembly).Bytes) - tailOffset
		overlapEndSlice = len(head.Value.(Reassembly).Bytes) - tailOffset + overlapStartSlice - headOffset
		overlapBytes = head.Value.(Reassembly).Bytes[headOffset:endOffset]
	} else {
		totalLen := start.Difference(end) + 1
		overlapEndSlice = totalLen - overlapEndOffset
		tailSlice := len(tail.Value.(Reassembly).Bytes) - tailOffset
		overlapBytes = getRingSlice(head, tail, headOffset, tailSlice)
	}
	return overlapBytes, overlapStartSlice, overlapEndSlice
}

// isInjection returns true if the given packet indicates a TCP injection attack
// such as segment veto. Returns false otherwise.
func (c *Connection) isInjection(p PacketManifest, flow TcpIpFlow) bool {
	head, tail := c.getOverlapRings(p, flow)
	if head == nil || tail == nil {
		log.Print("getOverlapRings returned a nil\n")
		return false
	}
	start := tcpassembly.Sequence(p.TCP.Seq)
	end := start.Add(len(p.Payload) - 1)
	overlapBytes, startOffset, endOffset := c.getOverlapBytes(head, tail, start, end)
	return !bytes.Equal(overlapBytes, p.Payload[startOffset:endOffset])
}

// stateListen gets called by our TCP finite state machine runtime
// and moves us into the TCP_CONNECTION_REQUEST state if we receive
// a SYN packet.
func (c *Connection) stateListen(p PacketManifest, flow TcpIpFlow) {
	if p.TCP.SYN && !p.TCP.ACK {
		log.Print("TCP_CONNECTION_REQUEST\n")
		c.state = TCP_CONNECTION_REQUEST
		c.clientFlow = flow
		c.serverFlow = c.clientFlow.Reverse()

		// Note that TCP SYN and SYN/ACK packets may contain payload data if
		// a TCP extension is used...
		// If so then the sequence number needs to track this payload.
		// For more information see: https://tools.ietf.org/id/draft-agl-tcpm-sadata-00.html
		c.clientNextSeq = tcpassembly.Sequence(p.TCP.Seq).Add(len(p.Payload) + 1) // XXX
		c.hijackNextAck = c.clientNextSeq
	} else {
		log.Print("unknown TCP state\n")
	}
}

// stateConnectionRequest gets called by our TCP finite state machine runtime
// and moves us into the TCP_CONNECTION_ESTABLISHED state if we receive
// a SYN/ACK packet.
func (c *Connection) stateConnectionRequest(p PacketManifest, flow TcpIpFlow) {
	if !flow.Equal(c.serverFlow) {
		log.Print("handshake anomaly\n")
		return
	}
	if !(p.TCP.SYN && p.TCP.ACK) {
		log.Print("handshake anomaly\n")
		return
	}
	if tcpassembly.Sequence(c.clientNextSeq).Difference(tcpassembly.Sequence(p.TCP.Ack)) != 0 {
		log.Print("handshake anomaly\n")
		return
	}
	log.Print("TCP_CONNECTION_ESTABLISHED\n")
	c.state = TCP_CONNECTION_ESTABLISHED
	c.serverNextSeq = tcpassembly.Sequence(p.TCP.Seq).Add(len(p.Payload) + 1) // XXX see above comment about TCP extentions
}

// stateConnectionEstablished is called by our TCP FSM runtime and
// changes our state to TCP_DATA_TRANSFER if we receive a valid final
// handshake ACK packet.
func (c *Connection) stateConnectionEstablished(p PacketManifest, flow TcpIpFlow) {
	if c.isHijack(p, flow) {
		log.Print("handshake hijack attack detected.\n")
		return
	}
	if !flow.Equal(c.clientFlow) {
		log.Print("handshake anomaly\n")
		return
	}
	if !p.TCP.ACK || p.TCP.SYN {
		log.Print("handshake anomaly\n")
		return
	}
	if tcpassembly.Sequence(p.TCP.Seq).Difference(c.clientNextSeq) != 0 {
		log.Print("handshake anomaly\n")
		return
	}
	if tcpassembly.Sequence(p.TCP.Ack).Difference(c.serverNextSeq) != 0 {
		log.Print("handshake anomaly\n")
		return
	}
	c.state = TCP_DATA_TRANSFER
	log.Print("TCP_DATA_TRANSFER\n")
}

// stateDataTransfer is called by our TCP FSM and processes packets
// once we are in the TCP_DATA_TRANSFER state
func (c *Connection) stateDataTransfer(p PacketManifest, flow TcpIpFlow) {
	var nextSeqPtr *tcpassembly.Sequence
	var closerState, remoteState *uint8
	if c.packetCount < FIRST_FEW_PACKETS {
		if c.isHijack(p, flow) {
			log.Print("handshake hijack detected\n")
			return
		}
	}
	if flow.Equal(c.clientFlow) {
		nextSeqPtr = &c.clientNextSeq
		closerState = &c.clientState
		remoteState = &c.serverState
	} else {
		nextSeqPtr = &c.serverNextSeq
		closerState = &c.serverState
		remoteState = &c.clientState
	}
	diff := tcpassembly.Sequence(p.TCP.Seq).Difference(*nextSeqPtr)
	if diff > 0 {
		// *nextSeqPtr comes after p.TCP.Seq
		// stream overlap case

		log.Printf("overlap case: TCP.Seq %d before nextSeqPtr %d\n", p.TCP.Seq, *nextSeqPtr)
		if c.isInjection(p, flow) {
			log.Print("TCP injection attack detected.\n")
		}
	} else if diff == 0 {
		// contiguous!
		if p.TCP.FIN {
			c.closingFlow = c.clientFlow // XXX
			*nextSeqPtr += 1
			c.state = TCP_CONNECTION_CLOSING
			*closerState = TCP_FIN_WAIT1
			*remoteState = TCP_CLOSE_WAIT
			log.Print("TCP_CONNECTION_CLOSING: FIN packet\n")
			return
		}
		if p.TCP.RST {
			// XXX
			c.state = TCP_CLOSED
			return
		}
		if len(p.Payload) > 0 {
			reassembly := Reassembly{
				Seq:   tcpassembly.Sequence(p.TCP.Seq),
				Bytes: []byte(p.Payload),
			}
			if flow == c.clientFlow {
				c.ServerStreamRing = c.ServerStreamRing.Next()
				c.ServerStreamRing.Value = reassembly
				log.Printf("expected tcp Sequence from client; payload len %d; ring len %d\n", len(p.Payload), c.ServerStreamRing.Len())
			} else {
				c.ClientStreamRing = c.ClientStreamRing.Next()
				c.ClientStreamRing.Value = reassembly
				log.Printf("expected tcp Sequence from server; payload len %d; ring len %d\n", len(p.Payload), c.ClientStreamRing.Len())
			}
			*nextSeqPtr = tcpassembly.Sequence(p.TCP.Seq).Add(len(p.Payload)) // XXX
		}
	} else if diff < 0 {
		// p.TCP.Seq comes after *nextSeqPtr
		// futute-out-of-order packet case
		// ...
	}
}

// stateFinWait1 handles packets for the FIN-WAIT-1 state
func (c *Connection) stateFinWait1(p PacketManifest, flow TcpIpFlow, nextSeqPtr *tcpassembly.Sequence, nextAckPtr *tcpassembly.Sequence, statePtr, otherStatePtr *uint8) {
	if tcpassembly.Sequence(p.TCP.Seq).Difference(*nextSeqPtr) != 0 {
		log.Print("FIN-WAIT-1: out of order packet received\n")
		return
	}
	if p.TCP.ACK {
		if tcpassembly.Sequence(p.TCP.Ack).Difference(*nextAckPtr) != 0 { //XXX
			log.Printf("FIN-WAIT-1: unexpected ACK: got %d expected %d\n", p.TCP.Ack, *nextAckPtr)
			return
		}
		if p.TCP.FIN {
			*statePtr = TCP_CLOSING
			*otherStatePtr = TCP_LAST_ACK
			log.Print("TCP_CLOSING FIN/ACK\n")
			*nextSeqPtr = tcpassembly.Sequence(p.TCP.Seq).Add(len(p.Payload) + 1)
		} else {
			*statePtr = TCP_FIN_WAIT2
			log.Print("TCP_FIN_WAIT2\n")
		}
	} else {
		log.Print("FIN-WAIT-1: non-ACK packet received.\n")
	}
}

// stateFinWait1 handles packets for the FIN-WAIT-2 state
func (c *Connection) stateFinWait2(p PacketManifest, flow TcpIpFlow, nextSeqPtr *tcpassembly.Sequence, nextAckPtr *tcpassembly.Sequence, statePtr *uint8) {
	if tcpassembly.Sequence(p.TCP.Seq).Difference(*nextSeqPtr) == 0 {
		if p.TCP.ACK && p.TCP.FIN {
			if tcpassembly.Sequence(p.TCP.Ack).Difference(*nextAckPtr) != 0 {
				log.Print("FIN-WAIT-1: out of order ACK packet received.\n")
				return
			}
			*nextSeqPtr += 1
			// XXX
			*statePtr = TCP_TIME_WAIT
			log.Print("TCP_TIME_WAIT\n")

		} else {
			log.Print("FIN-WAIT-2: protocol anamoly")
		}
	} else {
		log.Print("FIN-WAIT-2: out of order packet received.\n")
	}
}

func (c *Connection) stateCloseWait(p PacketManifest) {
	log.Print("CLOSE-WAIT: invalid protocol state\n")
}

func (c *Connection) stateTimeWait(p PacketManifest) {
	log.Print("TIME-WAIT: invalid protocol state\n")
}

func (c *Connection) stateClosing(p PacketManifest) {
	log.Print("CLOSING: invalid protocol state\n")
}

func (c *Connection) stateLastAck(p PacketManifest, flow TcpIpFlow, nextSeqPtr *tcpassembly.Sequence, nextAckPtr *tcpassembly.Sequence, statePtr *uint8) {
	if tcpassembly.Sequence(p.TCP.Seq).Difference(*nextSeqPtr) == 0 { //XXX
		if p.TCP.ACK && (!p.TCP.FIN && !p.TCP.SYN) {
			if tcpassembly.Sequence(p.TCP.Ack).Difference(*nextAckPtr) != 0 {
				log.Print("LAST-ACK: out of order ACK packet received.\n")
				return
			}
			// XXX
			log.Print("TCP_CLOSED\n")
			c.state = TCP_CLOSED
			// ...
		} else {
			log.Print("LAST-ACK: protocol anamoly\n")
		}
	} else {
		log.Print("LAST-ACK: out of order packet received\n")
		//log.Printf("LAST-ACK: out of order packet received; got %d expected %d\n", p.TCP.Seq, *nextSeqPtr)
	}
}

// stateClosing handles all the closing states until the closed state has been reached.
func (c *Connection) stateConnectionClosing(p PacketManifest, flow TcpIpFlow) {
	var nextSeqPtr *tcpassembly.Sequence
	var nextAckPtr *tcpassembly.Sequence
	var statePtr, otherStatePtr *uint8
	if flow.Equal(c.closingFlow) {
		// XXX double check this
		if c.clientFlow.Equal(flow) {
			statePtr = &c.clientState
			nextSeqPtr = &c.clientNextSeq
			nextAckPtr = &c.serverNextSeq
		} else {
			statePtr = &c.serverState
			nextSeqPtr = &c.serverNextSeq
			nextAckPtr = &c.clientNextSeq
		}
		switch *statePtr {
		case TCP_CLOSE_WAIT:
			c.stateCloseWait(p)
		case TCP_LAST_ACK:
			c.stateLastAck(p, flow, nextSeqPtr, nextAckPtr, statePtr)
		}
	} else {
		// XXX double check this
		if c.clientFlow.Equal(flow) {
			statePtr = &c.clientState
			otherStatePtr = &c.serverState
			nextSeqPtr = &c.clientNextSeq
			nextAckPtr = &c.serverNextSeq
		} else {
			statePtr = &c.serverState
			otherStatePtr = &c.clientState
			nextSeqPtr = &c.serverNextSeq
			nextAckPtr = &c.clientNextSeq
		}
		switch *statePtr {
		case TCP_FIN_WAIT1:
			c.stateFinWait1(p, flow, nextSeqPtr, nextAckPtr, statePtr, otherStatePtr)
		case TCP_FIN_WAIT2:
			c.stateFinWait2(p, flow, nextSeqPtr, nextAckPtr, statePtr)
		case TCP_TIME_WAIT:
			c.stateTimeWait(p)
		case TCP_CLOSING:
			c.stateClosing(p)
		}
	}
}

func (c *Connection) stateClosed(p PacketManifest, flow TcpIpFlow) {
	log.Print("state closed: it is a protocol anomaly to receive packets on a closed connection.\n")
}

// receivePacket implements a TCP finite state machine
// which is loosely based off of the simplified FSM in this paper:
// http://ants.iis.sinica.edu.tw/3bkmj9ltewxtsrrvnoknfdxrm3zfwrr/17/p520460.pdf
// The goal is to detect all manner of content injection.
func (c *Connection) receivePacket(p PacketManifest, flow TcpIpFlow) {
	c.packetCount += 1
	switch c.state {
	case TCP_LISTEN:
		c.stateListen(p, flow)
	case TCP_CONNECTION_REQUEST:
		c.stateConnectionRequest(p, flow)
	case TCP_CONNECTION_ESTABLISHED:
		c.stateConnectionEstablished(p, flow)
	case TCP_DATA_TRANSFER:
		c.stateDataTransfer(p, flow)
	case TCP_CONNECTION_CLOSING:
		c.stateConnectionClosing(p, flow)
	case TCP_CLOSED:
		c.stateClosed(p, flow)
	}
}

// ConnTracker is used to track TCP connections using
// two maps. One for each flow... where a TcpIpFlow
// is the key and *Connection is the value.
type ConnTracker struct {
	flowAMap map[TcpIpFlow]*Connection
	flowBMap map[TcpIpFlow]*Connection
}

// NewConnTracker returns a new ConnTracker struct
func NewConnTracker() *ConnTracker {
	return &ConnTracker{
		flowAMap: make(map[TcpIpFlow]*Connection),
		flowBMap: make(map[TcpIpFlow]*Connection),
	}
}

// Has returns true if the given TcpIpFlow is a key in our
// either of flowAMap or flowBMap
func (c *ConnTracker) Has(key TcpIpFlow) bool {
	_, ok := c.flowAMap[key]
	if !ok {
		_, ok = c.flowBMap[key]
	}
	return ok
}

// Get returns the Connection struct pointer corresponding
// to the given TcpIpFlow key in one of the flow maps
// flowAMap or flowBMap
func (c *ConnTracker) Get(key TcpIpFlow) (*Connection, error) {
	val, ok := c.flowAMap[key]
	if ok {
		return val, nil
	} else {
		val, ok = c.flowBMap[key]
		if !ok {
			return nil, fmt.Errorf("failed to retreive flow\n")
		}
	}
	return val, nil
}

// Put sets the connectionMap's key/value.. where a given TcpBidirectionalFlow
// is the key and a Connection struct pointer is the value.
func (c *ConnTracker) Put(key TcpIpFlow, conn *Connection) {
	c.flowAMap[key] = conn
	c.flowBMap[key.Reverse()] = conn
}

// startReceivingTcp is a generator function which returns two channels;
// a stop channel and a packet channel. This function creates a goroutine
// which continually reads packets off the network interface and sends them
// to the packet channel.
func StartReceivingTcp(filter, iface string, snaplen int) (chan bool, chan []byte) {

	handle, err := pcap.OpenLive(iface, int32(snaplen), true, pcap.BlockForever)
	if err != nil {
		log.Fatal("error opening pcap handle: ", err)
	}
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatal("error setting BPF filter: ", err)
	}

	stopReceiveChan := make(chan bool)
	receiveParseChan := make(chan []byte)

	go func() {
		for {
			select {
			case <-stopReceiveChan:
				return
			default:
				data, _, err := handle.ReadPacketData()
				if err != nil {
					continue
				}
				receiveParseChan <- data
			}
		}
	}()
	return stopReceiveChan, receiveParseChan
}

// startDecodingTcp calls decodeTcp in a new goroutine...
func StartDecodingTcp(packetChan chan []byte, connTracker *ConnTracker) {
	stopDecodeChan := make(chan bool)
	go decodeTcp(packetChan, connTracker, stopDecodeChan)
}

// decodeTcp receives packets from a channel and decodes them with gopacket,
// creates a bidirectional flow identifier for each TCP packet and determines
// which flow tracker instance is tracking that connection. If none is found then
// a new flow tracker is created. Either way the parsed packet structs are passed
// to the flow tracker for further processing.
func decodeTcp(packetChan chan []byte, connTracker *ConnTracker, stopDecodeChan chan bool) {
	var eth layers.Ethernet
	var ip layers.IPv4
	var tcp layers.TCP
	var payload gopacket.Payload

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip, &tcp, &payload)
	decoded := make([]gopacket.LayerType, 0, 4)

	for {
		select {
		case packetBytes := <-packetChan:
			newPayload := new(gopacket.Payload)
			payload = *newPayload
			err := parser.DecodeLayers(packetBytes, &decoded)
			if err != nil {
				continue
			}
			tcpipflow := NewTcpIpFlowFromFlows(ip.NetworkFlow(), tcp.TransportFlow())
			packetManifest := PacketManifest{
				IP:      ip,
				TCP:     tcp,
				Payload: payload,
			}
			if connTracker.Has(tcpipflow) {
				conn, err := connTracker.Get(tcpipflow)
				if err != nil {
					panic(err) // wtf
				}
				conn.receivePacket(packetManifest, tcpipflow)
			} else {
				conn := NewConnection()
				connTracker.Put(tcpipflow, &conn)
				conn.receivePacket(packetManifest, tcpipflow)
			}
		case <-stopDecodeChan:
			return
		}
	}
}
