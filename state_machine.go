/*
 *    state_machine.go - HoneyBadger core library for detecting TCP attacks
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
	"container/ring"
	"fmt"
	"log"
	"time"
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
	TCP_UNKNOWN                = 0
	TCP_CONNECTION_REQUEST     = 1
	TCP_CONNECTION_ESTABLISHED = 2
	TCP_DATA_TRANSFER          = 3
	TCP_CONNECTION_CLOSING     = 4

	// initiating TCP closing finite state machine
	TCP_FIN_WAIT1 = 0
	TCP_FIN_WAIT2 = 1
	TCP_TIME_WAIT = 2
	TCP_CLOSING   = 3

	// initiated TCP closing finite state machine
	TCP_CLOSE_WAIT = 0
	TCP_LAST_ACK   = 1
)

// PacketManifest is used to send parsed packets via channels to other goroutines
type PacketManifest struct {
	Timestamp time.Time
	Flow      TcpIpFlow
	RawPacket []byte
	IP        layers.IPv4
	TCP       layers.TCP
	Payload   gopacket.Payload
}

// String returns a string representation of Reassembly
func (r *Reassembly) String() string {
	return fmt.Sprintf("Reassembly: Seq %d Bytes len %d data %s\n", r.Seq, len(r.Bytes), string(r.Bytes))
}

type CloseRequest struct {
	Flow           *TcpIpFlow
	CloseReadyChan chan bool
}

type ConnectionOptions struct {
	MaxBufferedPagesTotal         int
	MaxBufferedPagesPerConnection int
}

// Connection is used to track client and server flows for a given TCP connection.
// We implement a basic TCP finite state machine and track state in order to detect
// hanshake hijack and other TCP attacks such as segment veto and stream injection.
type Connection struct {
	ConnectionOptions

	closeRequestChan chan CloseRequest
	stopChan         chan bool
	receiveChan      chan *PacketManifest

	packetCount uint64
	lastSeen    time.Time

	state       uint8
	clientState uint8
	serverState uint8

	connectFlowKnown bool

	clientFlow  TcpIpFlow
	serverFlow  TcpIpFlow
	closingFlow TcpIpFlow

	clientNextSeq Sequence
	serverNextSeq Sequence
	hijackNextAck Sequence

	ClientStreamRing *ring.Ring
	ServerStreamRing *ring.Ring

	ClientCoalesce *OrderedCoalesce
	ServerCoalesce *OrderedCoalesce

	PacketLogger PacketLogger
	AttackLogger AttackLogger
}

// NewConnection returns a new Connection struct
func NewConnection(closeRequestChan chan CloseRequest) *Connection {
	conn := Connection{
		closeRequestChan: closeRequestChan,
		stopChan:         make(chan bool),
		receiveChan:      make(chan *PacketManifest),

		state: TCP_LISTEN,

		ClientStreamRing: ring.New(MAX_CONN_PACKETS),
		ServerStreamRing: ring.New(MAX_CONN_PACKETS),
	}
	go conn.startReceivingPackets()
	return &conn
}

// Close frees up all resources used by the connection
// We send a close request to the Inquisitor;
// once we receive response on the closeReadyChan
// we call our Stop method.
func (c *Connection) Close() {
	log.Printf("close detected for %s\n", c.clientFlow.String())
	closeReadyChan := make(chan bool)
	// remove Connection from ConnectionPool
	c.closeRequestChan <- CloseRequest{
		Flow:           &c.clientFlow,
		CloseReadyChan: closeReadyChan,
	}
	log.Print("close request sent\n")
	<-closeReadyChan
	log.Print("close request completed.\n")
	c.Stop()
}

// Stop is used to stop the packet receiving goroutine and
// the packet logger.
func (c *Connection) Stop() {
	log.Print("Connection.Stop() called.\n")
	c.stopChan <- true
	if c.PacketLogger != nil {
		log.Print("stoping pcap logger\n")
		c.PacketLogger.Stop()
	}
	log.Printf("stopped tracking %s\n", c.clientFlow.String())
}

// detectHijack checks for duplicate SYN/ACK indicating handshake hijake
// and submits a report if an attack was observed
func (c *Connection) detectHijack(p PacketManifest, flow TcpIpFlow) {
	// check for duplicate SYN/ACK indicating handshake hijake
	if !flow.Equal(c.serverFlow) {
		return
	}
	if p.TCP.ACK && p.TCP.SYN {
		if Sequence(p.TCP.Ack).Difference(c.hijackNextAck) == 0 {
			c.AttackLogger.ReportHijackAttack(time.Now(), flow)
		}
	}
}

// getOverlapRings returns the head and tail ring elements corresponding to the first and last
// overlapping ring segments... that overlap with the given packet (PacketManifest).
func (c *Connection) getOverlapRings(p PacketManifest, flow TcpIpFlow) (*ring.Ring, *ring.Ring) {
	var ringPtr, head, tail *ring.Ring
	start := Sequence(p.TCP.Seq)
	end := start.Add(len(p.Payload) - 1)
	if flow.Equal(c.clientFlow) {
		ringPtr = c.ServerStreamRing
	} else {
		ringPtr = c.ClientStreamRing
	}
	head = getHeadFromRing(ringPtr, start, end)
	if head == nil {
		return nil, nil
	}
	tail = getTailFromRing(head, end)
	return head, tail
}

// getOverlapBytes returns the overlap byte array; that is the contiguous data stored in our ring buffer
// that overlaps with the stream segment specified by the start and end Sequence boundaries.
// The other return values are the slice offsets of the original packet payload that can be used to derive
// the new overlapping portion of the stream segment.
func (c *Connection) getOverlapBytes(head, tail *ring.Ring, start, end Sequence) ([]byte, int, int) {
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

// detectInjection write an attack report if the given packet indicates a TCP injection attack
// such as segment veto.
func (c *Connection) detectInjection(p PacketManifest, flow TcpIpFlow) {
	head, tail := c.getOverlapRings(p, flow)
	if head == nil || tail == nil {
		log.Printf("ring buffer not adequately filled. retrospective analysis impossible\n", flow.String())
	}
	start := Sequence(p.TCP.Seq)
	end := start.Add(len(p.Payload) - 1)
	overlapBytes, startOffset, endOffset := c.getOverlapBytes(head, tail, start, end)
	if !bytes.Equal(overlapBytes, p.Payload[startOffset:endOffset]) {
		c.AttackLogger.ReportInjectionAttack("injection", time.Now(), flow, p.Payload, overlapBytes, start, end, startOffset, endOffset)
	} else {
		log.Print("not an attack attempt; a normal TCP retransmission.\n")
	}
}

// stateUnknown gets called by our TCP finite state machine runtime
// and moves us into the TCP_CONNECTION_REQUEST state if we receive
// a SYN packet... otherwise TCP_DATA_TRANSFER state.
func (c *Connection) stateUnknown(p PacketManifest) {
	if p.TCP.SYN && !p.TCP.ACK {
		c.state = TCP_CONNECTION_REQUEST
		c.connectFlowKnown = true
		c.clientFlow = p.Flow
		c.serverFlow = p.Flow.Reverse()

		// Note that TCP SYN and SYN/ACK packets may contain payload data if
		// a TCP extension is used...
		// If so then the sequence number needs to track this payload.
		// For more information see: https://tools.ietf.org/id/draft-agl-tcpm-sadata-00.html
		c.clientNextSeq = Sequence(p.TCP.Seq).Add(len(p.Payload) + 1) // XXX
		c.hijackNextAck = c.clientNextSeq

	} else {
		c.state = TCP_DATA_TRANSFER
		c.connectFlowKnown = false
		c.clientFlow = p.Flow
		c.clientFlow = p.Flow.Reverse()

		c.clientNextSeq = Sequence(p.TCP.Seq).Add(len(p.Payload) + 1)
	}
	c.ClientCoalesce = NewOrderedCoalesce(c.clientFlow, c.ClientStreamRing, c.MaxBufferedPagesTotal, c.MaxBufferedPagesPerConnection)
	c.ServerCoalesce = NewOrderedCoalesce(c.serverFlow, c.ServerStreamRing, c.MaxBufferedPagesTotal, c.MaxBufferedPagesPerConnection)
}

// stateConnectionRequest gets called by our TCP finite state machine runtime
// and moves us into the TCP_CONNECTION_ESTABLISHED state if we receive
// a SYN/ACK packet.
func (c *Connection) stateConnectionRequest(p PacketManifest) {
	if !p.Flow.Equal(c.serverFlow) {
		//handshake anomaly
		return
	}
	if !(p.TCP.SYN && p.TCP.ACK) {
		//handshake anomaly
		return
	}
	if c.clientNextSeq.Difference(Sequence(p.TCP.Ack)) != 0 {
		//handshake anomaly
		return
	}
	c.state = TCP_CONNECTION_ESTABLISHED
	c.serverNextSeq = Sequence(p.TCP.Seq).Add(len(p.Payload) + 1) // XXX see above comment about TCP extentions
}

// stateConnectionEstablished is called by our TCP FSM runtime and
// changes our state to TCP_DATA_TRANSFER if we receive a valid final
// handshake ACK packet.
func (c *Connection) stateConnectionEstablished(p PacketManifest) {
	c.detectHijack(p, p.Flow)
	if !p.Flow.Equal(c.clientFlow) {
		// handshake anomaly
		return
	}
	if !p.TCP.ACK || p.TCP.SYN {
		// handshake anomaly
		return
	}
	if Sequence(p.TCP.Seq).Difference(c.clientNextSeq) != 0 {
		// handshake anomaly
		return
	}
	if Sequence(p.TCP.Ack).Difference(c.serverNextSeq) != 0 {
		// handshake anomaly
		return
	}
	c.state = TCP_DATA_TRANSFER
	log.Printf("connected %s\n", c.clientFlow.String())
}

// stateDataTransfer is called by our TCP FSM and processes packets
// once we are in the TCP_DATA_TRANSFER state
func (c *Connection) stateDataTransfer(p PacketManifest) {
	var nextSeqPtr *Sequence
	var closerState, remoteState *uint8
	if c.packetCount < FIRST_FEW_PACKETS {
		c.detectHijack(p, p.Flow)
	}
	if p.Flow.Equal(c.clientFlow) {
		nextSeqPtr = &c.clientNextSeq
		closerState = &c.clientState
		remoteState = &c.serverState
	} else {
		nextSeqPtr = &c.serverNextSeq
		closerState = &c.serverState
		remoteState = &c.clientState
	}
	diff := Sequence(p.TCP.Seq).Difference(*nextSeqPtr)
	if diff > 0 {
		// *nextSeqPtr comes after p.TCP.Seq
		// stream overlap case
		c.detectInjection(p, p.Flow)
	} else if diff == 0 {
		// contiguous!
		if p.TCP.FIN {
			*nextSeqPtr += 1
			c.closingFlow = p.Flow
			c.state = TCP_CONNECTION_CLOSING
			*closerState = TCP_FIN_WAIT1
			*remoteState = TCP_CLOSE_WAIT
			return
		}
		if p.TCP.RST {
			log.Print("got RST!\n")
			c.Close()
			return
		}
		if len(p.Payload) > 0 {
			reassembly := Reassembly{
				Seq:   Sequence(p.TCP.Seq),
				Bytes: []byte(p.Payload),
			}
			if p.Flow == c.clientFlow {
				c.ServerStreamRing.Value = reassembly
				c.ServerStreamRing = c.ServerStreamRing.Next()
			} else {
				c.ClientStreamRing.Value = reassembly
				c.ClientStreamRing = c.ClientStreamRing.Next()
			}
			*nextSeqPtr = Sequence(p.TCP.Seq).Add(len(p.Payload)) // XXX
		}
	} else if diff < 0 {
		// p.TCP.Seq comes after *nextSeqPtr
		// future-out-of-order packet case
		if len(p.Payload) > 0 {
			if p.Flow == c.clientFlow {
				c.ClientCoalesce.insert(p)
			} else {
				c.ServerCoalesce.insert(p)
			}
		}
	}
}

// stateFinWait1 handles packets for the FIN-WAIT-1 state
func (c *Connection) stateFinWait1(p PacketManifest, flow TcpIpFlow, nextSeqPtr *Sequence, nextAckPtr *Sequence, statePtr, otherStatePtr *uint8) {
	if Sequence(p.TCP.Seq).Difference(*nextSeqPtr) != 0 {
		log.Printf("FIN-WAIT-1: out of order packet received. sequence %d != nextSeq %d\n", p.TCP.Seq, *nextSeqPtr)
		return
	}
	if p.TCP.ACK {
		if Sequence(p.TCP.Ack).Difference(*nextAckPtr) != 0 { //XXX
			log.Printf("FIN-WAIT-1: unexpected ACK: got %d expected %d\n", p.TCP.Ack, *nextAckPtr)
			return
		}
		if p.TCP.FIN {
			*statePtr = TCP_CLOSING
			*otherStatePtr = TCP_LAST_ACK
			*nextSeqPtr = Sequence(p.TCP.Seq).Add(len(p.Payload) + 1)
		} else {
			*statePtr = TCP_FIN_WAIT2
		}
	} else {
		log.Print("FIN-WAIT-1: non-ACK packet received.\n")
	}
}

// stateFinWait1 handles packets for the FIN-WAIT-2 state
func (c *Connection) stateFinWait2(p PacketManifest, flow TcpIpFlow, nextSeqPtr *Sequence, nextAckPtr *Sequence, statePtr *uint8) {
	if Sequence(p.TCP.Seq).Difference(*nextSeqPtr) == 0 {
		if p.TCP.ACK && p.TCP.FIN {
			if Sequence(p.TCP.Ack).Difference(*nextAckPtr) != 0 {
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

// stateCloseWait represents the TCP FSM's CLOSE-WAIT state
func (c *Connection) stateCloseWait(p PacketManifest) {
	flow := NewTcpIpFlowFromLayers(p.IP, p.TCP)
	log.Printf("stateCloseWait: flow %s\n", flow.String())
	log.Print("CLOSE-WAIT: invalid protocol state\n")
}

// stateTimeWait represents the TCP FSM's CLOSE-WAIT state
func (c *Connection) stateTimeWait(p PacketManifest) {
	log.Print("TIME-WAIT: invalid protocol state\n")
}

// stateClosing represents the TCP FSM's CLOSING state
func (c *Connection) stateClosing(p PacketManifest) {
	log.Print("CLOSING: invalid protocol state\n")
}

// stateLastAck represents the TCP FSM's LAST-ACK state
func (c *Connection) stateLastAck(p PacketManifest, flow TcpIpFlow, nextSeqPtr *Sequence, nextAckPtr *Sequence, statePtr *uint8) {
	if Sequence(p.TCP.Seq).Difference(*nextSeqPtr) == 0 { //XXX
		if p.TCP.ACK && (!p.TCP.FIN && !p.TCP.SYN) {
			if Sequence(p.TCP.Ack).Difference(*nextAckPtr) != 0 {
				log.Print("LAST-ACK: out of order ACK packet received. seq %d != nextAck %d\n", p.TCP.Ack, *nextAckPtr)
				return
			}
			c.Close()
		} else {
			log.Print("LAST-ACK: protocol anamoly\n")
		}
	} else {
		log.Print("LAST-ACK: out of order packet received\n")
		log.Printf("LAST-ACK: out of order packet received; got %d expected %d\n", p.TCP.Seq, *nextSeqPtr)
	}
}

// stateConnectionClosing handles all the closing states until the closed state has been reached.
func (c *Connection) stateConnectionClosing(p PacketManifest) {
	var nextSeqPtr *Sequence
	var nextAckPtr *Sequence
	var statePtr, otherStatePtr *uint8
	if p.Flow.Equal(c.closingFlow) {
		if c.clientFlow.Equal(p.Flow) {
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
			c.stateLastAck(p, p.Flow, nextSeqPtr, nextAckPtr, statePtr)
		}
	} else {
		if c.clientFlow.Equal(p.Flow) {
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
			c.stateFinWait1(p, p.Flow, nextSeqPtr, nextAckPtr, statePtr, otherStatePtr)
		case TCP_FIN_WAIT2:
			c.stateFinWait2(p, p.Flow, nextSeqPtr, nextAckPtr, statePtr)
		case TCP_TIME_WAIT:
			c.stateTimeWait(p)
		case TCP_CLOSING:
			c.stateClosing(p)
		}
	}
}

func (c *Connection) receivePacket(p *PacketManifest) {
	c.receiveChan <- p
}

// startReceivingPackets implements a TCP finite state machine
// which is loosely based off of the simplified FSM in this paper:
// http://ants.iis.sinica.edu.tw/3bkmj9ltewxtsrrvnoknfdxrm3zfwrr/17/p520460.pdf
// The goal is to detect all manner of content injection.
func (c *Connection) startReceivingPackets() {
	for {
		select {
		case <-c.stopChan:
			return
		case p := <-c.receiveChan:
			if c.lastSeen.Before(p.Timestamp) {
				c.lastSeen = p.Timestamp
			}
			if c.PacketLogger != nil {
				c.PacketLogger.WritePacket(p.RawPacket, p.Timestamp)
			}
			c.packetCount += 1
			switch c.state {
			case TCP_UNKNOWN:
				c.stateUnknown(*p)
			case TCP_CONNECTION_REQUEST:
				c.stateConnectionRequest(*p)
			case TCP_CONNECTION_ESTABLISHED:
				c.stateConnectionEstablished(*p)
			case TCP_DATA_TRANSFER:
				c.stateDataTransfer(*p)
			case TCP_CONNECTION_CLOSING:
				c.stateConnectionClosing(*p)
			}
		}
	}
}
