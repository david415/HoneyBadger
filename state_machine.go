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
	"github.com/david415/HoneyBadger/logging"
	"github.com/david415/HoneyBadger/types"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
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
	TCP_INVALID                = 5

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
	Flow      *types.TcpIpFlow
	RawPacket []byte
	IP        layers.IPv4
	TCP       layers.TCP
	Payload   gopacket.Payload
}

type CloseRequest struct {
	Flow           *types.TcpIpFlow
	CloseReadyChan chan bool
}

type ConnectionOptions struct {
	MaxBufferedPagesTotal         int
	MaxBufferedPagesPerConnection int
	MaxRingPackets                int
	CloseRequestChan              chan CloseRequest
	Pager                         *Pager
	LogDir                        string
	AttackLogger                  types.Logger
}

// Connection is used to track client and server flows for a given TCP connection.
// We implement a basic TCP finite state machine and track state in order to detect
// hanshake hijack and other TCP attacks such as segment veto and sloppy injection.
type Connection struct {
	ConnectionOptions
	attackDetected            bool
	closeRequestChanListening bool
	stopChan                  chan bool
	receiveChan               chan *PacketManifest
	packetCount               uint64
	lastSeen                  time.Time
	lastSeenMutex             sync.Mutex
	state                     uint8
	clientState               uint8
	serverState               uint8
	clientFlow                *types.TcpIpFlow
	serverFlow                *types.TcpIpFlow
	closingFlow               *types.TcpIpFlow
	clientNextSeq             types.Sequence
	serverNextSeq             types.Sequence
	hijackNextAck             types.Sequence
	firstSynAckSeq            uint32
	ClientStreamRing          *ring.Ring
	ServerStreamRing          *ring.Ring
	ClientCoalesce            *OrderedCoalesce
	ServerCoalesce            *OrderedCoalesce
	ClientReassembly          []types.Reassembly
	ServerReassembly          []types.Reassembly
	PacketLogger              *logging.PcapLogger
}

// NewConnection returns a new Connection struct
func NewConnection(options *ConnectionOptions) *Connection {
	conn := Connection{
		ConnectionOptions: *options,
		attackDetected:    false,
		stopChan:          make(chan bool),
		receiveChan:       make(chan *PacketManifest),
		state:             TCP_UNKNOWN,
		clientNextSeq:     types.InvalidSequence,
		serverNextSeq:     types.InvalidSequence,
		ClientStreamRing:  ring.New(options.MaxRingPackets),
		ServerStreamRing:  ring.New(options.MaxRingPackets),
		ClientReassembly:  make([]types.Reassembly, 0),
		ServerReassembly:  make([]types.Reassembly, 0),
	}

	conn.ClientCoalesce = NewOrderedCoalesce(conn.AttackLogger, conn.ClientReassembly, conn.clientFlow, conn.Pager, conn.ClientStreamRing, conn.MaxBufferedPagesTotal, conn.MaxBufferedPagesPerConnection/2)
	conn.ServerCoalesce = NewOrderedCoalesce(conn.AttackLogger, conn.ServerReassembly, conn.serverFlow, conn.Pager, conn.ServerStreamRing, conn.MaxBufferedPagesTotal, conn.MaxBufferedPagesPerConnection/2)

	return &conn
}

// getLastSeen returns the lastSeen timestamp after grabbing the lock
func (c *Connection) getLastSeen() time.Time {
	c.lastSeenMutex.Lock()
	defer c.lastSeenMutex.Unlock()
	return c.lastSeen
}

// updateLastSeen updates our lastSeen with the new timestamp after grabbing the lock
func (c *Connection) updateLastSeen(timestamp time.Time) {
	c.lastSeenMutex.Lock()
	defer c.lastSeenMutex.Unlock()
	if c.lastSeen.Before(timestamp) {
		c.lastSeen = timestamp
	}
}

// Close is used by the Connection to shutdown itself.
// Firstly it removes it's entry from the connection pool...
// if CloseRequestChanListening is set to true.
// After that Stop is called.
func (c *Connection) Close() {
	log.Printf("close detected for %s\n", c.clientFlow.String())

	if c.closeRequestChanListening {
		closeReadyChan := make(chan bool)
		// remove Connection from ConnectionPool
		c.CloseRequestChan <- CloseRequest{
			Flow:           c.clientFlow,
			CloseReadyChan: closeReadyChan,
		}
		<-closeReadyChan
	}
	c.Stop()
}

// Start is used to start the packet receiving goroutine for
// this connection... closeRequestChanListening shall be set to
// false for many of the TCP FSM unit tests.
func (c *Connection) Start(closeRequestChanListening bool) {
	c.closeRequestChanListening = closeRequestChanListening
	go c.startReceivingPackets()
}

// Stop frees up all resources used by the connection
func (c *Connection) Stop() {
	log.Print("Connection.Stop() called.\n")
	log.Printf("stopped tracking %s\n", c.clientFlow.String())
	c.stopChan <- true
	log.Print("checking attack detection status\n")
	if c.attackDetected == false {
		c.removeAllLogs()
	} else {
		log.Print("not removing logs. attack detected.\n")
	}
	c.ClientCoalesce.Close()
	c.ServerCoalesce.Close()
}

// removeAllLogs removes all the logs associated with this Connection instance
func (c *Connection) removeAllLogs() {
	log.Printf("removeAllLogs %s\n", c.clientFlow.String())
	os.Remove(filepath.Join(c.LogDir, fmt.Sprintf("%s.pcap", c.clientFlow)))
	os.Remove(filepath.Join(c.LogDir, fmt.Sprintf("%s.pcap", c.serverFlow)))
	os.Remove(filepath.Join(c.LogDir, fmt.Sprintf("%s.attackreport.json", c.clientFlow)))
	os.Remove(filepath.Join(c.LogDir, fmt.Sprintf("%s.attackreport.json", c.serverFlow)))
}

// detectHijack checks for duplicate SYN/ACK indicating handshake hijake
// and submits a report if an attack was observed
func (c *Connection) detectHijack(p PacketManifest, flow *types.TcpIpFlow) {
	// check for duplicate SYN/ACK indicating handshake hijake
	if !flow.Equal(c.serverFlow) {
		return
	}
	if p.TCP.ACK && p.TCP.SYN {
		if types.Sequence(p.TCP.Ack).Difference(c.hijackNextAck) == 0 {
			if p.TCP.Seq != c.firstSynAckSeq {
				log.Print("handshake hijack detected\n")
				c.AttackLogger.Log(&types.Event{Time: time.Now(), Flow: flow, HijackSeq: p.TCP.Seq, HijackAck: p.TCP.Ack})
				c.attackDetected = true
			} else {
				log.Print("SYN/ACK retransmission\n")
			}
		}
	}
}

// getOverlapRings returns the head and tail ring elements corresponding to the first and last
// overlapping ring segments... that overlap with the given packet (PacketManifest).
func (c *Connection) getOverlapRings(p PacketManifest, flow *types.TcpIpFlow) (*ring.Ring, *ring.Ring) {
	var ringPtr, head, tail *ring.Ring
	start := types.Sequence(p.TCP.Seq)
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
func (c *Connection) getOverlapBytes(head, tail *ring.Ring, start, end types.Sequence) ([]byte, int, int) {
	var overlapStartSlice, overlapEndSlice int
	var overlapBytes []byte
	if head == nil || tail == nil {
		panic("wtf; head or tail is nil\n")
	}
	sequenceStart, overlapStartSlice := getStartOverlapSequenceAndOffset(head, start)
	headOffset := getHeadRingOffset(head, sequenceStart)

	sequenceEnd, overlapEndOffset := getEndOverlapSequenceAndOffset(tail, end)
	tailOffset := getTailRingOffset(tail, sequenceEnd)

	if int(head.Value.(types.Reassembly).Seq) == int(tail.Value.(types.Reassembly).Seq) {
		endOffset := len(head.Value.(types.Reassembly).Bytes) - tailOffset
		overlapEndSlice = len(head.Value.(types.Reassembly).Bytes) - tailOffset + overlapStartSlice - headOffset
		overlapBytes = head.Value.(types.Reassembly).Bytes[headOffset:endOffset]
	} else {
		totalLen := start.Difference(end) + 1
		overlapEndSlice = totalLen - overlapEndOffset
		tailSlice := len(tail.Value.(types.Reassembly).Bytes) - tailOffset
		overlapBytes = getRingSlice(head, tail, headOffset, tailSlice)
	}
	return overlapBytes, overlapStartSlice, overlapEndSlice
}

// detectInjection write an attack report if the given packet indicates a TCP injection attack
// such as segment veto.
func (c *Connection) detectInjection(p PacketManifest, flow *types.TcpIpFlow) {
	head, tail := c.getOverlapRings(p, flow)
	if head == nil || tail == nil {
		return
	}
	start := types.Sequence(p.TCP.Seq)
	end := start.Add(len(p.Payload) - 1)
	overlapBytes, startOffset, endOffset := c.getOverlapBytes(head, tail, start, end)
	if !bytes.Equal(overlapBytes, p.Payload[startOffset:endOffset]) {
		log.Print("injection attack detected\n")
		e := &types.Event{
			Type:          "injection",
			Time:          time.Now(),
			Flow:          flow,
			Payload:       p.Payload,
			Overlap:       overlapBytes,
			StartSequence: start,
			EndSequence:   end,
			OverlapStart:  startOffset,
			OverlapEnd:    endOffset,
		}

		c.AttackLogger.Log(e)
		c.attackDetected = true
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
		c.clientFlow = p.Flow
		c.serverFlow = p.Flow.Reverse()

		// Note that TCP SYN and SYN/ACK packets may contain payload data if
		// a TCP extension is used...
		// If so then the sequence number needs to track this payload.
		// For more information see: https://tools.ietf.org/id/draft-agl-tcpm-sadata-00.html
		c.clientNextSeq = types.Sequence(p.TCP.Seq).Add(len(p.Payload) + 1) // XXX
		c.hijackNextAck = c.clientNextSeq

	} else {
		// else process a connection after handshake
		c.state = TCP_DATA_TRANSFER
		c.clientFlow = p.Flow
		c.serverFlow = p.Flow.Reverse()
		c.packetCount = FIRST_FEW_PACKETS // skip handshake hijack detection
		c.clientNextSeq = c.ServerCoalesce.insert(p, c.clientNextSeq)
	}
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
	if c.clientNextSeq.Difference(types.Sequence(p.TCP.Ack)) != 0 {
		//handshake anomaly
		return
	}
	c.state = TCP_CONNECTION_ESTABLISHED
	c.serverNextSeq = types.Sequence(p.TCP.Seq).Add(len(p.Payload) + 1) // XXX see above comment about TCP extentions
	c.firstSynAckSeq = p.TCP.Seq
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
	if types.Sequence(p.TCP.Seq).Difference(c.clientNextSeq) != 0 {
		// handshake anomaly
		return
	}
	if types.Sequence(p.TCP.Ack).Difference(c.serverNextSeq) != 0 {
		// handshake anomaly
		return
	}
	c.state = TCP_DATA_TRANSFER
	log.Printf("connected %s\n", c.clientFlow.String())
}

// stateDataTransfer is called by our TCP FSM and processes packets
// once we are in the TCP_DATA_TRANSFER state
func (c *Connection) stateDataTransfer(p PacketManifest) {
	var nextSeqPtr *types.Sequence
	var closerState, remoteState *uint8

	if c.clientNextSeq == types.InvalidSequence && p.Flow.Equal(c.clientFlow) {
		c.clientNextSeq = c.ServerCoalesce.insert(p, c.clientNextSeq)
		return
	} else if c.serverNextSeq == types.InvalidSequence && p.Flow.Equal(c.serverFlow) {
		c.serverNextSeq = c.ClientCoalesce.insert(p, c.serverNextSeq)
		return
	}

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
	diff := types.Sequence(p.TCP.Seq).Difference(*nextSeqPtr)
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
		// XXX TODO: check for RST in the other states as well...
		if p.TCP.RST {
			log.Print("got RST!\n")
		}
		if len(p.Payload) > 0 {
			reassembly := types.Reassembly{
				Seq:   types.Sequence(p.TCP.Seq),
				Bytes: []byte(p.Payload),
				Seen:  p.Timestamp,
				End:   p.TCP.RST,
			}

			if p.Flow.Equal(c.clientFlow) {
				c.ServerReassembly = append(c.ServerReassembly, reassembly)
				c.ServerStreamRing.Value = reassembly
				c.ServerStreamRing = c.ServerStreamRing.Next()
			} else {
				c.ClientReassembly = append(c.ClientReassembly, reassembly)
				c.ClientStreamRing.Value = reassembly
				c.ClientStreamRing = c.ClientStreamRing.Next()
			}
			*nextSeqPtr = types.Sequence(p.TCP.Seq).Add(len(p.Payload)) // XXX
		}
	} else if diff < 0 {
		// p.TCP.Seq comes after *nextSeqPtr
		// future-out-of-order packet case
		if len(p.Payload) > 0 {
			if p.Flow.Equal(c.clientFlow) {
				c.clientNextSeq = c.ServerCoalesce.insert(p, c.clientNextSeq)
			} else {
				c.serverNextSeq = c.ClientCoalesce.insert(p, c.serverNextSeq)
			}
		}
	}
}

// stateFinWait1 handles packets for the FIN-WAIT-1 state
func (c *Connection) stateFinWait1(p PacketManifest, flow *types.TcpIpFlow, nextSeqPtr *types.Sequence, nextAckPtr *types.Sequence, statePtr, otherStatePtr *uint8) {
	if types.Sequence(p.TCP.Seq).Difference(*nextSeqPtr) != 0 {
		log.Printf("FIN-WAIT-1: out of order packet received. sequence %d != nextSeq %d\n", p.TCP.Seq, *nextSeqPtr)
		return
	}
	if p.TCP.ACK {
		if types.Sequence(p.TCP.Ack).Difference(*nextAckPtr) != 0 { //XXX
			log.Printf("FIN-WAIT-1: unexpected ACK: got %d expected %d\n", p.TCP.Ack, *nextAckPtr)
			return
		}
		if p.TCP.FIN {
			*statePtr = TCP_CLOSING
			*otherStatePtr = TCP_LAST_ACK
			*nextSeqPtr = types.Sequence(p.TCP.Seq).Add(len(p.Payload) + 1)
		} else {
			*statePtr = TCP_FIN_WAIT2
		}
	} else {
		log.Print("FIN-WAIT-1: non-ACK packet received.\n")
	}
}

// stateFinWait1 handles packets for the FIN-WAIT-2 state
func (c *Connection) stateFinWait2(p PacketManifest, flow *types.TcpIpFlow, nextSeqPtr *types.Sequence, nextAckPtr *types.Sequence, statePtr *uint8) {
	if types.Sequence(p.TCP.Seq).Difference(*nextSeqPtr) == 0 {
		if p.TCP.ACK && p.TCP.FIN {
			if types.Sequence(p.TCP.Ack).Difference(*nextAckPtr) != 0 {
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
	flow := types.NewTcpIpFlowFromLayers(p.IP, p.TCP)
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
func (c *Connection) stateLastAck(p PacketManifest, flow *types.TcpIpFlow, nextSeqPtr *types.Sequence, nextAckPtr *types.Sequence, statePtr *uint8) {
	if types.Sequence(p.TCP.Seq).Difference(*nextSeqPtr) == 0 { //XXX
		if p.TCP.ACK && (!p.TCP.FIN && !p.TCP.SYN) {
			if types.Sequence(p.TCP.Ack).Difference(*nextAckPtr) != 0 {
				log.Printf("LAST-ACK: out of order ACK packet received. seq %d != nextAck %d\n", p.TCP.Ack, *nextAckPtr)
				return
			}
			reassembly := types.Reassembly{
				Seq:   types.Sequence(p.TCP.Seq),
				Bytes: []byte(p.Payload),
				Seen:  p.Timestamp,
				End:   true,
			}
			if p.Flow.Equal(c.clientFlow) {
				c.ServerReassembly = append(c.ServerReassembly, reassembly)
			} else {
				c.ClientReassembly = append(c.ClientReassembly, reassembly)
			}
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
	var nextSeqPtr *types.Sequence
	var nextAckPtr *types.Sequence
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

func (c *Connection) ReceivePacket(p *PacketManifest) {
	c.receiveChan <- p
}

// receivePacketState implements a TCP finite state machine
// which is loosely based off of the simplified FSM in this paper:
// http://ants.iis.sinica.edu.tw/3bkmj9ltewxtsrrvnoknfdxrm3zfwrr/17/p520460.pdf
// The goal is to detect all manner of content injection.
func (c *Connection) receivePacketState(p *PacketManifest) {
	c.updateLastSeen(p.Timestamp)

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

	if p.Flow.Equal(c.serverFlow) {
		if len(c.ClientReassembly) > 0 {
			c.serverNextSeq = c.sendToStream(c.ClientReassembly, c.serverNextSeq, c.ClientCoalesce)
		}
	} else {
		if len(c.ServerReassembly) > 0 {
			c.clientNextSeq = c.sendToStream(c.ServerReassembly, c.clientNextSeq, c.ServerCoalesce)
		}
	}
	c.ClientReassembly = make([]types.Reassembly, 0)
	c.ServerReassembly = make([]types.Reassembly, 0)
}

func (c *Connection) startReceivingPackets() {
	for {
		select {
		case <-c.stopChan:
			log.Print("stopChan signaled\n")
			return
		case p := <-c.receiveChan:
			c.receivePacketState(p)
		}
	}
}

// sendToStream send the current values in ret to the stream-ring-buffer
// closing the connection if the last thing sent had End set.
func (c *Connection) sendToStream(ret []types.Reassembly, nextSeq types.Sequence, coalesce *OrderedCoalesce) types.Sequence {
	nextSeq = coalesce.addContiguous(nextSeq)
	if ret[len(ret)-1].End {
		go c.Close()
	}
	return nextSeq
}
