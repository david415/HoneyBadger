package HoneyBadger

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"code.google.com/p/gopacket/tcpassembly"
	"container/ring"
	"fmt"
	"log"
)

const (
	invalidSequence   = -1
	MAX_CONN_PACKETS  = 1000
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

// TcpBidirectionalFlow struct can be used as a hashmap key.
// Bidirectional in this case means that an instance of this
// struct can be used to match either unidirectional flow
// from a given TCP connection.
type TcpBidirectionalFlow struct {
	flow TcpIpFlow
}

// PacketManifest is used to send parsed packets via channels to other goroutines
type PacketManifest struct {
	IP      layers.IPv4
	TCP     layers.TCP
	Payload gopacket.Payload
}

// Reassembly is inspired by gopacket.tcpassembly this struct can be used
// to represent ordered segments of a TCP stream... currently not used.
type Reassembly struct {
	PacketManifest PacketManifest
	Skip           int
	Start          bool
	End            bool
}

// Connection is used to track client and server flows for a given TCP connection.
// Currently Connection is being used to track TCP handshake states and detect handshake hijack...
// but it could be used for other things too like stream reassembly and detecting other TCP attacks.
type Connection struct {
	state         uint8
	clientState   uint8
	serverState   uint8
	clientFlow    TcpIpFlow
	serverFlow    TcpIpFlow
	closingFlow   TcpIpFlow
	clientNextSeq tcpassembly.Sequence
	serverNextSeq tcpassembly.Sequence
	hijackNextAck tcpassembly.Sequence
	head          *ring.Ring
	current       *ring.Ring
	packetCount   uint64
}

// NewConnection returns a new Connection struct
func NewConnection() Connection {
	return Connection{
		head:    nil,
		current: ring.New(MAX_CONN_PACKETS),
		state:   TCP_LISTEN,
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

func (c *Connection) stateConnectionEstablished(p PacketManifest, flow TcpIpFlow) {
	if c.isHijack(p, flow) {
		log.Print("handshake hijack detected\n")
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
	if tcpassembly.Sequence(p.TCP.Seq).Difference(*nextSeqPtr) == 0 {
		*nextSeqPtr = tcpassembly.Sequence(p.TCP.Seq).Add(len(p.Payload)) // XXX
		log.Printf("expected tcp Sequence from client; payload len %d\n", len(p.Payload))

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
		}
	} else {
		log.Print("unexpected tcp Sequence from client\n")
	}
}

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
// Currently we detect TCP handshake hijack. But soon we'll be doing
// retrospective analysis on reassembled stream segments to detect
// TCP segment veto attacks and other stream injection attacks.
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

// ConnTracker is used to track TCP connections
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
