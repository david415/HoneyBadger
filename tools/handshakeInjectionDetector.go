// detector for tcp handshake injections
// author David Stainton
// Copyright 2014 David Stainton
// inspired by Graeme Connel's gopacket.tcpassembly
//

package main

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"code.google.com/p/gopacket/tcpassembly"
	"container/ring"
	"flag"
	"log"
)

const (
	MAX_CONN_PACKETS = 1000
	invalidSequence  = -1
	TCP_UNKNOWN      = 0
	TCP_SYN          = 1
	TCP_SYNACK       = 2
	TCP_ACK          = 3
	TCP_CONNECTED    = 4
)

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

func (t *TcpIpFlow) Reverse() TcpIpFlow {
	return NewTcpIpFlowFromFlows(t.ipFlow.Reverse(), t.tcpFlow.Reverse())
}

func (t *TcpIpFlow) Equal(s TcpIpFlow) bool {
	return t.ipFlow == s.ipFlow && t.tcpFlow == s.tcpFlow
}

// getPacketFlow returns a tcp/ip flowKey
// given a byte array packet
func NewTcpIpFlowFromPacket(packet []byte) (TcpIpFlow, error) {
	var ip layers.IPv4
	var tcp layers.TCP
	decoded := []gopacket.LayerType{}
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip, &tcp)
	err := parser.DecodeLayers(packet, &decoded)
	if err != nil {
		return TcpIpFlow{}, err
	}
	return TcpIpFlow{
		ipFlow:  ip.NetworkFlow(),
		tcpFlow: tcp.TransportFlow(),
	}, nil
}

// Layers returns the component flow structs IPv4, TCP
func (t *TcpIpFlow) Layers() (gopacket.Flow, gopacket.Flow) {
	return t.ipFlow, t.tcpFlow
}

// TcpBidirectionalFlow struct can be used as a hashmap key.
// Bidirectional in this case means that each of these keys
// for each TCP connection can be represented by two TcpFlow`s
type TcpBidirectionalFlow struct {
	flow TcpIpFlow
}

// NewTcpBidirectionalFlowFromTcpIpFlow takes a TcpIpFlow argument
// and returns a TcpBidirectionalFlow
// XXX can we please have short names for things? What should we rename it to?
func NewTcpBidirectionalFlowFromTcpIpFlow(tcpipFlow TcpIpFlow) TcpBidirectionalFlow {
	var tcpSrc, tcpDst, ipSrcEnd, ipDstEnd gopacket.Endpoint

	ipflow, tcpflow := tcpipFlow.Layers()
	srcIP, dstIP := ipflow.Endpoints()
	if srcIP.LessThan(dstIP) {
		ipSrcEnd = srcIP
		ipDstEnd = dstIP
	} else {
		ipSrcEnd = dstIP
		ipDstEnd = srcIP
	}
	ipFlow, _ := gopacket.FlowFromEndpoints(ipSrcEnd, ipDstEnd)

	srcPortEnd, dstPortEnd := tcpflow.Endpoints()
	if srcPortEnd.LessThan(dstPortEnd) {
		tcpSrc = srcPortEnd
		tcpDst = dstPortEnd
	} else {
		tcpSrc = dstPortEnd
		tcpDst = srcPortEnd
	}
	tcpFlow, _ := gopacket.FlowFromEndpoints(tcpSrc, tcpDst)

	return TcpBidirectionalFlow{
		flow: TcpIpFlow{
			ipFlow:  ipFlow,
			tcpFlow: tcpFlow,
		},
	}
}

func (f *TcpBidirectionalFlow) Get() TcpIpFlow {
	return f.flow
}

type PacketManifest struct {
	IP      layers.IPv4
	TCP     layers.TCP
	Payload gopacket.Payload
}

type Reassembly struct {
	PacketManifest PacketManifest
	Skip           int
	Start          bool
	End            bool
}

type Connection struct {
	state         uint8
	clientFlow    TcpIpFlow
	serverFlow    TcpIpFlow
	clientNextSeq tcpassembly.Sequence
	serverNextSeq tcpassembly.Sequence
	hijackNextAck tcpassembly.Sequence
	head          *ring.Ring
	current       *ring.Ring
}

func NewConnection() Connection {
	return Connection{
		head:    nil,
		current: ring.New(MAX_CONN_PACKETS),
		state:   TCP_UNKNOWN,
	}
}

// check for duplicate SYN/ACK indicating handshake hijake
// XXX todo: make compatible with ipv6
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

func (c *Connection) receivePacket(p PacketManifest, flow TcpIpFlow) {
	switch c.state {
	case TCP_UNKNOWN:
		if p.TCP.SYN && !p.TCP.ACK {
			log.Print("SYN\n")
			c.state = TCP_SYN
			c.clientFlow = flow
			c.serverFlow = c.clientFlow.Reverse()
			c.clientNextSeq = tcpassembly.Sequence(p.TCP.Seq).Add(len(p.Payload) + 1) // XXX
			c.hijackNextAck = c.clientNextSeq
		} else {
			log.Print("unknown TCP state\n")
		}
	case TCP_SYN:
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
		log.Print("SYN/ACK\n")
		c.state = TCP_SYNACK
		c.serverNextSeq = tcpassembly.Sequence(p.TCP.Seq).Add(len(p.Payload) + 1) // XXX
	case TCP_SYNACK:
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
		c.state = TCP_CONNECTED
		log.Print("connected\n")
	case TCP_CONNECTED:
		if c.isHijack(p, flow) {
			log.Print("handshake hijack detected\n")
			return
		}

		if flow.Equal(c.clientFlow) {
			if tcpassembly.Sequence(p.TCP.Seq).Difference(c.clientNextSeq) == 0 {
				log.Printf("expected tcp Sequence from client; payload len %d\n", len(p.Payload))
				c.clientNextSeq = tcpassembly.Sequence(p.TCP.Seq).Add(len(p.Payload)) // XXX
			} else {
				log.Print("unexpected tcp Sequence from client\n")
			}
			return
		}
		if flow.Equal(c.serverFlow) {
			if tcpassembly.Sequence(p.TCP.Seq).Difference(c.serverNextSeq) == 0 {
				log.Printf("expected tcp Sequence from server; payload len %d\n", len(p.Payload))
				c.serverNextSeq = tcpassembly.Sequence(p.TCP.Seq).Add(len(p.Payload)) // XXX
			} else {
				log.Print("unexpected tcp Sequence from server; payload: %s\n", string(p.Payload))
			}
			return
		}
	}
}

type ConnTracker struct {
	connectionMap map[TcpBidirectionalFlow]*Connection
}

func NewConnTracker() *ConnTracker {
	return &ConnTracker{
		connectionMap: make(map[TcpBidirectionalFlow]*Connection),
	}
}

func (c *ConnTracker) Has(key TcpBidirectionalFlow) bool {
	_, ok := c.connectionMap[key]
	return ok
}

func (c *ConnTracker) Get(key TcpBidirectionalFlow) *Connection {
	return c.connectionMap[key]
}

func (c *ConnTracker) Put(key TcpBidirectionalFlow, conn *Connection) {
	c.connectionMap[key] = conn
}

func startReceivingTcp(filter, iface string, snaplen int) (chan bool, chan []byte) {

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

func startDecodingTcp(packetChan chan []byte, connTracker *ConnTracker) {
	stopDecodeChan := make(chan bool)
	go decodeTcp(packetChan, connTracker, stopDecodeChan)
}

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
			connKey := NewTcpBidirectionalFlowFromTcpIpFlow(tcpipflow)
			packetManifest := PacketManifest{
				IP:      ip,
				TCP:     tcp,
				Payload: payload,
			}
			if connTracker.Has(connKey) {
				conn := connTracker.Get(connKey)
				conn.receivePacket(packetManifest, tcpipflow)
			} else {
				conn := NewConnection()
				connTracker.Put(connKey, &conn)
				conn.receivePacket(packetManifest, tcpipflow)
			}
		case <-stopDecodeChan:
			return
		}
	}
}

func main() {
	var (
		iface   = flag.String("i", "eth0", "Interface to get packets from")
		snaplen = flag.Int("s", 65536, "SnapLen for pcap packet capture")
		filter  = flag.String("f", "tcp", "BPF filter for pcap")
	)
	flag.Parse()

	connTracker := NewConnTracker()
	stopChan, packetChan := startReceivingTcp(*filter, *iface, *snaplen)
	startDecodingTcp(packetChan, connTracker)
	<-stopChan
}
