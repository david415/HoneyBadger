/*
 *    service.go - HoneyBadger core library for detecting TCP attacks
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
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"io"
	"log"
	"time"
)

type TimedRawPacket struct {
	Timestamp time.Time
	RawPacket []byte
}

// InquisitorOptions are user set parameters for specifying the
// details of how to proceed with honey_bager's TCP connection monitoring.
// More parameters should soon be added here!
type InquisitorOptions struct {
	Interface             string
	Filename              string
	WireDuration          time.Duration
	BufferedPerConnection int
	BufferedTotal         int
	Filter                string
	LogDir                string
	Snaplen               int
	PacketLog             bool
	StreamLog             bool
	TcpIdleTimeout        time.Duration
}

// Inquisitor sets up the connection pool and is an abstraction layer for dealing
// with incoming packets weather they be from a pcap file or directly off the wire.
type Inquisitor struct {
	InquisitorOptions
	stopCaptureChan     chan bool
	decodePacketChan    chan TimedRawPacket
	stopDecodeChan      chan bool
	dispatchPacketChan  chan PacketManifest
	stopDispatchChan    chan bool
	closeConnectionChan chan CloseRequest
	connPool            *ConnectionPool
	handle              *pcap.Handle
	pager               *Pager
	AttackLogger        AttackLogger
}

// NewInquisitor creates a new Inquisitor struct
func NewInquisitor(options *InquisitorOptions) *Inquisitor {
	i := Inquisitor{
		InquisitorOptions:   *options,
		stopCaptureChan:     make(chan bool),
		decodePacketChan:    make(chan TimedRawPacket),
		stopDecodeChan:      make(chan bool),
		dispatchPacketChan:  make(chan PacketManifest),
		stopDispatchChan:    make(chan bool),
		closeConnectionChan: make(chan CloseRequest),

		pager:        NewPager(),
		connPool:     NewConnectionPool(),
		AttackLogger: NewAttackJsonLogger(options.LogDir),
	}
	return &i
}

// Start... starts the TCP attack inquisition!
func (i *Inquisitor) Start() {
	if i.handle == nil {
		i.setupHandle()
	}
	go i.capturePackets()  // stopCaptureChan
	go i.decodePackets()   // stopDecodeChan decodePacketChan
	go i.dispatchPackets() // stopDispatchChan dispatchPacketChan
	i.pager.Start()
	i.AttackLogger.Start()
}

// Stop... stops the TCP attack inquisition!
func (i *Inquisitor) Stop() {
	i.stopDispatchChan <- true
	i.stopDecodeChan <- true
	i.stopCaptureChan <- true
	i.AttackLogger.Stop()
	i.handle.Close()
	i.pager.Stop()
}

func (i *Inquisitor) setupHandle() {
	var err error
	if i.Filename != "" {
		log.Printf("Reading from pcap dump %q", i.Filename)
		i.handle, err = pcap.OpenOffline(i.Filename)
	} else {
		log.Printf("Starting capture on interface %q", i.Interface)
		i.handle, err = pcap.OpenLive(i.Interface, int32(i.Snaplen), true, i.WireDuration)
	}
	if err != nil {
		log.Fatal(err)
	}
	if err = i.handle.SetBPFFilter(i.Filter); err != nil {
		log.Fatal(err)
	}
}

func (i *Inquisitor) capturePackets() {
	for {
		select {
		case <-i.stopCaptureChan:
			return
		default:
			rawPacket, captureInfo, err := i.handle.ReadPacketData()
			if err == io.EOF {
				log.Print("ReadPacketData got EOF\n")
				i.Stop()
				return
			}
			if err != nil {
				continue
			}
			i.decodePacketChan <- TimedRawPacket{
				Timestamp: captureInfo.Timestamp,
				RawPacket: rawPacket,
			}
		}
	}
}

func (i *Inquisitor) decodePackets() {
	var eth layers.Ethernet
	var ip layers.IPv4
	var tcp layers.TCP
	var payload gopacket.Payload

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip, &tcp, &payload)
	decoded := make([]gopacket.LayerType, 0, 4)

	for {
		select {
		case <-i.stopDecodeChan:
			return
		case timedRawPacket := <-i.decodePacketChan:
			newPayload := new(gopacket.Payload)
			payload = *newPayload
			err := parser.DecodeLayers(timedRawPacket.RawPacket, &decoded)
			if err != nil {
				continue
			}
			flow := NewTcpIpFlowFromFlows(ip.NetworkFlow(), tcp.TransportFlow())
			packetManifest := PacketManifest{
				Timestamp: timedRawPacket.Timestamp,
				Flow:      flow,
				RawPacket: timedRawPacket.RawPacket,
				IP:        ip,
				TCP:       tcp,
				Payload:   payload,
			}
			i.dispatchPacketChan <- packetManifest
		}
	}
}

func (i *Inquisitor) setupNewConnection(flow TcpIpFlow) *Connection {
	conn := NewConnection(i.closeConnectionChan, i.pager, i.InquisitorOptions.BufferedPerConnection, i.InquisitorOptions.BufferedTotal)
	conn.AttackLogger = i.AttackLogger
	if i.PacketLog {
		conn.PacketLogger = NewPcapLogger(i.LogDir, flow)
		conn.PacketLogger.Start()
	}
	if i.StreamLog {
		clientStream := NewStreamLogger(i.LogDir, flow)
		clientStream.Start()
		conn.ClientStream = clientStream
		serverStream := NewStreamLogger(i.LogDir, flow.Reverse())
		serverStream.Start()
		conn.ServerStream = serverStream
	}
	i.connPool.Put(flow, conn)
	conn.Start(true)
	return conn
}

func (i *Inquisitor) dispatchPackets() {
	var conn *Connection
	var err error
	timeout := i.InquisitorOptions.TcpIdleTimeout
	ticker := time.Tick(timeout)
	var lastTimestamp time.Time
	for {
		select {
		case <-ticker:
			if !lastTimestamp.IsZero() {
				log.Printf("lastTimestamp is %s\n", lastTimestamp)
				lastTimestamp = lastTimestamp.Add(timeout)
				closed := i.connPool.CloseOlderThan(lastTimestamp)
				if closed != 0 {
					log.Printf("timeout closed %d connections\n", closed)
				}
			}
		case <-i.stopDispatchChan:
			return
		case closeRequest := <-i.closeConnectionChan:
			i.connPool.Delete(*closeRequest.Flow)
			closeRequest.CloseReadyChan <- true
		case packetManifest := <-i.dispatchPacketChan:
			if i.connPool.Has(packetManifest.Flow) {
				conn, err = i.connPool.Get(packetManifest.Flow)
				if err != nil {
					panic(err) // wtf
				}
			} else {
				conn = i.setupNewConnection(packetManifest.Flow)
			}
			conn.receivePacket(&packetManifest)
		}
	}
}
