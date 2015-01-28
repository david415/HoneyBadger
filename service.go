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
	"log"
	"time"
)

type HoneyBadgerServiceOptions struct {
	Interface    string
	WireDuration time.Duration
	Filter       string
	LogDir       string
	Snaplen      int
}

type HoneyBadgerService struct {
	HoneyBadgerServiceOptions
	stopChan      chan bool
	rawPacketChan chan []byte
	connTracker   *ConnTracker
}

// NewHoneyBadgerService creates and starts an instance of HoneyBadgerService
// which passively observes TCP connections and logs information about observed TCP attacks.
// `iface` specifies the network interface to watch.
// The `filter` arguement is a Berkeley Packet Filter string; observe packets that match this filter.
// `snaplen` is the max packet size.
// `logDir` is the directory to write logs to.
func NewHoneyBadgerService(iface string, wireDuration time.Duration, filter string, snaplen int, logDir string) *HoneyBadgerService {
	service := HoneyBadgerService{
		HoneyBadgerServiceOptions: HoneyBadgerServiceOptions{
			Interface:    iface,
			WireDuration: wireDuration,
			Filter:       filter,
			Snaplen:      snaplen,
			LogDir:       logDir,
		},
		connTracker:   NewConnTracker(),
		stopChan:      make(chan bool),
		rawPacketChan: make(chan []byte),
	}
	return &service
}

// Start the HoneyBadgerService
func (b *HoneyBadgerService) Start() {
	b.StartReceivingTcp()
	b.StartDecodingTcp()
}

// Stop the HoneyBadgerService
func (b *HoneyBadgerService) Stop() {
	b.stopChan <- true
	close(b.rawPacketChan)
	b.connTracker.Close()
	close(b.stopChan)
}

// startDecodingTcp calls decodeTcp in a new goroutine...
func (b *HoneyBadgerService) StartDecodingTcp() {
	go b.decodeTcp()
}

// decodeTcp receives packets from a channel and decodes them with gopacket,
// creates a bidirectional flow identifier for each TCP packet and determines
// which flow tracker instance is tracking that connection. If none is found then
// a new flow tracker is created. Either way the parsed packet structs are passed
// to the flow tracker for further processing.
func (b *HoneyBadgerService) decodeTcp() {
	var eth layers.Ethernet
	var ip layers.IPv4
	var tcp layers.TCP
	var payload gopacket.Payload
	var conn *Connection
	var err error

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip, &tcp, &payload)
	decoded := make([]gopacket.LayerType, 0, 4)

	for packetBytes := range b.rawPacketChan {
		newPayload := new(gopacket.Payload)
		payload = *newPayload
		err = parser.DecodeLayers(packetBytes, &decoded)
		if err != nil {
			continue
		}
		tcpipflow := NewTcpIpFlowFromFlows(ip.NetworkFlow(), tcp.TransportFlow())
		packetManifest := PacketManifest{
			IP:      ip,
			TCP:     tcp,
			Payload: payload,
		}
		if b.connTracker.Has(tcpipflow) {
			conn, err = b.connTracker.Get(tcpipflow)
			if err != nil {
				panic(err) // wtf
			}
		} else {
			conn = NewConnection(b.connTracker)
			conn.PacketLogger = NewConnectionPacketLogger(b.LogDir, tcpipflow)
			conn.AttackLogger = NewAttackJsonLogger(b.LogDir, tcpipflow)
			b.connTracker.Put(tcpipflow, conn)
		}

		conn.receivePacket(packetManifest, tcpipflow)
		conn.PacketLoggerWrite(packetBytes, tcpipflow)
	}
}

func (b *HoneyBadgerService) StartReceivingTcp() {
	go b.receiveTcp()
}

// startReceivingTcp is a generator function which returns two channels;
// a stop channel and a packet channel. This function creates a goroutine
// which continually reads packets off the network interface and sends them
// to the packet channel.
func (b *HoneyBadgerService) receiveTcp() {
	//handle, err := pcap.OpenLive(iface, int32(snaplen), true, pcap.BlockForever)
	handle, err := pcap.OpenLive(b.Interface, int32(b.Snaplen), true, b.WireDuration)
	if err != nil {
		log.Fatal("error opening pcap handle: ", err)
	}
	if err := handle.SetBPFFilter(b.Filter); err != nil {
		log.Fatal("error setting BPF filter: ", err)
	}

	for {
		select {
		case <-b.stopChan:
			return
		default:
			data, _, err := handle.ReadPacketData()
			if err != nil {
				continue
			}
			b.rawPacketChan <- data
		}
	}
}
