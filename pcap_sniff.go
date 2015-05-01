/*
 *    HoneyBadger core library
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
	"github.com/david415/HoneyBadger/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io"
	"log"
	"time"
)

/*type TimedRawPacket struct {
	Timestamp time.Time
	RawPacket []byte
}
*/
// PcapSnifferOptions are user set parameters for specifying how to
// receive packets.
type PcapSnifferOptions struct {
	Interface    string
	Filename     string
	WireDuration time.Duration
	Filter       string
	Snaplen      int
	Dispatcher   PacketDispatcher
	Supervisor   types.Supervisor
}

// PcapSniffer sets up the connection pool and is an abstraction layer for dealing
// with incoming packets weather they be from a pcap file or directly off the wire.
type PcapSniffer struct {
	PcapSnifferOptions
	stopCaptureChan  chan bool
	decodePacketChan chan TimedRawPacket
	stopDecodeChan   chan bool
	handle           *pcap.Handle
	supervisor       types.Supervisor
}

// NewPcapSniffer creates a new PcapSniffer struct
func NewPcapSniffer(options *PcapSnifferOptions) types.PacketSource {
	i := PcapSniffer{
		PcapSnifferOptions: *options,
		stopCaptureChan:    make(chan bool),
		decodePacketChan:   make(chan TimedRawPacket),
		stopDecodeChan:     make(chan bool),
	}
	return &i
}

func (i *PcapSniffer) SetSupervisor(supervisor types.Supervisor) {
	i.supervisor = supervisor
}
func (i *PcapSniffer) GetStartedChan() chan bool {
	return make(chan bool)
}

// Start... starts the TCP attack inquisition!
func (i *PcapSniffer) Start() {
	if i.handle == nil {
		i.setupHandle()
	}
	go i.capturePackets()
	go i.decodePackets()
}

func (i *PcapSniffer) Stop() {
	i.stopCaptureChan <- true
	i.stopDecodeChan <- true
	i.handle.Close()
}

func (i *PcapSniffer) setupHandle() {
	var err error
	if i.Filename != "" {
		log.Printf("Reading from pcap file %q", i.Filename)
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

func (i *PcapSniffer) capturePackets() {

	tchan := make(chan TimedRawPacket, 0)
	// XXX does this need a shutdown code path?
	go func() {
		for {
			rawPacket, captureInfo, err := i.handle.ReadPacketData()
			if err == io.EOF {
				log.Print("ReadPacketData got EOF\n")
				i.Stop()
				close(tchan)
				i.supervisor.Stopped()
				return
			}
			if err != nil {
				continue
			}
			tchan <- TimedRawPacket{
				Timestamp: captureInfo.Timestamp,
				RawPacket: rawPacket,
			}
		}
	}()

	for {
		select {
		case <-i.stopCaptureChan:
			return
		case t := <-tchan:
			i.decodePacketChan <- t
		}
	}
}

func (i *PcapSniffer) decodePackets() {
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
			flow := types.NewTcpIpFlowFromFlows(ip.NetworkFlow(), tcp.TransportFlow())
			packetManifest := types.PacketManifest{
				Timestamp: timedRawPacket.Timestamp,
				Flow:      flow,
				RawPacket: timedRawPacket.RawPacket,
				IP:        ip,
				TCP:       tcp,
				Payload:   payload,
			}
			i.Dispatcher.ReceivePacket(&packetManifest)
		}
	}
}
