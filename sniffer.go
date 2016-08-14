/*
 *    HoneyBadger core library for detecting TCP injection attacks
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
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"io"
	"log"

	"github.com/david415/HoneyBadger/drivers"
	"github.com/david415/HoneyBadger/types"
)

// Sniffer sets up the connection pool and is an abstraction layer for dealing
// with incoming packets weather they be from a pcap file or directly off the wire.
type Sniffer struct {
	options          *types.SnifferDriverOptions
	supervisor       types.Supervisor
	dispatcher       PacketDispatcher
	packetDataSource types.PacketDataSourceCloser
	isStopped        bool
	decodePacketChan chan TimedRawPacket
	stopDecodeChan   chan bool
}

// NewSniffer creates a new Sniffer struct
func NewSniffer(options *types.SnifferDriverOptions, dispatcher PacketDispatcher) types.PacketSource {
	i := Sniffer{
		dispatcher:       dispatcher,
		options:          options,
		decodePacketChan: make(chan TimedRawPacket),
		stopDecodeChan:   make(chan bool),
	}
	return &i
}

func (i *Sniffer) SetSupervisor(supervisor types.Supervisor) {
	i.supervisor = supervisor
}

func (i *Sniffer) GetStartedChan() chan bool {
	return make(chan bool)
}

// Start... starts the TCP attack inquisition!
func (i *Sniffer) Start() {
	// XXX
	i.setupHandle()

	go i.capturePackets()
	go i.decodePackets()
}

func (i *Sniffer) Stop() {
	log.Print("sniffer: sending stopCapureChan signal")
	i.isStopped = true
	i.stopDecodeChan <- true
}

func (i *Sniffer) Close() {
	if i.packetDataSource != nil {
		log.Print("closing packet capture socket")
		i.packetDataSource.Close()
	}
	log.Print("stopping the sniffer decode loop")
	i.isStopped = true
	log.Print("done.")
}

func (i *Sniffer) setupHandle() {
	var err error
	var what string

	factory, ok := drivers.Drivers[i.options.DAQ]
	if !ok {
		log.Fatal(fmt.Sprintf("%s Sniffer not supported on this system", i.options.DAQ))
	}
	i.packetDataSource, err = factory(i.options)

	if err != nil {
		if i.options.Filename != "" {
			log.Printf("failed to read file %s", i.options.Filename)
		}
		panic(fmt.Sprintf("Failed to acquire DataAcQuisition source: %s", err))
	}

	if i.options.Filename != "" {
		what = fmt.Sprintf("file %s", i.options.Filename)
	} else {
		what = fmt.Sprintf("interface %s", i.options.Device)
	}

	log.Printf("Starting %s packet capture on %s", i.options.DAQ, what)
}

func (i *Sniffer) capturePackets() {
	for {
		rawPacket, captureInfo, err := i.packetDataSource.ReadPacketData()
		if err == io.EOF {
			log.Print("ReadPacketData got EOF\n")
			i.Close()
			i.Stop()
			i.dispatcher.Stop()
			i.supervisor.Stopped()
			return
		}
		if err != nil {
			//log.Printf("packet capure read error: %s", err)
			continue
		}
		timedPacket := TimedRawPacket{
			Timestamp: captureInfo.Timestamp,
		}
		timedPacket.RawPacket = make([]byte, len(rawPacket))
		copy(timedPacket.RawPacket, rawPacket)
		i.decodePacketChan <- timedPacket
		if i.isStopped {
			break
		}
	}
}

func (i *Sniffer) decodePackets() {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var payload gopacket.Payload

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &payload)
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

			packetManifest := types.PacketManifest{
				Timestamp: timedRawPacket.Timestamp,
				Payload:   payload,
				IPv6:      nil,
				IPv4:      nil,
			}
			foundNetLayer := false

			for _, typ := range decoded {
				switch typ {
				case layers.LayerTypeIPv4:
					packetManifest.IPv4 = &ip4
					foundNetLayer = true
				case layers.LayerTypeIPv6:
					packetManifest.IPv6 = &ip6
					foundNetLayer = true
				case layers.LayerTypeTCP:
					if foundNetLayer {
						flow := types.TcpIpFlow{}
						if packetManifest.IPv6 == nil {
							// IPv4 case
							flow = types.NewTcpIpFlowFromFlows(ip4.NetworkFlow(), tcp.TransportFlow())
						} else if packetManifest.IPv4 == nil {
							// IPv6 case
							flow = types.NewTcpIpFlowFromFlows(ip6.NetworkFlow(), tcp.TransportFlow())
						} else {
							panic("wtf")
						}

						packetManifest.Flow = &flow
						packetManifest.TCP = &tcp
						i.dispatcher.ReceivePacket(&packetManifest)
					} else {
						log.Println("could not find IPv4 or IPv6 layer, inoring")
					}
				} // switch
			} // for

		} // select
	} // for
}
