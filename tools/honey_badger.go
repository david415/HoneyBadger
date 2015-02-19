/*
 *    honeyBadger.go - HoneyBadger core program for detecting TCP attacks
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

package main

import (
	"flag"
	"github.com/david415/HoneyBadger"
	"log"
	"os"
	"os/signal"
	"time"
)

func main() {
	var (
		iface                 = flag.String("i", "eth0", "Interface to get packets from")
		snaplen               = flag.Int("s", 65536, "SnapLen for pcap packet capture")
		filter                = flag.String("f", "tcp", "BPF filter for pcap")
		logDir                = flag.String("l", "honeyBadger-logs", "log directory")
		wireTimeout           = flag.String("w", "10s", "timeout for reading packets off the wire")
		packetLog             = flag.Bool("packet_log", false, "if set to true then log all packets for each tracked TCP connection")
		streamLog             = flag.Bool("stream_log", false, "if set to true then log both reassembled TCP streams for each tracked TCP connection")
		tcpTimeout            = flag.Duration("tcp_idle_timeout", time.Minute*5, "tcp idle timeout duration")
		maxRingPackets        = flag.Int("max_ring_packets", 40, "Max packets per connection stream ring buffer")
		bufferedPerConnection = flag.Int("connection_max_buffer", 0, `
Max packets to buffer for a single connection before skipping over a gap in data
and continuing to stream the connection after the buffer.  If zero or less, this
is infinite.`)
		bufferedTotal = flag.Int("total_max_buffer", 0, `
Max packets to buffer total before skipping over gaps in connections and
continuing to stream connection data.  If zero or less, this is infinite`)
	)
	flag.Parse()

	wireDuration, err := time.ParseDuration(*wireTimeout)
	if err != nil {
		log.Fatal("invalid wire timeout duration: ", *wireTimeout)
	}

	options := HoneyBadger.InquisitorOptions{
		Interface:             *iface,
		WireDuration:          wireDuration,
		BufferedPerConnection: *bufferedPerConnection,
		BufferedTotal:         *bufferedTotal,
		Filter:                *filter,
		LogDir:                *logDir,
		Snaplen:               *snaplen,
		PacketLog:             *packetLog,
		StreamLog:             *streamLog,
		TcpIdleTimeout:        *tcpTimeout,
		MaxRingPackets:        *maxRingPackets,
	}

	service := HoneyBadger.NewInquisitor(&options)
	log.Println("HoneyBadger: comprehensive TCP injection attack detection.")
	service.Start()

	// quit when we detect a control-c
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	service.Stop()
}
