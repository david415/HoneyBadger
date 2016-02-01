/*
 *    HoneyBadger main command line tool
 *
 *    Copyright (C) 2014, 2015  David Stainton
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
	"log"
	"time"

	"github.com/david415/HoneyBadger"
	"github.com/david415/HoneyBadger/logging"
	"github.com/david415/HoneyBadger/types"
)

func main() {
	var (
		pcapfile                 = flag.String("pcapfile", "", "pcap filename to read packets from rather than a wire interface.")
		iface                    = flag.String("i", "eth0", "Interface to get packets from")
		snaplen                  = flag.Int("s", 65536, "SnapLen for pcap packet capture")
		filter                   = flag.String("f", "tcp", "BPF filter for pcap")
		logDir                   = flag.String("l", "", "incoming log dir used initially for pcap files if packet logging is enabled")
		wireTimeout              = flag.String("w", "3s", "timeout for reading packets off the wire")
		metadataAttackLog        = flag.Bool("metadata_attack_log", true, "if set to true then attack reports will only include metadata")
		logPackets               = flag.Bool("log_packets", false, "if set to true then log all packets for each tracked TCP connection")
		tcpTimeout               = flag.Duration("tcp_idle_timeout", time.Minute*5, "tcp idle timeout duration")
		maxRingPackets           = flag.Int("max_ring_packets", 40, "Max packets per connection stream ring buffer")
		detectHijack             = flag.Bool("detect_hijack", true, "Detect handshake hijack attacks")
		detectInjection          = flag.Bool("detect_injection", true, "Detect injection attacks")
		detectCoalesceInjection  = flag.Bool("detect_coalesce_injection", true, "Detect coalesce injection attacks")
		maxConcurrentConnections = flag.Int("max_concurrent_connections", 0, "Maximum number of concurrent connection to track.")
		bufferedPerConnection    = flag.Int("connection_max_buffer", 0, `
Max packets to buffer for a single connection before skipping over a gap in data
and continuing to stream the connection after the buffer.  If zero or less, this
is infinite.`)
		bufferedTotal = flag.Int("total_max_buffer", 0, `
Max packets to buffer total before skipping over gaps in connections and
continuing to stream connection data.  If zero or less, this is infinite`)
		maxPcapLogSize      = flag.Int("max_pcap_log_size", 1, "maximum pcap size per rotation in megabytes")
		maxNumPcapRotations = flag.Int("max_pcap_rotations", 10, "maximum number of pcap rotations per connection")
		archiveDir          = flag.String("archive_dir", "", "archive directory for storing attack logs and related pcap files")
		daq                 = flag.String("daq", "libpcap", "Data AcQuisition packet source")
	)
	flag.Parse()

	if *daq == "" {
		log.Fatal("must specify a Data AcQuisition packet source`")
	}

	// XXX TODO use the pure golang pcap file sniffing API; gopacket's pcapgo
	if *pcapfile != "" && *daq != "libpcap" {
		log.Fatal("only libpcap DAQ supports sniffing pcap files")
	}

	if *archiveDir == "" || *logDir == "" {
		log.Fatal("must specify both incoming log dir and archive log dir")
	}

	wireDuration, err := time.ParseDuration(*wireTimeout)
	if err != nil {
		log.Fatal("invalid wire timeout duration: ", *wireTimeout)
	}

	if *maxConcurrentConnections == 0 {
		log.Fatal("maxConcurrentConnections must be specified")
	}

	if *bufferedPerConnection == 0 || *bufferedTotal == 0 {
		log.Fatal("connection_max_buffer and total_max_buffer must be set to a non-zero value")
	}

	var logger types.Logger

	if *metadataAttackLog {
		loggerInstance := logging.NewAttackMetadataJsonLogger(*archiveDir)
		loggerInstance.Start()
		defer func() { loggerInstance.Stop() }()
		logger = loggerInstance
	} else {
		loggerInstance := logging.NewAttackJsonLogger(*archiveDir)
		loggerInstance.Start()
		defer func() { loggerInstance.Stop() }()
		logger = loggerInstance
	}

	dispatcherOptions := HoneyBadger.DispatcherOptions{
		BufferedPerConnection:    *bufferedPerConnection,
		BufferedTotal:            *bufferedTotal,
		LogDir:                   *logDir,
		LogPackets:               *logPackets,
		MaxPcapLogRotations:      *maxNumPcapRotations,
		MaxPcapLogSize:           *maxPcapLogSize,
		TcpIdleTimeout:           *tcpTimeout,
		MaxRingPackets:           *maxRingPackets,
		Logger:                   logger,
		DetectHijack:             *detectHijack,
		DetectInjection:          *detectInjection,
		DetectCoalesceInjection:  *detectCoalesceInjection,
		MaxConcurrentConnections: *maxConcurrentConnections,
	}

	snifferDriverOptions := types.SnifferDriverOptions{
		DAQ:          *daq,
		Device:       *iface,
		Filename:     *pcapfile,
		WireDuration: wireDuration,
		Snaplen:      int32(*snaplen),
		Filter:       *filter,
	}

	connectionFactory := &HoneyBadger.DefaultConnFactory{}
	var packetLoggerFactory types.PacketLoggerFactory
	if *logPackets {
		packetLoggerFactory = logging.NewPcapLoggerFactory(*logDir, *archiveDir, *maxNumPcapRotations, *maxPcapLogSize)
	} else {
		packetLoggerFactory = nil
	}

	log.Println("HoneyBadger: comprehensive TCP injection attack detection.")
	options := HoneyBadger.SupervisorOptions{
		SnifferDriverOptions: &snifferDriverOptions,
		DispatcherOptions:    dispatcherOptions,
		SnifferFactory:       HoneyBadger.NewSniffer,
		ConnectionFactory:    connectionFactory,
		PacketLoggerFactory:  packetLoggerFactory,
	}
	supervisor := HoneyBadger.NewSupervisor(options)
	supervisor.Run()
}
