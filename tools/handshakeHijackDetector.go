// detector for tcp handshake injections
// author David Stainton
// Copyright 2014 David Stainton
// inspired by Graeme Connel's gopacket.tcpassembly
//

package main

import (
	"flag"
	"github.com/david415/HoneyBadger"
)

func main() {
	var (
		iface   = flag.String("i", "eth0", "Interface to get packets from")
		snaplen = flag.Int("s", 65536, "SnapLen for pcap packet capture")
		filter  = flag.String("f", "tcp", "BPF filter for pcap")
	)
	flag.Parse()

	connTracker := HoneyBadger.NewConnTracker()
	stopChan, packetChan := HoneyBadger.StartReceivingTcp(*filter, *iface, *snaplen)
	HoneyBadger.StartDecodingTcp(packetChan, connTracker)
	<-stopChan
}
