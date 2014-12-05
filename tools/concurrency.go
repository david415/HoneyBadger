package main

import (
	"code.google.com/p/gopacket/examples/util"
	"flag"
	"github.com/david415/HoneyBadger/observe"
)

var iface = flag.String("i", "lo", "Interface to get packets from")
var filter = flag.String("f", "tcp", "BPF filter for pcap")
var snaplen = flag.Int("s", 65536, "SnapLen for pcap packet capture")

func main() {
	defer util.Run()()
	multiObserver := observe.MultiTCPFlowObserver{}
	multiObserver.Start(*iface, int32(*snaplen), *filter)
}
