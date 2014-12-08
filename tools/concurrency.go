package main

import (
	"flag"
	"github.com/david415/HoneyBadger/observe"
)

var iface = flag.String("i", "lo", "Interface to get packets from")
var filter = flag.String("f", "tcp", "BPF filter for pcap")
var snaplen = flag.Int("s", 65536, "SnapLen for pcap packet capture")

func main() {
	multiObserver := observe.MultiTCPFlowObserver{}
	err := multiObserver.Start(*iface, int32(*snaplen), *filter)
	if err != nil {
		panic(err)
	}
}
