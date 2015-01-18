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
