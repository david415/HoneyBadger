/*
 *    inference.go - inference TCP injector
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

package attack

import (
	"fmt"

	"github.com/subgraph/go-nfnetlink/nfqueue"
	//"github.com/subgraph/go-nfnetlink"
	//"github.com/david415/HoneyBadger/types"
	//"github.com/google/gopacket"
	//"github.com/google/gopacket/layers"
	//"github.com/google/gopacket/pcap"
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("tcpInference")

type TCPInferenceSideChannel struct {
	// NFQUEUE handler struct type
	nfq *nfqueue.NFQueue
	// channel for receiving packets from NFQUEUE
	receiveChan <-chan *nfqueue.NFQPacket
}

func NewTCPInferenceSideChannel(queue_number uint16) *TCPInferenceSideChannel {
	t := TCPInferenceSideChannel{
		nfq: nfqueue.NewNFQueue(queue_number),
	}
	return &t
}

func (t *TCPInferenceSideChannel) Open() error {
	var err error
	t.receiveChan, err = t.nfq.Open()
	if err != nil {
		return err
	} else {
		return nil
	}
}

func (t *TCPInferenceSideChannel) Close() {
	pendingError := t.nfq.PendingError()
	if pendingError != nil {
		log.Warning(fmt.Sprintf("%s", pendingError))
	}
	t.nfq.Close()
}

func (t *TCPInferenceSideChannel) Flutter() {
	for p := range t.receiveChan {
		fmt.Printf("Packet: %v\n", p.Packet)
		p.Accept()
	}
}
