/*
 *    pcap_loggers.go - HoneyBadger core library for detecting TCP attacks
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

package HoneyBadger

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcapgo"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type PacketLogger interface {
	WritePacket(rawPacket []byte, timestamp time.Time)
	Start()
	Stop()
}

type TimedPacket struct {
	RawPacket []byte
	Timestamp time.Time
}

// PcapLogger struct is used to log packets to a pcap file
type PcapLogger struct {
	packetChan chan TimedPacket
	stopChan   chan bool
	Dir        string
	Flow       TcpIpFlow
	writer     *pcapgo.Writer
	fileWriter io.WriteCloser
}

// NewPcapLogger returns a PcapLogger struct...
// and in doing so writes a pcap header to the beginning of the file.
func NewPcapLogger(dir string, flow TcpIpFlow) *PcapLogger {
	p := PcapLogger{
		packetChan: make(chan TimedPacket),
		Flow:       flow,
		Dir:        dir,
	}
	return &p
}

func (p *PcapLogger) Start() {
	var err error
	if p.fileWriter == nil {
		p.fileWriter, err = os.OpenFile(filepath.Join(p.Dir, fmt.Sprintf("%s.pcap", p.Flow.String())), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			panic(fmt.Sprintf("error opening file: %v", err))
		}
	}
	p.writer = pcapgo.NewWriter(p.fileWriter)
	err = p.writer.WriteFileHeader(65536, layers.LinkTypeEthernet) // XXX
	if err != nil {
		panic(err)
	}
	go p.logPackets()
}

// Close causes the file to be closed.
func (p *PcapLogger) Stop() {
	p.stopChan <- true
	p.fileWriter.Close()
}

func (p *PcapLogger) logPackets() {
	for {
		select {
		case <-p.stopChan:
			return
		case timedPacket := <-p.packetChan:
			p.WritePacketToFile(timedPacket.RawPacket, timedPacket.Timestamp)
		}
	}
}

func (p *PcapLogger) WritePacket(rawPacket []byte, timestamp time.Time) {
	p.packetChan <- TimedPacket{
		RawPacket: rawPacket,
		Timestamp: timestamp,
	}
}

// WritePacket receives a raw packet and a timestamp. It writes this
// info to the pcap log file.
func (p *PcapLogger) WritePacketToFile(rawPacket []byte, timestamp time.Time) {
	err := p.writer.WritePacket(gopacket.CaptureInfo{
		Timestamp:     timestamp,
		CaptureLength: len(rawPacket),
		Length:        len(rawPacket),
	}, rawPacket)
	if err != nil {
		panic(err)
	}
}
