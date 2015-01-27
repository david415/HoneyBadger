/*
 *    pcapLoggers.go - HoneyBadger core library for detecting TCP attacks
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
	"os"
	"path/filepath"
	"time"
)

type ConnectionPacketLogger struct {
	dir            string
	aPacketLogChan chan []byte
	bPacketLogChan chan []byte
	closeChan      chan bool
	aFlow          TcpIpFlow
	aLogger        *PcapLogger
	bLogger        *PcapLogger
}

func NewConnectionPacketLogger(dir string, aFlow TcpIpFlow) *ConnectionPacketLogger {
	return &ConnectionPacketLogger{
		aPacketLogChan: make(chan []byte),
		bPacketLogChan: make(chan []byte),
		closeChan:      make(chan bool),
		aLogger:        NewPcapLogger(dir, aFlow),
		bLogger:        NewPcapLogger(dir, aFlow.Reverse()),
		aFlow:          aFlow,
		dir:            dir,
	}
}

func (c *ConnectionPacketLogger) WritePacket(packet []byte, flow TcpIpFlow) {
	if flow.Equal(c.aFlow) {
		c.aLogger.WritePacket(packet)
	} else {
		c.bLogger.WritePacket(packet)
	}
}

func (c *ConnectionPacketLogger) Close() {
	c.aLogger.Close()
	c.bLogger.Close()
}

type PcapLogger struct {
	dir        string
	flow       TcpIpFlow
	writer     *pcapgo.Writer
	fileHandle *os.File
	closeChan  chan bool
	writeChan  chan []byte
}

func NewPcapLogger(dir string, flow TcpIpFlow) *PcapLogger {
	var err error
	p := PcapLogger{
		dir:       dir,
		flow:      flow,
		closeChan: make(chan bool),
		writeChan: make(chan []byte),
	}
	p.fileHandle, err = os.OpenFile(filepath.Join(p.dir, fmt.Sprintf("%s.pcap", p.flow.String())), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		panic(fmt.Sprintf("error opening file: %v", err))
	}

	p.writer = pcapgo.NewWriter(p.fileHandle)

	err = p.writer.WriteFileHeader(65536, layers.LinkTypeEthernet) // XXX
	if err != nil {
		panic(err)
	}
	return &p
}

func (p *PcapLogger) WritePacket(packet []byte) {
	err := p.writer.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(packet),
		Length:        len(packet), // XXX
	}, packet)
	if err != nil {
		panic(err)
	}
}

func (p *PcapLogger) Close() {
	close(p.writeChan)
	close(p.closeChan)
	p.fileHandle.Close()
}

func (p *PcapLogger) StartWriter() {
	go p.startWriter()
}

func (p *PcapLogger) startWriter() {
	for {
		select {
		case <-p.closeChan:
			return
		case packetBytes := <-p.writeChan:
			p.WritePacket(packetBytes)
		}
	}
}
