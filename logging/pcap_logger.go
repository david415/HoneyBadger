/*
 *    HoneyBadger core library for detecting TCP injection attacks
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

package logging

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/david415/HoneyBadger/types"
)

type TimedPacket struct {
	RawPacket []byte
	Timestamp time.Time
}

// PcapLogger struct is used to log packets to a pcap file
type PcapLogger struct {
	packetChan chan TimedPacket
	stopChan   chan bool
	LogDir     string
	ArchiveDir string
	Flow       *types.TcpIpFlow
	writer     *pcapgo.Writer
	fileWriter io.WriteCloser
	pcapLogNum int
	pcapQuota  int
	basename   string
}

func NewPcapLogger(logDir, archiveDir string, flow *types.TcpIpFlow, pcapLogNum int, pcapQuota int) types.PacketLogger {
	p := PcapLogger{
		packetChan: make(chan TimedPacket),
		stopChan:   make(chan bool),
		Flow:       flow,
		LogDir:     logDir,
		ArchiveDir: archiveDir,
		pcapLogNum: pcapLogNum,
		pcapQuota:  pcapQuota,
	}
	return types.PacketLogger(&p)
}

type PcapLoggerFactory struct {
	LogDir     string
	ArchiveDir string
	PcapLogNum int
	PcapQuota  int
}

func NewPcapLoggerFactory(logDir, archiveDir string, pcapLogNum, pcapQuota int) PcapLoggerFactory {
	return PcapLoggerFactory{
		LogDir:     logDir,
		ArchiveDir: archiveDir,
		PcapLogNum: pcapLogNum,
		PcapQuota:  pcapQuota,
	}
}

func (f PcapLoggerFactory) Build(flow *types.TcpIpFlow) types.PacketLogger {
	return NewPcapLogger(f.LogDir, f.ArchiveDir, flow, f.PcapLogNum, f.PcapQuota)
}

func (p *PcapLogger) WriteHeader() {
	err := p.writer.WriteFileHeader(65536, layers.LinkTypeEthernet)
	if err != nil {
		panic(err)
	}
}

func (p *PcapLogger) Start() {
	if p.fileWriter == nil {
		p.basename = filepath.Join(p.LogDir, fmt.Sprintf("%s.pcap", p.Flow))
		p.fileWriter = NewRotatingQuotaWriter(p.basename, p.pcapQuota, p.pcapLogNum, p.WriteHeader)
		p.writer = pcapgo.NewWriter(p.fileWriter)
	}
	go p.logPackets()
}

func (p *PcapLogger) Stop() {
	p.stopChan <- true
	p.fileWriter.Close()
}

func (p *PcapLogger) Archive() {
	newBasename := filepath.Join(p.ArchiveDir, filepath.Base(p.basename))
	os.Rename(p.basename, newBasename)
	for i := 1; i < p.pcapLogNum+1; i++ {
		os.Rename(filepath.Join(p.LogDir, fmt.Sprintf("%s.pcap.%d", p.Flow.String(), i)), fmt.Sprintf("%s.%d", newBasename, i))
	}
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

func (p *PcapLogger) Remove() {
	os.Remove(p.basename)
	for i := 1; i < p.pcapLogNum+1; i++ {
		os.Remove(filepath.Join(p.LogDir, fmt.Sprintf("%s.pcap.%d", p.Flow, i)))
	}
}

func (p *PcapLogger) WritePacket(rawPacket []byte, timestamp time.Time) {
	p.packetChan <- TimedPacket{
		RawPacket: rawPacket,
		Timestamp: timestamp,
	}
}

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
