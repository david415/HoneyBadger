/*
 *    stream_logger.go - HoneyBadger core library for detecting TCP attacks
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
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

// StreamLogger is used to persist reassembled TCP streams.
// It implements the Stream interface.
type StreamLogger struct {
	dir         string
	flow        TcpIpFlow
	stopChan    chan bool
	receiveChan chan []Reassembly
	byteCount   int64 // total bytes seen on this stream.
	writer      io.WriteCloser
}

func NewStreamLogger(dir string, flow TcpIpFlow) *StreamLogger {
	return &StreamLogger{
		dir:         dir,
		flow:        flow,
		stopChan:    make(chan bool),
		receiveChan: make(chan []Reassembly),
	}
}

func (s *StreamLogger) Start() {
	var err error
	if s.writer == nil {
		s.writer, err = os.OpenFile(filepath.Join(s.dir, fmt.Sprintf("%s.stream", s.flow.String())), os.O_RDWR|os.O_CREATE, 0666)
		if err != nil {
			panic(fmt.Sprintf("error opening file: %v", err))
		}
	}
	go s.receiveReassembly()
}

func (s *StreamLogger) Stop() {
	s.stopChan <- true
	s.writer.Close()
}

func (s *StreamLogger) receiveReassembly() {
	for {
		select {
		case <-s.stopChan:
			return
		case res := <-s.receiveChan:
			s.persistStreamReassembly(res)
		}
	}
}

func (s *StreamLogger) Reassembled(r []Reassembly) {
	s.receiveChan <- r
}

func (s *StreamLogger) persistStreamReassembly(rs []Reassembly) {
	for _, r := range rs {
		// For now, we'll simply count the bytes on each side of the TCP stream.
		s.byteCount += int64(len(r.Bytes))
		s.writer.Write(r.Bytes)
	}
}

func (s *StreamLogger) ReassemblyComplete() {
	log.Printf("ReassemblyComplete() wrote %d bytes\n", s.byteCount)
	s.Stop()
}
