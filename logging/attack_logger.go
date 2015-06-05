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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/david415/HoneyBadger/types"
	"io"
	"os"
	"path/filepath"
	"time"
)

type SerializedEvent struct {
	Type                     string
	Time                     time.Time
	PacketCount              uint64
	Flow                     string
	HijackSeq                uint32
	HijackAck                uint32
	Payload                  string
	Overlap                  string
	Start, End               types.Sequence
	OverlapStart, OverlapEnd int
}

// AttackJsonLogger is responsible for recording all attack reports as JSON objects in a file.
type AttackJsonLogger struct {
	writer           io.WriteCloser
	ArchiveDir       string
	stopChan         chan bool
	attackReportChan chan *types.Event
}

// NewAttackJsonLogger returns a pointer to a AttackJsonLogger struct
func NewAttackJsonLogger(archiveDir string) *AttackJsonLogger {
	a := AttackJsonLogger{
		ArchiveDir:       archiveDir,
		stopChan:         make(chan bool),
		attackReportChan: make(chan *types.Event),
	}
	return &a
}

func (a *AttackJsonLogger) Start() {
	go a.receiveReports()
}

func (a *AttackJsonLogger) Stop() {
	a.stopChan <- true
}

func (a *AttackJsonLogger) receiveReports() {
	for {
		select {
		case <-a.stopChan:
			return
		case unserializedReport := <-a.attackReportChan:
			a.SerializeAndWrite(unserializedReport)
		}
	}
}

func (a *AttackJsonLogger) Log(event *types.Event) {
	a.attackReportChan <- event
}

func (a *AttackJsonLogger) SerializeAndWrite(event *types.Event) {
	serialized := &SerializedEvent{
		Type:         event.Type,
		PacketCount:  event.PacketCount,
		Flow:         event.Flow.String(),
		HijackSeq:    event.HijackSeq,
		HijackAck:    event.HijackAck,
		Time:         event.Time,
		Payload:      base64.StdEncoding.EncodeToString(event.Payload),
		Overlap:      base64.StdEncoding.EncodeToString(event.Overlap),
		Start:        event.StartSequence,
		End:          event.EndSequence,
		OverlapStart: event.OverlapStart,
		OverlapEnd:   event.OverlapEnd,
	}
	a.Publish(serialized)
}

// Publish writes a JSON report to the attack-report file for that flow.
func (a *AttackJsonLogger) Publish(event *SerializedEvent) {
	b, err := json.Marshal(event)
	logName := filepath.Join(a.ArchiveDir, fmt.Sprintf("%s.attackreport.json", event.Flow))
	a.writer, err = os.OpenFile(logName, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		panic(fmt.Sprintf("error opening file: %v", err))
	}
	defer a.writer.Close()
	a.writer.Write([]byte(fmt.Sprintf("%s\n", string(b))))
}
