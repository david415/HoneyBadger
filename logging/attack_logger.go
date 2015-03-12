/*
 *    attack_logger.go - HoneyBadger core library for detecting TCP attacks
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

package logging

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/david415/HoneyBadger/types"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type serializedEvent struct {
	Type                     string
	Time                     time.Time
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
	LogDir           string
	stopChan         chan bool
	attackReportChan chan types.EventWithMutex
}

// NewAttackJsonLogger returns a pointer to a AttackJsonLogger struct
func NewAttackJsonLogger(logDir string) *AttackJsonLogger {
	a := AttackJsonLogger{
		LogDir:           logDir,
		stopChan:         make(chan bool),
		attackReportChan: make(chan types.EventWithMutex),
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
		case eventWithMutex := <-a.attackReportChan:
			a.SerializeAndWrite(eventWithMutex.Event)
			eventWithMutex.Mutex.Unlock()
		}
	}
}

func (a *AttackJsonLogger) Log(event *types.Event, mutex sync.Mutex) {
	eventWithMutex := types.EventWithMutex{
		Event: event,
		Mutex: mutex,
	}
	a.attackReportChan <- eventWithMutex
}

func (a *AttackJsonLogger) SerializeAndWrite(event *types.Event) {
	serialized := &serializedEvent{
		Type:         event.Type,
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
func (a *AttackJsonLogger) Publish(event *serializedEvent) {
	b, err := json.Marshal(event)
	a.writer, err = os.OpenFile(filepath.Join(a.LogDir, fmt.Sprintf("%s.attackreport.json", event.Flow)), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		panic(fmt.Sprintf("error opening file: %v", err))
	}
	defer a.writer.Close()
	a.writer.Write([]byte(fmt.Sprintf("%s\n", string(b))))
}
