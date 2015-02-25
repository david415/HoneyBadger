/*
 *    metadata_attack_logger.go - HoneyBadger core library for detecting TCP attacks
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
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"
)

// AttackMetadataJsonLogger is responsible for recording all attack reports as JSON objects in a file.
// This attack logger only logs metadata... but ouch code duplication.
type AttackMetadataJsonLogger struct {
	writer           io.WriteCloser
	LogDir           string
	stopChan         chan bool
	attackReportChan chan UnserializedAttackReport
}

// NewAttackMetadataJsonLogger returns a pointer to a AttackMetadataJsonLogger struct
func NewAttackMetadataJsonLogger(logDir string) *AttackMetadataJsonLogger {
	a := AttackMetadataJsonLogger{
		LogDir:           logDir,
		stopChan:         make(chan bool),
		attackReportChan: make(chan UnserializedAttackReport),
	}
	return &a
}

func (a *AttackMetadataJsonLogger) Start() {
	go a.receiveReports()
}

func (a *AttackMetadataJsonLogger) Stop() {
	a.stopChan <- true
}

func (a *AttackMetadataJsonLogger) receiveReports() {
	for {
		select {
		case <-a.stopChan:
			return
		case unserializedReport := <-a.attackReportChan:
			a.SerializeAndWrite(unserializedReport)
		}
	}
}

// ReportHijackAttack method is called to record a TCP handshake hijack attack
func (a *AttackMetadataJsonLogger) ReportHijackAttack(instant time.Time, flow TcpIpFlow, Seq, Ack uint32) {
	log.Print("ReportHijackAttack\n")
	unserializedAttackReport := UnserializedAttackReport{
		Type:      "hijack",
		Time:      instant,
		Flow:      flow,
		HijackSeq: Seq,
		HijackAck: Ack,
	}
	a.attackReportChan <- unserializedAttackReport
}

// ReportInjectionAttack takes the details of an injection attack and writes
// an attack report to the attack log file
func (a *AttackMetadataJsonLogger) ReportInjectionAttack(attackType string, instant time.Time, flow TcpIpFlow, attemptPayload []byte, overlap []byte, start, end Sequence, overlapStart, overlapEnd int) {
	log.Print("ReportInjectionAttack\n")
	unserializedAttackReport := UnserializedAttackReport{
		Type:           attackType,
		Time:           instant,
		Flow:           flow,
		AttemptPayload: []byte{},
		OverlapPayload: []byte{},
		Start:          start,
		End:            end,
		OverlapStart:   overlapStart,
		OverlapEnd:     overlapEnd,
	}
	a.attackReportChan <- unserializedAttackReport
}

func (a *AttackMetadataJsonLogger) SerializeAndWrite(unserializedAttackReport UnserializedAttackReport) {
	timeText, err := unserializedAttackReport.Time.MarshalText()
	if err != nil {
		panic(err)
	}

	report := &AttackReport{
		Type:          unserializedAttackReport.Type,
		Flow:          unserializedAttackReport.Flow.String(),
		HijackSeq:     unserializedAttackReport.HijackSeq,
		HijackAck:     unserializedAttackReport.HijackAck,
		Time:          string(timeText),
		Payload:       "",
		Overlap:       "",
		StartSequence: uint32(unserializedAttackReport.Start),
		EndSequence:   uint32(unserializedAttackReport.End),
		OverlapStart:  unserializedAttackReport.OverlapStart,
		OverlapEnd:    unserializedAttackReport.OverlapEnd,
	}
	a.Publish(report)
}

// Publish writes a JSON report to the attack-report file for that flow.
func (a *AttackMetadataJsonLogger) Publish(report *AttackReport) {
	b, err := json.Marshal(*report)
	a.writer, err = os.OpenFile(filepath.Join(a.LogDir, fmt.Sprintf("%s.metadata-attackreport.json", report.Flow)), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		panic(fmt.Sprintf("error opening file: %v", err))
	}
	defer a.writer.Close()
	a.writer.Write([]byte(fmt.Sprintf("%s\n", string(b))))
}
