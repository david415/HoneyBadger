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

package HoneyBadger

import (
	"code.google.com/p/gopacket/tcpassembly"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

type UnserializedAttackReport struct {
	Type                     string
	Time                     time.Time
	Flow                     TcpIpFlow
	AttemptPayload           []byte
	OverlapPayload           []byte
	Start, End               tcpassembly.Sequence
	OverlapStart, OverlapEnd int
}

// AttackReport contains information about the TCP injection attack
type AttackReport struct {
	Type          string
	Flow          string
	Time          string
	Payload       string
	Overlap       string
	StartSequence uint32
	EndSequence   uint32
	OverlapStart  int
	OverlapEnd    int
}

// The AttackLogger interface is used to describe TCP injection attack loggers.
// For the time being I have specified only two methods.. one for handshake hijack attacks
// and the other for injection attacks. However if an attack logger's implementation requires
// more methods then we should add those. Perhaps a Close() method will be required in the future for instance.
type AttackLogger interface {
	ReportHijackAttack(instant time.Time, flow TcpIpFlow)
	ReportInjectionAttack(instant time.Time, flow TcpIpFlow, attemptPayload []byte, overlap []byte, start, end tcpassembly.Sequence, overlapStart, overlapEnd int)
	Start()
	Stop()
}

// AttackJsonLogger is responsible for recording all attack reports as JSON objects in a file.
type AttackJsonLogger struct {
	LogDir           string
	stopChan         chan bool
	attackReportChan chan UnserializedAttackReport
}

// NewAttackJsonLogger returns a pointer to a AttackJsonLogger struct
func NewAttackJsonLogger(logDir string) *AttackJsonLogger {
	a := AttackJsonLogger{
		LogDir:           logDir,
		stopChan:         make(chan bool),
		attackReportChan: make(chan UnserializedAttackReport),
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

// ReportHijackAttack method is called to record a TCP handshake hijack attack
func (a *AttackJsonLogger) ReportHijackAttack(instant time.Time, flow TcpIpFlow) {
	log.Print("ReportHijackAttack\n")
	unserializedAttackReport := UnserializedAttackReport{
		Type: "hijack",
		Time: instant,
		Flow: flow,
	}
	a.attackReportChan <- unserializedAttackReport
}

// ReportInjectionAttack takes the details of an injection attack and writes
// an attack report to the attack log file
func (a *AttackJsonLogger) ReportInjectionAttack(instant time.Time, flow TcpIpFlow, attemptPayload []byte, overlap []byte, start, end tcpassembly.Sequence, overlapStart, overlapEnd int) {
	log.Print("ReportInjectionAttack\n")
	unserializedAttackReport := UnserializedAttackReport{
		Time:           instant,
		Flow:           flow,
		AttemptPayload: attemptPayload,
		OverlapPayload: overlap,
		Start:          start,
		End:            end,
		OverlapStart:   overlapStart,
		OverlapEnd:     overlapEnd,
	}
	a.attackReportChan <- unserializedAttackReport
}

func (a *AttackJsonLogger) SerializeAndWrite(unserializedAttackReport UnserializedAttackReport) {
	timeText, err := unserializedAttackReport.Time.MarshalText()
	if err != nil {
		panic(err)
	}

	report := &AttackReport{
		Type:          unserializedAttackReport.Type,
		Flow:          unserializedAttackReport.Flow.String(),
		Time:          string(timeText),
		Payload:       base64.StdEncoding.EncodeToString(unserializedAttackReport.AttemptPayload),
		Overlap:       base64.StdEncoding.EncodeToString(unserializedAttackReport.OverlapPayload),
		StartSequence: uint32(unserializedAttackReport.Start),
		EndSequence:   uint32(unserializedAttackReport.End),
		OverlapStart:  unserializedAttackReport.OverlapStart,
		OverlapEnd:    unserializedAttackReport.OverlapEnd,
	}
	a.Publish(report)
}

// Publish writes a JSON report to the attack-report file for that flow.
func (a *AttackJsonLogger) Publish(report *AttackReport) {
	b, err := json.Marshal(*report)
	f, err := os.OpenFile(filepath.Join(a.LogDir, fmt.Sprintf("%s.attackreport.json", report.Flow)), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		panic(fmt.Sprintf("error opening file: %v", err))
	}
	defer f.Close()
	f.Write([]byte(fmt.Sprintf("%s\n", string(b)))) // ugly
}
