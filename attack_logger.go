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
}

// AttackJsonLogger is responsible for recording all attack reports as JSON objects in a file.
type AttackJsonLogger struct {
	LogDir string
	Flow   TcpIpFlow
}

// NewAttackJsonLogger returns a pointer to a AttackJsonLogger struct
func NewAttackJsonLogger(logDir string, flow TcpIpFlow) *AttackJsonLogger {
	a := AttackJsonLogger{
		LogDir: logDir,
		Flow:   flow,
	}
	return &a
}

// ReportHijackAttack method is called to record a TCP handshake hijack attack
func (a *AttackJsonLogger) ReportHijackAttack(instant time.Time, flow TcpIpFlow) {
	timeText, err := instant.MarshalText()
	if err != nil {
		panic(err)
	}

	report := &AttackReport{
		Type: "hijack",
		Flow: flow.String(),
		Time: string(timeText),
	}
	a.Publish(report)
}

// ReportInjectionAttack takes the details of an injection attack and writes
// an attack report to the attack log file
func (a *AttackJsonLogger) ReportInjectionAttack(instant time.Time, flow TcpIpFlow, attemptPayload []byte, overlap []byte, start, end tcpassembly.Sequence, overlapStart, overlapEnd int) {

	log.Print("ReportInjectionAttack\n")

	timeText, err := instant.MarshalText()
	if err != nil {
		panic(err)
	}

	report := &AttackReport{
		Type:          "injection",
		Flow:          flow.String(),
		Time:          string(timeText),
		Payload:       base64.StdEncoding.EncodeToString(attemptPayload),
		Overlap:       base64.StdEncoding.EncodeToString(overlap),
		StartSequence: uint32(start),
		EndSequence:   uint32(end),
		OverlapStart:  overlapStart,
		OverlapEnd:    overlapEnd,
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
