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

type AttackLogger interface {
	ReportHijackAttack(instant time.Time, flow TcpIpFlow)
	ReportInjectionAttack(instant time.Time, flow TcpIpFlow, attemptPayload []byte, overlap []byte, start, end tcpassembly.Sequence, overlapStart, overlapEnd int)
	Close()
}

type AttackJsonLogger struct {
	LogDir string
	Flow   TcpIpFlow
	count  int
}

func NewAttackJsonLogger(logDir string, flow TcpIpFlow) *AttackJsonLogger {
	a := AttackJsonLogger{
		LogDir: logDir,
		Flow:   flow,
		count:  0,
	}
	return &a
}

func (a *AttackJsonLogger) Close() {
	log.Print("AttackJsonLogger Close method not yet implemented...\n")
}

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
// I've tried to use the json.Encoder to do this... and I think we should do it
// that way... but I'm holding off on adding that feature to debug other problems.
//
func (a *AttackJsonLogger) Publish(report *AttackReport) {
	log.Printf("Publish count %d\n", a.count)
	a.count += 1
	b, err := json.Marshal(*report)
	f, err := os.OpenFile(filepath.Join(a.LogDir, fmt.Sprintf("%s.attackreport.json", report.Flow)), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		panic(fmt.Sprintf("error opening file: %v", err))
	}
	defer f.Close()
	f.Write([]byte(fmt.Sprintf("%s\n", string(b))))
}
