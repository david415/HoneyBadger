/*
 *    HoneyBadger report deserialization tool
 *
 *    Copyright (C) 2015  David Stainton
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

package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/david415/HoneyBadger/logging"
	"github.com/fatih/color"
)

func colorLineDiff(a, b string) {
	aLines := strings.Split(a, "\n")
	bLines := strings.Split(b, "\n")

	fmt.Print("Overlapping portion of reassembled TCP Stream:\n")
	for i := 0; i < len(aLines); i++ {
		if aLines[i] == bLines[i] {
			color.Blue(aLines[i])
		} else {
			color.Green(aLines[i])
		}
	}

	fmt.Print("Injection packet whose contents did not coalesce into the TCP Stream:\n")
	for i := 0; i < len(aLines); i++ {
		if aLines[i] == bLines[i] {
			color.Cyan(bLines[i])
		} else {
			color.Red(bLines[i])
		}
	}

}

func expandReport(reportPath string) {
	fmt.Printf("attack report: %s\n", reportPath)
	file, err := os.Open(reportPath)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	reader := bufio.NewReader(file)

	var line string
	line, err = reader.ReadString('\n')
	for err == nil {
		event := logging.SerializedEvent{}
		err = json.Unmarshal([]byte(line), &event)
		if err != nil {
			panic(err)
		}

		fmt.Printf("Event Type: %s\nFlow: %s\nTime: %s\n", event.Type, event.Flow, event.Time)
		fmt.Printf("Packet Number: %d\n", event.PacketCount)
		fmt.Printf("HijackSeq: %d HijackAck: %d\nStart: %d End: %d\nOverlapStart: %d OverlapEnd: %d\n\n", event.HijackSeq, event.HijackAck, event.Start, event.End, event.OverlapStart, event.OverlapEnd)

		var payload []byte
		var overlap []byte

		overlap, err = base64.StdEncoding.DecodeString(event.Overlap)
		if err != nil {
			panic(err)
		}

		payload, err = base64.StdEncoding.DecodeString(event.Payload)
		if err != nil {
			panic(err)
		}

		colorLineDiff(hex.Dump(overlap), hex.Dump(payload))
		line, err = reader.ReadString('\n')
	}
}

func main() {
	var ()
	flag.Parse()
	reports := flag.Args()

	for i := 0; i < len(reports); i++ {
		expandReport(reports[i])
	}
}
