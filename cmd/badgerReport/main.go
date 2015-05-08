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
	"log"
	"os"

	"encoding/base64"
	"encoding/json"
	"github.com/david415/HoneyBadger/logging"
)

func expandReport(reportPath string) {
	log.Printf("expandReport: reportPath %s", reportPath)
	file, err := os.Open(reportPath)
	if err != nil {
		log.Fatal(err)
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

		log.Printf("Event Type %s Flow %s Time %s\n", event.Type, event.Flow, event.Time)
		log.Printf("HijackSeq %d HijackAck %d Start %d End %d OverlapStart %d OverlapEnd %d\n", event.HijackSeq, event.HijackAck, event.Start, event.End, event.OverlapStart, event.OverlapEnd)

		var payload []byte
		var overlap []byte

		overlap, err = base64.StdEncoding.DecodeString(event.Payload)
		if err != nil {
			panic(err)
		}
		log.Printf("\n\noverlap: %s\n\n", overlap)

		payload, err = base64.StdEncoding.DecodeString(event.Payload)
		if err != nil {
			panic(err)
		}
		log.Printf("\n\npayload: %s\n\n", payload)

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
