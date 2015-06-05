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

package types

import (
	"time"
)

type Logger interface {
	Log(r *Event)
}

type PacketLogger interface {
	WritePacket(rawPacket []byte, timestamp time.Time)
	Start()
	Stop()
	Remove()
	Archive()
}

type PacketLoggerFactory interface {
	Build(*TcpIpFlow) PacketLogger
}

type Event struct {
	Type          string
	PacketCount   uint64
	Flow          *TcpIpFlow
	Time          time.Time
	HijackSeq     uint32
	HijackAck     uint32
	Payload       []byte
	Overlap       []byte
	StartSequence Sequence
	EndSequence   Sequence
	OverlapStart  int
	OverlapEnd    int
}
