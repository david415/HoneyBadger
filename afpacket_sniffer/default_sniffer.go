// +build !linux

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

package afpacket_sniffer

import (
	"github.com/google/gopacket"
)

type AfpacketHandle struct {
}

func NewAfpacketHandle(netDevice string) (*AfpacketHandle, error) {
	return &AfpacketHandle{}, nil
}

func (a *AfpacketHandle) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	panic("AF_PACKET not supported by non-Linux systems")
}

func (a *AfpacketHandle) Close() {
}
