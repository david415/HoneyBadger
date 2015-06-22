// +build darwin dragonfly freebsd netbsd openbsd

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

package drivers

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/bsdbpf"

	"github.com/david415/HoneyBadger/types"
)

func init() {
	SnifferRegister("BSD_BPF", NewBPFHandle)
}

type BPFHandle struct {
	bpfSniffer *bsdbpf.BPFSniffer
}

func NewBPFHandle(options *types.SnifferDriverOptions) (types.PacketDataSourceCloser, error) {
	// XXX TODO pass more options...
	bpfSniffer, err := bsdbpf.NewBPFSniffer(options.Device, nil)
	return &BPFHandle{
		bpfSniffer: bpfSniffer,
	}, err
}

func (a *BPFHandle) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	return a.bpfSniffer.ReadPacketData()
}

func (a *BPFHandle) Close() error {
	return a.bpfSniffer.Close()
}
