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
	"io"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"

	"github.com/david415/HoneyBadger/types"
)


func init() {
	SnifferRegister("pcapgo", NewPcapgoHandle)
}

type PcapgoHandle struct {
	reader *pcapgo.Reader
	fileReader io.ReadCloser
}

func NewPcapgoHandle(options *types.SnifferDriverOptions) (types.PacketDataSourceCloser, error) {
	fileReader, err := os.Open(options.Filename)
	if err != nil {
		return nil, err
	}

	reader, err := pcapgo.NewReader(fileReader)
	if err != nil {
		return nil, err
	}
	return &PcapgoHandle{
		reader: reader,
		fileReader: fileReader,
	}, nil
}

func (a *PcapgoHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	data, ci, err := a.reader.ReadPacketData()
	return data, ci, err
}

func (a *PcapgoHandle) Close() error {
	return a.fileReader.Close()
}
