/*
 *    HoneyBadger core library for detecting TCP injection attacks
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

package logging

import (
	"fmt"
	"math"
	"os"
)

type RotatingQuotaWriter struct {
	filename        string
	fp              *os.File
	numLogs         int
	logSize         int
	quotaSizeBytes  int
	sizes           []int
	headerFunc      func()
	mustWriteHeader bool
}

// NewRotatingQuotaWriter takes a "starting filename" and a quota size in bytes...
// and guarantees to behave as an io.Writer who will write no more than quotaSize
// bytes to disk. `headerFunc` is executed upon the new file, after each rotation.
func NewRotatingQuotaWriter(filename string, quotaSize int, numLogs int, headerFunc func()) *RotatingQuotaWriter {
	quotaSizeBytes := quotaSize * 1024 * 1024
	logSize := int(math.Floor(float64(quotaSizeBytes) / float64(numLogs)))
	if logSize*numLogs > quotaSizeBytes {
		panic("wtf: logSize * numLogs > quotaSize")
	}
	w := &RotatingQuotaWriter{
		filename:        filename,
		numLogs:         numLogs,
		logSize:         logSize,
		quotaSizeBytes:  quotaSizeBytes,
		headerFunc:      headerFunc,
		sizes:           make([]int, numLogs),
		fp:              nil,
		mustWriteHeader: true,
	}
	return w
}

func (w *RotatingQuotaWriter) Write(output []byte) (int, error) {
	var err error
	if w.fp == nil {
		w.fp, err = os.Create(w.filename)
		if err != nil {
			panic(err)
		}
		w.mustWriteHeader = true
		w.headerFunc()
		w.sizes[0] += len(output)
		return w.fp.Write(output)
	}
	if w.mustWriteHeader {
		w.mustWriteHeader = false
		w.sizes[0] += len(output)
		return w.fp.Write(output)
	}
	if w.sizes[0]+len(output) > w.logSize {
		w.rotate()
		// pop
		w.sizes = w.sizes[0 : len(w.sizes)-1]
		// push
		new := make([]int, 1, 10)
		new[0] = len(output)
		w.sizes = append(new, w.sizes...)
		w.fp, err = os.Create(w.filename)
		if err != nil {
			panic(err)
		}
	} else {
		w.sizes[0] += len(output)
	}
	return w.fp.Write(output)
}

func (w *RotatingQuotaWriter) Close() error {
	err := w.fp.Close()
	w.fp = nil
	return err
}

func (w *RotatingQuotaWriter) rotate() {
	var err error
	if w.fp != nil {
		err = w.fp.Close()
		w.fp = nil
		if err != nil {
			panic(err)
		}
	}
	for i := w.numLogs; i > 0; i-- {
		w.shiftLog(i)
	}
	newName := fmt.Sprintf("%s.1", w.filename)
	err = os.Rename(w.filename, newName)
	if err != nil {
		panic(err)
	}
}

func (w *RotatingQuotaWriter) shiftLog(logNum int) {
	var err error
	oldName := fmt.Sprintf("%s.%d", w.filename, logNum)
	if logNum == w.numLogs {
		os.Remove(oldName)
		return
	}
	_, err = os.Stat(oldName)
	if os.IsNotExist(err) {
		return
	} else if err != nil {
		panic(err)
	}
	newName := fmt.Sprintf("%s.%d", w.filename, logNum+1)
	err = os.Rename(oldName, newName)
	if err != nil {
		panic(err)
	}
}
