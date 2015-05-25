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
	"math"
	"os"
	"time"
)

type RotatingQuotaWriter struct {
	filename  string
	fp        *os.File
	numLogs   int
	logSize   int
	quotaSize int
	sizes     []int
}

// NewRotatingQuotaWriter takes a "starting filename" and a quota size in bytes...
// and guarantees to behave as an io.Writer who will write no more than quotaSize
// bytes to disk.
func NewRotatingQuotaWriter(filename string, quotaSize int) *RotatingQuotaWriter {
	// XXX make this a user configurable option?
	numLogs := 10

	// XXX correcto?
	logSize := int(math.Floor(float64(quotaSize) / float64(numLogs)))

	if logSize*numLogs > quotaSize {
		panic("wtf: logSize * numLogs > quotaSize")
	}

	w := &RotatingQuotaWriter{
		filename:  filename,
		numLogs:   numLogs,
		logSize:   logSize,
		quotaSize: quotaSize,
	}
	return w
}

func (w *RotatingQuotaWriter) Write(output []byte) (int, error) {
	if w.GetCurrentSize()+len(output) > w.quotaSize {
		w.Rotate()
	}
	return w.fp.Write(output)
}

func (w *RotatingQuotaWriter) GetCurrentSize() int {
	total := 0
	for i := 0; i < len(w.sizes); i++ {
		total += w.sizes[i]
	}
	return total
}

func (w *RotatingQuotaWriter) Rotate() {
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

	w.fp, err = os.Create(w.filename)
	if err != nil {
		panic(err)
	}
}

func (w *RotatingQuotaWriter) shiftLog(logNum int) {
	oldName := fmt.Sprintf("%s.%d", w.filename, logNum)

	if logNum == w.numLogs {
		os.Remove(oldName)
		return
	}

	_, err = os.Stat(oldName)
	if os.IsNotExist(err) {
		// if not exit then no-op
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
