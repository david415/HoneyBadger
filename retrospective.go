/*
 *    retrospective.go - HoneyBadger core library for detecting TCP attacks
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
	"container/ring"
	"fmt"
	"log"
)

func getHeadFromRing(ringPtr *ring.Ring, start, end tcpassembly.Sequence) *ring.Ring {
	var head, prev *ring.Ring
	current := ringPtr.Prev()
	_, ok := current.Value.(Reassembly)
	if !ok { // do we NOT have any data in our ring buffer?
		log.Print("ring buffer is still empty\n")
		return nil
	}
	if start.Difference(current.Value.(Reassembly).Seq.Add(len(current.Value.(Reassembly).Bytes)-1)) < 0 {
		log.Print("latest ring buffer entry is before start of segment\n")
		log.Printf("lastestSeq %d < newStartSeq %d\n", current.Value.(Reassembly).Seq.Add(len(current.Value.(Reassembly).Bytes)-1), start)
		log.Printf("lastest ring payload:%s\n", string(current.Value.(Reassembly).Bytes))
		return nil
	}
	for current != ringPtr {
		if !ok {
			if prev.Value.(Reassembly).Seq.Difference(end) < 0 {
				log.Print("end of segment is before oldest ring buffer entry\n")
				head = nil
				break
			}
			head = prev
			break
		}
		diff := current.Value.(Reassembly).Seq.Difference(start)
		if diff == 0 {
			head = current
			break
		} else if diff > 0 {
			diff = start.Difference(current.Value.(Reassembly).Seq.Add(len(current.Value.(Reassembly).Bytes) - 1))
			if diff == 0 {
				head = current
				break
			} else if diff > 0 {
				head = current
				break
			}
		}
		prev = current
		current = current.Prev()
		_, ok = current.Value.(Reassembly)
	}
	return head
}

func getTailFromRing(head *ring.Ring, end tcpassembly.Sequence) *ring.Ring {
	var current, prev, tail *ring.Ring
	current = head
	for {
		diff := current.Value.(Reassembly).Seq.Add(len(current.Value.(Reassembly).Bytes) - 1).Difference(end)
		if diff <= 0 {
			tail = current
			break
		}
		prev = current
		current = current.Next()
		_, ok := current.Value.(Reassembly)
		if !ok {
			tail = prev
			break
		}
	}
	return tail
}

func getStartSequence(head *ring.Ring, start tcpassembly.Sequence) tcpassembly.Sequence {
	var startSeq tcpassembly.Sequence
	diff := head.Value.(Reassembly).Seq.Difference(start)
	if diff >= 0 {
		startSeq = start
	} else {
		startSeq = head.Value.(Reassembly).Seq
	}
	return startSeq
}

func getEndSequence(tail *ring.Ring, end tcpassembly.Sequence) tcpassembly.Sequence {
	var seqEnd tcpassembly.Sequence
	diff := tail.Value.(Reassembly).Seq.Add(len(tail.Value.(Reassembly).Bytes) - 1).Difference(end)
	if diff <= 0 {
		seqEnd = end
	} else {
		seqEnd = tail.Value.(Reassembly).Seq.Add(len(tail.Value.(Reassembly).Bytes) - 1)
	}
	return seqEnd
}

// getRingSlice returns a byte slice from the ring buffer given the head
// and tail of the ring segment. sliceStart indicates the zero-indexed byte offset into
// the head that we should copy from; sliceEnd indicates the number of bytes into tail.
func getRingSlice(head, tail *ring.Ring, sliceStart, sliceEnd int) []byte {
	var overlapBytes []byte
	if sliceStart < 0 || sliceEnd < 0 {
		panic("sliceStart < 0 || sliceEnd < 0")
	}
	if sliceStart >= len(head.Value.(Reassembly).Bytes) {
		panic(fmt.Sprintf("getRingSlice: sliceStart %d >= head len %d", sliceStart, len(head.Value.(Reassembly).Bytes)))
	}
	if sliceEnd > len(tail.Value.(Reassembly).Bytes) {
		panic("impossible; sliceEnd is greater than ring segment")
	}
	if head == tail {
		panic("head == tail")
	}

	overlapBytes = append(overlapBytes, head.Value.(Reassembly).Bytes[sliceStart:]...)
	current := head
	current = current.Next()
	for current.Value.(Reassembly).Seq != tail.Value.(Reassembly).Seq {
		overlapBytes = append(overlapBytes, current.Value.(Reassembly).Bytes...)
		current = current.Next()
	}
	overlapBytes = append(overlapBytes, tail.Value.(Reassembly).Bytes[:sliceEnd]...)
	return overlapBytes
}

func getHeadRingOffset(head *ring.Ring, start tcpassembly.Sequence) int {
	return head.Value.(Reassembly).Seq.Difference(start)
}

func getStartOverlapSequenceAndOffset(head *ring.Ring, start tcpassembly.Sequence) (tcpassembly.Sequence, int) {
	seqStart := getStartSequence(head, start)
	offset := int(start.Difference(seqStart))
	return seqStart, offset
}

func getRingSegmentLastSequence(segment *ring.Ring) tcpassembly.Sequence {
	return segment.Value.(Reassembly).Seq.Add(len(segment.Value.(Reassembly).Bytes) - 1)
}

func getTailRingOffset(tail *ring.Ring, end tcpassembly.Sequence) int {
	tailEndSequence := getRingSegmentLastSequence(tail)
	return end.Difference(tailEndSequence)
}

func getEndOverlapSequenceAndOffset(tail *ring.Ring, end tcpassembly.Sequence) (tcpassembly.Sequence, int) {
	seqEnd := getEndSequence(tail, end)
	offset := int(seqEnd.Difference(end))
	return seqEnd, offset
}
