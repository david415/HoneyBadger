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
	"bytes"
	"fmt"
	"github.com/david415/HoneyBadger/types"
	"log"
	"time"
)

func injectionInStreamRing(p PacketManifest, flow *types.TcpIpFlow, ringPtr *types.Ring, eventType string) *types.Event {
	start := types.Sequence(p.TCP.Seq)
	end := start.Add(len(p.Payload) - 1)
	head, tail := getOverlapRings(p, flow, ringPtr)

	if head == nil || tail == nil {
		return nil
	}

	overlapBytes, startOffset, endOffset := getOverlapBytes(head, tail, start, end)

	if overlapBytes == nil {
		return nil
	}

	log.Printf("len overlapBytes %d startOffset %d endOffset %d\n", len(overlapBytes), startOffset, endOffset)

	if !bytes.Equal(overlapBytes, p.Payload[startOffset:endOffset]) {
		log.Print("injection attack detected\n")
		e := &types.Event{
			Type:          eventType,
			Time:          time.Now(),
			Flow:          flow,
			Payload:       p.Payload,
			StartSequence: start,
			EndSequence:   end,
			OverlapStart:  startOffset,
			OverlapEnd:    endOffset,
		}
		copy(e.Overlap, overlapBytes)

		return e
	} else {
		return nil
	}
}

// getOverlapBytes takes several arguments:
// head and tail - ring pointers used to indentify a list of ring elements.
// start and end - sequence numbers representing locations in head and tail respectively.
// NOTE: here we assume that the head and tail were calculated properly such that:
// 1. start must be located within the head segment's sequence boundaries or BEFORE.
// 2. end must be located within the tail segment's sequence boundaries or AFTER.
// normally head and tail values would be procured with a call to getOverlapRings like this:
//	head, tail := getOverlapRings(p, flow, ringPtr)
// Given these arguments, getOverlapBytes returns the overlap byte array;
// that is the contiguous data stored in our ring buffer
// that overlaps with the stream segment specified by the start and end Sequence boundaries.
// The other return values are the slice offsets of the original packet payload that can be used to derive
// calculate the section of the packet that has overlapped with our Reassembly ring buffer.
func getOverlapBytes(head, tail *types.Ring, start, end types.Sequence) ([]byte, int, int) {
	var overlapStartSlice, overlapEndSlice int
	var overlapBytes []byte

	if head == nil || tail == nil {
		panic("wtf; head or tail is nil\n")
	}
	if len(head.Reassembly.Bytes) == 0 {
		panic("length of head ring element is zero")
	}
	if len(tail.Reassembly.Bytes) == 0 {
		panic("length of tail ring element is zero")
	}

	packetLength := start.Difference(end)
	if packetLength <= 0 {
		panic("wtf")
	}
	var headOffset int
	tailLastSeq := tail.Reassembly.Seq.Add(len(tail.Reassembly.Bytes) - 1)
	diff := head.Reassembly.Seq.Difference(start)
	if diff < 0 {
		headOffset = 0
		overlapStartSlice = -1 * diff
	} else if diff == 0 {
		headOffset = 0
		overlapStartSlice = 0
	} else {
		headOffset = diff
		overlapStartSlice = 0
	}
	if head.Reassembly.Seq == tail.Reassembly.Seq {
		log.Print("head == tail\n")
		var endOffset int
		diff = tailLastSeq.Difference(end)
		if diff <= 0 {
			overlapEndSlice = packetLength + 1
			tailDiff := end.Difference(tailLastSeq)
			endOffset = len(head.Reassembly.Bytes) - tailDiff
		} else {
			overlapEndSlice = packetLength - diff + 1
			endOffset = len(head.Reassembly.Bytes)
			log.Printf("endOffset %d diff %d", endOffset, diff)
		}
		log.Printf("len head %d headOffset %d endOffset %d", len(head.Reassembly.Bytes), headOffset, endOffset)
		overlapBytes = head.Reassembly.Bytes[headOffset:endOffset]
	} else {
		log.Print("head != tail\n")
		diff = tailLastSeq.Difference(end)
		var tailSlice int
		// if end is equal or less than tailLastSeq
		if diff <= 0 {
			overlapEndSlice = packetLength
			if (-1 * diff) > len(tail.Reassembly.Bytes) {
				tailSlice = len(tail.Reassembly.Bytes)
			} else {
				tailSlice = len(tail.Reassembly.Bytes) - (diff * -1)
			}
		} else {
			overlapEndSlice = packetLength - diff + 1
			tailSlice = len(tail.Reassembly.Bytes)
		}
		overlapBytes = getRingSlice(head, tail, headOffset, tailSlice)
		if overlapBytes == nil {
			return nil, 0, 0
		}
	}
	log.Printf("len overlapBytes %d overlapStartSlice %d overlapEndSlice %d", len(overlapBytes), overlapStartSlice, overlapEndSlice)
	return overlapBytes, overlapStartSlice, overlapEndSlice
}

// getOverlapRings returns the head and tail ring elements corresponding to the first and last
// overlapping ring segments... that overlap with the given packet (PacketManifest).
func getOverlapRings(p PacketManifest, flow *types.TcpIpFlow, ringPtr *types.Ring) (*types.Ring, *types.Ring) {
	var head, tail *types.Ring
	start := types.Sequence(p.TCP.Seq)
	end := start.Add(len(p.Payload) - 1)
	head = getHeadFromRing(ringPtr, start, end)
	if head == nil {
		return nil, nil
	}
	tail = getTailFromRing(head, end)
	return head, tail
}

// getHeadFromRing returns a pointer to the oldest ring element that
// contains the beginning of our sequence range (start - end)
func getHeadFromRing(ringPtr *types.Ring, start, end types.Sequence) *types.Ring {
	var head *types.Ring
	current := ringPtr.Prev()
	if current.Reassembly == nil {
		return nil
	}
	if start.Difference(current.Reassembly.Seq.Add(len(current.Reassembly.Bytes)-1)) < 0 {
		log.Printf("lastestSeq %d < newStartSeq %d\n", current.Reassembly.Seq.Add(len(current.Reassembly.Bytes)-1), start)
		return nil
	}
	for prev, current := ringPtr, ringPtr.Prev(); current != ringPtr; prev, current = current, current.Prev() {
		if current.Reassembly == nil {
			if prev.Reassembly != nil {
				if prev.Reassembly.Seq.Difference(end) < 0 {
					log.Print("end of segment is before oldest ring buffer entry\n")
					head = nil
					break
				}
				head = prev
				break
			} else {
				return nil
			}
		}
		if len(current.Reassembly.Bytes) == 0 {
			panic("zero length payload in ring. wtf.")
		}
		diff := current.Reassembly.Seq.Difference(start)
		if diff == 0 {
			head = current
			break
		} else if diff > 0 {
			diff = start.Difference(current.Reassembly.Seq.Add(len(current.Reassembly.Bytes) - 1))
			if diff >= 0 {
				head = current
				break
			}
		}
	}
	return head
}

// getTailFromRing returns the oldest ring element that contains the beginning of
// our sequence range (start - end)
func getTailFromRing(head *types.Ring, end types.Sequence) *types.Ring {
	for r := head; r != head.Prev(); r = r.Next() {
		if r.Reassembly == nil {
			return r.Prev()
		}
		diff := r.Reassembly.Seq.Add(len(r.Reassembly.Bytes) - 1).Difference(end)
		if diff <= 0 {
			return r
		}
	}
	return nil
}

// getStartSequence receives a ring pointer and a starting sequence number
// and returns the closest available starting sequence number that is available from the ring.
func getStartSequence(head *types.Ring, start types.Sequence) types.Sequence {
	var startSeq types.Sequence
	diff := head.Reassembly.Seq.Difference(start)
	if diff >= 0 {
		startSeq = start
	} else {
		startSeq = head.Reassembly.Seq
	}
	return startSeq
}

// getRingSlice returns a byte slice from the ring buffer given the head
// and tail of the ring segment AND the slice indexes for head and tail.
// That is, for head's byte slice, sliceStart is the a slice start index.
// For tail's byte slice, sliceEnd is the slice end index.
func getRingSlice(head, tail *types.Ring, sliceStart, sliceEnd int) []byte {
	var overlapBytes []byte
	if sliceStart < 0 || sliceEnd < 0 {
		log.Printf("sliceStart %d sliceEnd %d", sliceStart, sliceEnd)
		panic("sliceStart < 0 || sliceEnd < 0")
	}
	if sliceStart >= len(head.Reassembly.Bytes) {
		panic(fmt.Sprintf("getRingSlice: sliceStart %d >= head len %d", sliceStart, len(head.Reassembly.Bytes)))
	}
	if sliceEnd > len(tail.Reassembly.Bytes) {
		panic("impossible; sliceEnd is greater than ring segment")
	}
	if head == nil || tail == nil {
		panic("head or tail is nil")
	}
	if head == tail {
		panic("head == tail")
	}
	overlapBytes = append(overlapBytes, head.Reassembly.Bytes[sliceStart:]...)
	current := head.Next()
	for current.Reassembly.Seq != tail.Reassembly.Seq {
		overlapBytes = append(overlapBytes, current.Reassembly.Bytes...)
		current = current.Next()
	}
	overlapBytes = append(overlapBytes, tail.Reassembly.Bytes[:sliceEnd]...)
	return overlapBytes
}
