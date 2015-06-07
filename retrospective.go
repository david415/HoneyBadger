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

package HoneyBadger

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/david415/HoneyBadger/types"
	"log"
	"time"
)

func displayRingSummary(ringHeadPtr *types.Ring) {
	log.Print("displayRingSummary:")
	i := 0
	current := ringHeadPtr.Next()
	for current != ringHeadPtr {
		if current.Reassembly != nil {
			log.Printf("index: %d TCP.Seq %d Skip %d payload len %d\n", i, current.Reassembly.Seq, current.Reassembly.Skip, len(current.Reassembly.Bytes))
		} else {
			log.Printf("index: %d nil\n", i)
		}
		current = current.Next()
		i += 1
	}
}

func injectionInStreamRing(p *types.PacketManifest, flow *types.TcpIpFlow, ringPtr *types.Ring, eventType string, packetCount uint64) *types.Event {
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
	if len(overlapBytes) > len(p.Payload) {
		log.Printf("impossible: overlapBytes length greater than payload length at packet # %d", packetCount)
		return nil
	}
	if startOffset >= endOffset {
		log.Print("impossible: startOffset >= endOffset")
		return nil
	}
	if endOffset > len(p.Payload) {
		log.Print("impossible: endOffset greater than payload length")
		return nil
	}

	log.Printf("len overlapBytes %d startOffset %d endOffset %d\n", len(overlapBytes), startOffset, endOffset)

	if len(overlapBytes) != len(p.Payload[startOffset:endOffset]) {
		log.Printf("impossible: %d != %d len overlapBytes is not equal to payload slice", len(overlapBytes), len(p.Payload[startOffset:endOffset]))
		return nil
	}

	if !bytes.Equal(overlapBytes, p.Payload[startOffset:endOffset]) {
		log.Printf("injection attack detected at packet # %d with TCP.Seq %d\n", packetCount, p.TCP.Seq)
		log.Printf("len overlapBytes %d len Payload slice %d\n", len(overlapBytes), len(p.Payload[startOffset:endOffset]))
		log.Print("overlapBytes:")
		log.Print(hex.Dump(overlapBytes))
		log.Print("packet payload slice:")
		log.Print(hex.Dump(p.Payload[startOffset:endOffset]))

		e := &types.Event{
			Type:          eventType,
			PacketCount:   packetCount,
			Time:          time.Now(),
			Flow:          flow,
			Payload:       p.Payload,
			Overlap:       overlapBytes,
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
// the section of the packet that has overlapped with our Reassembly ring buffer.
func getOverlapBytes(head, tail *types.Ring, start, end types.Sequence) ([]byte, int, int) {
	var overlapStartSlice, overlapEndSlice int
	var overlapBytes []byte
	var diff int

	if head == nil || tail == nil {
		panic("wtf; head or tail is nil\n")
	}
	if len(head.Reassembly.Bytes) == 0 {
		panic("length of head ring element is zero")
	}
	if len(tail.Reassembly.Bytes) == 0 {
		panic("length of tail ring element is zero")
	}

	packetLength := start.Difference(end) + 1
	if packetLength <= 0 {
		panic("wtf")
	}
	var headOffset int
	tailLastSeq := tail.Reassembly.Seq.Add(len(tail.Reassembly.Bytes) - 1)
	startDiff := head.Reassembly.Seq.Difference(start)
	if startDiff < 0 {
		headOffset = 0
		overlapStartSlice = -1 * startDiff
		if overlapStartSlice > packetLength {
			// XXX print a error message here or panic?
			log.Print("getOverlapbytes: incorrect start/end head/tail parameters.")
			return nil, 0, 0
		}
	} else if startDiff == 0 {
		headOffset = 0
		overlapStartSlice = 0
	} else {
		headOffset = startDiff
		overlapStartSlice = 0
	}
	if head.Reassembly.Seq == tail.Reassembly.Seq {
		log.Print("head == tail\n")
		var endOffset int
		diff = tailLastSeq.Difference(end)
		if diff <= 0 {
			overlapEndSlice = packetLength
			tailDiff := end.Difference(tailLastSeq)
			endOffset = len(head.Reassembly.Bytes) - tailDiff
		} else {
			overlapEndSlice = packetLength - diff
			endOffset = len(head.Reassembly.Bytes)
		}
		overlapBytes = head.Reassembly.Bytes[headOffset:endOffset]
	} else {
		log.Print("head != tail\n")
		diff = tailLastSeq.Difference(end)
		var tailSlice int
		// if end is equal or less than tailLastSeq
		if diff <= 0 {
			overlapEndSlice = packetLength
			tailSlice = len(tail.Reassembly.Bytes) - (diff * -1)
			if tailSlice < 0 {
				panic("regression in getTailFromRing")
			}
		} else {
			if diff > packetLength {
				// XXX should we opt out instead of making the comparison?
				overlapEndSlice = packetLength
			} else {
				overlapEndSlice = packetLength - diff
				if overlapEndSlice < overlapStartSlice {
					// XXX wtf
					return nil, 0, 0
				}
			}
			tailSlice = len(tail.Reassembly.Bytes)
		}
		overlapBytes = getRingSlice(head, tail, headOffset, tailSlice)
		if overlapBytes == nil {
			return nil, 0, 0
		}
	}
	return overlapBytes, overlapStartSlice, overlapEndSlice
}

// getOverlapRings returns the head and tail ring elements corresponding to the first and last
// overlapping ring segments... that overlap with the given packet (types.PacketManifest).
// Furthermore geOverlapRings also will make sure none of these ring elements will have a Reassembly.Skip value
// other than 0 (zero).
func getOverlapRings(p *types.PacketManifest, flow *types.TcpIpFlow, ringPtr *types.Ring) (*types.Ring, *types.Ring) {
	var head, tail *types.Ring
	start := types.Sequence(p.TCP.Seq)
	end := start.Add(len(p.Payload) - 1)
	head = getHeadFromRing(ringPtr, start, end)
	if head == nil {
		return nil, nil
	}
	tail = getTailFromRing(head, end)
	if tail == nil {
		return head, head
	}
	return head, tail
}

// getHeadFromRing returns a pointer to the oldest ring element that
// contains the beginning of our sequence range (start - end) AND
// whose Reassembly.Skip value is 0 (zero).
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
	head = nil
	var candidate *types.Ring = nil

	for current := ringPtr.Prev(); current != ringPtr && current.Reassembly != nil; current = current.Prev() {
		if len(current.Reassembly.Bytes) == 0 {
			continue
		}

		startDiff := current.Reassembly.Seq.Difference(start)
		if startDiff == 0 {
			return current
		}
		if startDiff < 0 {
			finishEndDiff := current.Reassembly.Seq.Difference(end)
			if finishEndDiff >= 0 {
				candidate = current
			}

			continue
		} else {
			endDiff := start.Difference(current.Reassembly.Seq.Add(len(current.Reassembly.Bytes) - 1))
			if endDiff >= 0 {
				head = current
				break
			}
		}
	}
	if head == nil && candidate != nil {
		head = candidate
	}
	return head
}

// getTailFromRing returns the oldest ring element that contains the beginning of
// our sequence range (start - end) and whose range of ring segments all
// have their Reassembly.Skip value set to 0 (zero).
func getTailFromRing(head *types.Ring, end types.Sequence) *types.Ring {
	var ret *types.Ring

	for r := head; r != head.Prev(); r = r.Next() {
		if r.Reassembly == nil {
			ret = r.Prev()
			break
		}
		if len(r.Reassembly.Bytes) == 0 {
			log.Print("getTailFromRing: zero payload ring segment encountered.")
			ret = r.Prev()
			break
		}
		if r.Reassembly.Skip != 0 {
			log.Print("getTailFromRing: stream skip encountered.")
			ret = r.Prev()
			break
		}
		diff := r.Reassembly.Seq.Difference(end)
		if diff < 0 {
			return r.Prev()
		}
	}

	// XXX
	// prevent bug where the above sets ret to head.Prev()
	if ret == head.Prev() {
		return nil
	} else {
		return ret
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
		panic("getRingSlice: sliceStart < 0 || sliceEnd < 0")
	}
	if sliceStart >= len(head.Reassembly.Bytes) {
		panic(fmt.Sprintf("getRingSlice: sliceStart %d >= head len %d", sliceStart, len(head.Reassembly.Bytes)))
	}
	if sliceEnd > len(tail.Reassembly.Bytes) {
		panic("getRingSlice: impossible; sliceEnd is greater than ring segment")
	}
	if head == nil || tail == nil {
		panic("getRingSlice: head or tail is nil")
	}
	if head == tail {
		panic("getRingSlice: head == tail")
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
