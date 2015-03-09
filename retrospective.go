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
	"container/ring"
	"fmt"
	"github.com/david415/HoneyBadger/types"
	"log"
	"time"
)

func injectionInStreamRing(p PacketManifest, flow *types.TcpIpFlow, ringPtr *ring.Ring, eventType string) *types.Event {
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
	if !bytes.Equal(overlapBytes, p.Payload[startOffset:endOffset]) {
		log.Print("injection attack detected\n")
		e := &types.Event{
			Type:          eventType,
			Time:          time.Now(),
			Flow:          flow,
			Payload:       p.Payload,
			Overlap:       overlapBytes,
			StartSequence: start,
			EndSequence:   end,
			OverlapStart:  startOffset,
			OverlapEnd:    endOffset,
		}
		return e
	} else {
		return nil
	}
}

// getOverlapBytes returns the overlap byte array; that is the contiguous data stored in our ring buffer
// that overlaps with the stream segment specified by the start and end Sequence boundaries.
// The other return values are the slice offsets of the original packet payload that can be used to derive
// the new overlapping portion of the stream segment.
func getOverlapBytes(head, tail *ring.Ring, start, end types.Sequence) ([]byte, int, int) {
	var overlapStartSlice, overlapEndSlice int
	var overlapBytes []byte
	if head == nil || tail == nil {
		panic("wtf; head or tail is nil\n")
	}
	sequenceStart, overlapStartSlice := getStartOverlapSequenceAndOffset(head, start)
	headOffset := getHeadRingOffset(head, sequenceStart)

	sequenceEnd, overlapEndOffset := getEndOverlapSequenceAndOffset(tail, end)
	tailOffset := getTailRingOffset(tail, sequenceEnd)

	if int(head.Value.(types.Reassembly).Seq) == int(tail.Value.(types.Reassembly).Seq) {
		log.Print("head == tail\n")
		endOffset := len(head.Value.(types.Reassembly).Bytes) - tailOffset
		overlapEndSlice = len(head.Value.(types.Reassembly).Bytes) - tailOffset + overlapStartSlice - headOffset
		overlapBytes = head.Value.(types.Reassembly).Bytes[headOffset:endOffset]
	} else {
		log.Print("head != tail\n")
		totalLen := start.Difference(end) + 1
		overlapEndSlice = totalLen - overlapEndOffset
		tailSlice := len(tail.Value.(types.Reassembly).Bytes) - tailOffset
		overlapBytes = getRingSlice(head, tail, headOffset, tailSlice)
		if overlapBytes == nil {
			return nil, 0, 0
		}
	}
	return overlapBytes, overlapStartSlice, overlapEndSlice
}

// getOverlapRings returns the head and tail ring elements corresponding to the first and last
// overlapping ring segments... that overlap with the given packet (PacketManifest).
func getOverlapRings(p PacketManifest, flow *types.TcpIpFlow, ringPtr *ring.Ring) (*ring.Ring, *ring.Ring) {
	var head, tail *ring.Ring
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
func getHeadFromRing(ringPtr *ring.Ring, start, end types.Sequence) *ring.Ring {
	var head, prev *ring.Ring
	current := ringPtr.Prev()
	//current := ringPtr
	_, ok := current.Value.(types.Reassembly)
	if !ok { // do we NOT have any data in our ring buffer?
		return nil
	}
	if start.Difference(current.Value.(types.Reassembly).Seq.Add(len(current.Value.(types.Reassembly).Bytes)-1)) < 0 {
		log.Print("latest ring buffer entry is before start of segment\n")
		log.Printf("lastestSeq %d < newStartSeq %d\n", current.Value.(types.Reassembly).Seq.Add(len(current.Value.(types.Reassembly).Bytes)-1), start)
		return nil
	}
	for current != ringPtr {
		if !ok {
			if prev.Value.(types.Reassembly).Seq.Difference(end) < 0 {
				log.Print("end of segment is before oldest ring buffer entry\n")
				head = nil
				break
			}
			head = prev
			break
		}
		diff := current.Value.(types.Reassembly).Seq.Difference(start)
		if diff == 0 {
			head = current
			break
		} else if diff > 0 {
			diff = start.Difference(current.Value.(types.Reassembly).Seq.Add(len(current.Value.(types.Reassembly).Bytes) - 1))
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
		_, ok = current.Value.(types.Reassembly)
	}
	return head
}

// getTailFromRing returns the oldest ring element that contains the beginning of
// our sequence range (start - end)
func getTailFromRing(head *ring.Ring, end types.Sequence) *ring.Ring {
	var current, prev, tail *ring.Ring
	current = head
	for {
		diff := current.Value.(types.Reassembly).Seq.Add(len(current.Value.(types.Reassembly).Bytes) - 1).Difference(end)
		if diff <= 0 {
			tail = current
			break
		}
		prev = current
		current = current.Next()
		_, ok := current.Value.(types.Reassembly)
		if !ok {
			tail = prev
			break
		}
	}
	return tail
}

// getStartSequence receives a ring pointer and a starting sequence number
// and returns the closest available starting sequence number that is available from the ring.
func getStartSequence(head *ring.Ring, start types.Sequence) types.Sequence {
	var startSeq types.Sequence
	diff := head.Value.(types.Reassembly).Seq.Difference(start)
	if diff >= 0 {
		startSeq = start
	} else {
		startSeq = head.Value.(types.Reassembly).Seq
	}
	return startSeq
}

// getEndSequence receives a ring pointer and an ending sequence number
// and returns the closest available ending sequence number that is available from the ring.
func getEndSequence(tail *ring.Ring, end types.Sequence) types.Sequence {
	var seqEnd types.Sequence
	diff := tail.Value.(types.Reassembly).Seq.Add(len(tail.Value.(types.Reassembly).Bytes) - 1).Difference(end)
	if diff <= 0 {
		seqEnd = end
	} else {
		seqEnd = tail.Value.(types.Reassembly).Seq.Add(len(tail.Value.(types.Reassembly).Bytes) - 1)
	}
	return seqEnd
}

// getRingSlice returns a byte slice from the ring buffer given the head
// and tail of the ring segment. sliceStart indicates the zero-indexed byte offset into
// the head that we should copy from; sliceEnd indicates the number of bytes from the tail
// that we should skip.
func getRingSlice(head, tail *ring.Ring, sliceStart, sliceEnd int) []byte {
	var overlapBytes []byte
	if sliceStart < 0 || sliceEnd < 0 {
		return nil
	}
	if sliceStart >= len(head.Value.(types.Reassembly).Bytes) {
		panic(fmt.Sprintf("getRingSlice: sliceStart %d >= head len %d", sliceStart, len(head.Value.(types.Reassembly).Bytes)))
	}
	if sliceEnd > len(tail.Value.(types.Reassembly).Bytes) {
		panic("impossible; sliceEnd is greater than ring segment")
	}
	if head == tail {
		panic("head == tail")
	}

	overlapBytes = append(overlapBytes, head.Value.(types.Reassembly).Bytes[sliceStart:]...)
	current := head
	current = current.Next()
	for current.Value.(types.Reassembly).Seq != tail.Value.(types.Reassembly).Seq {
		overlapBytes = append(overlapBytes, current.Value.(types.Reassembly).Bytes...)
		current = current.Next()
	}
	overlapBytes = append(overlapBytes, tail.Value.(types.Reassembly).Bytes[:sliceEnd]...)
	return overlapBytes
}

// getHeadRingOffset receives a given ring element and starting sequence number
// and returns the offset into the ring element where the start sequence is found
func getHeadRingOffset(head *ring.Ring, start types.Sequence) int {
	return head.Value.(types.Reassembly).Seq.Difference(start)
}

// getStartOverlapSequenceAndOffset takes a ring element and start sequence and
// returns the closest sequence number available in the element... and the offset
// from the beginning of that element
func getStartOverlapSequenceAndOffset(head *ring.Ring, start types.Sequence) (types.Sequence, int) {
	seqStart := getStartSequence(head, start)
	offset := int(start.Difference(seqStart))
	return seqStart, offset
}

// getRingSegmentLastSequence returns the last sequence number represented by
// a given ring elements stream segment
func getRingSegmentLastSequence(segment *ring.Ring) types.Sequence {
	return segment.Value.(types.Reassembly).Seq.Add(len(segment.Value.(types.Reassembly).Bytes) - 1)
}

// getTailRingOffset returns the number of bytes the from end of the
// ring element's stream segment that the end sequence is found
func getTailRingOffset(tail *ring.Ring, end types.Sequence) int {
	tailEndSequence := getRingSegmentLastSequence(tail)
	return end.Difference(tailEndSequence)
}

// getEndOverlapSequenceAndOffset receives a ring element and end sequence.
// It returns the last sequence number represented by that ring element and the offset from the end.
func getEndOverlapSequenceAndOffset(tail *ring.Ring, end types.Sequence) (types.Sequence, int) {
	seqEnd := getEndSequence(tail, end)
	offset := int(seqEnd.Difference(end))
	return seqEnd, offset
}
