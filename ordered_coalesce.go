/*
 *    packet_reorder.go - tcp packet reordering
 *
 *    I include google's license because this code is copy-pasted and refactored
 *    from the original, Google's gopacket.tcpassembly...
 *    Thanks to Graeme Connel for writing tcpassembly!
 */

// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE_BSD file in the root of the source
// tree.

package HoneyBadger

import (
	"github.com/david415/HoneyBadger/types"
	"github.com/google/gopacket/layers"
	"log"
	"time"
)

const pageBytes = 1900

const memLog = true // XXX get rid of me later...

// page is used to store TCP data we're not ready for yet (out-of-order
// packets).  Unused pages are stored in and returned from a pageCache, which
// avoids memory allocation.  Used pages are stored in a doubly-linked list in
// an OrderedCoalesce.
type page struct {
	types.Reassembly
	index      int
	prev, next *page
	buf        [pageBytes]byte
}

// pageCache is a concurrency-unsafe store of page objects we use to avoid
// memory allocation as much as we can.  It grows but never shrinks.
type pageCache struct {
	free         []*page
	pcSize       int
	size, used   int
	pages        [][]page
	pageRequests int64
}

const initialAllocSize = 1024

func newPageCache() *pageCache {
	pc := &pageCache{
		free:   make([]*page, 0, initialAllocSize),
		pcSize: initialAllocSize,
	}
	pc.grow()
	return pc
}

// grow exponentially increases the size of our page cache as much as necessary.
func (c *pageCache) grow() {
	pages := make([]page, c.pcSize)
	c.pages = append(c.pages, pages)
	c.size += c.pcSize
	for i := range pages {
		c.free = append(c.free, &pages[i])
	}
	if memLog {
		log.Println("PageCache: created", c.pcSize, "new pages")
	}
	c.pcSize *= 2
}

// next returns a clean, ready-to-use page object.
func (c *pageCache) next(ts time.Time) (p *page) {
	if memLog {
		c.pageRequests++
		if c.pageRequests&0xFFFF == 0 {
			log.Println("PageCache:", c.pageRequests, "requested,", c.used, "used,", len(c.free), "free")
		}
	}
	if len(c.free) == 0 {
		c.grow()
	}
	i := len(c.free) - 1
	p, c.free = c.free[i], c.free[:i]
	p.prev = nil
	p.next = nil
	p.Seen = ts
	p.Bytes = p.buf[:0]
	c.used++
	return p
}

// replace replaces a page into the pageCache.
func (c *pageCache) replace(p *page) {
	c.used--
	c.free = append(c.free, p)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func byteSpan(expected, received types.Sequence, bytes []byte) (toSend []byte, next types.Sequence) {
	if expected == types.InvalidSequence {
		return bytes, received.Add(len(bytes))
	}
	span := int(received.Difference(expected))
	if span <= 0 {
		return bytes, received.Add(len(bytes))
	} else if len(bytes) < span {
		return nil, expected
	}
	return bytes[span:], expected.Add(len(bytes) - span)
}

type OrderedCoalesce struct {
	// MaxBufferedPagesTotal is an upper limit on the total number of pages to
	// buffer while waiting for out-of-order packets.  Once this limit is
	// reached, the assembler will degrade to flushing every connection it
	// gets a packet for.  If <= 0, this is ignored.
	MaxBufferedPagesTotal int
	// MaxBufferedPagesPerConnection is an upper limit on the number of pages
	// buffered for a single flow.  Should this limit be reached for a
	// particular flow, the smallest sequence number will be flushed, along
	// with any contiguous data.  If <= 0, this is ignored.
	MaxBufferedPagesPerFlow int

	Flow                    *types.TcpIpFlow
	StreamRing              *types.Ring
	log                     types.Logger
	pageCount               int
	pager                   *Pager
	first, last             *page
	DetectCoalesceInjection bool
}

func NewOrderedCoalesce(log types.Logger, flow *types.TcpIpFlow, pager *Pager, streamRing *types.Ring, maxBufferedPagesTotal, maxBufferedPagesPerFlow int, DetectCoalesceInjection bool) *OrderedCoalesce {
	return &OrderedCoalesce{
		log:        log,
		Flow:       flow,
		pager:      pager,
		StreamRing: streamRing,

		MaxBufferedPagesTotal:   maxBufferedPagesTotal,
		MaxBufferedPagesPerFlow: maxBufferedPagesPerFlow,
	}
}

// Close returns all used pages to the page cache via the Pager
func (o *OrderedCoalesce) Close() {
	o.pager.ReplaceAllFrom(o.first)
}

func (o *OrderedCoalesce) insert(packetManifest types.PacketManifest, nextSeq types.Sequence) (types.Sequence, bool) {
	isEnd := false
	if o.first != nil && o.first.Seq == nextSeq {
		panic("wtf")
	}
	// XXX for now we ignore zero size packets
	if len(packetManifest.Payload) == 0 {
		return nextSeq, false
	}
	if o.pageCount < 0 {
		panic("OrderedCoalesce.insert pageCount less than zero")
	}
	// XXX todo: handle out of order FIN and RST packets
	p, p2, pcount := o.pagesFromTcp(packetManifest)
	prev, current := o.traverse(types.Sequence(packetManifest.TCP.Seq))
	o.pushBetween(prev, current, p, p2)
	o.pageCount += pcount
	if (o.MaxBufferedPagesPerFlow > 0 && o.pageCount >= o.MaxBufferedPagesPerFlow) ||
		(o.MaxBufferedPagesTotal > 0 && o.pager.Used() >= o.MaxBufferedPagesTotal) {
		log.Printf("%v hit max buffer size: MaxBufferedPagesTotal %d, MaxBufferedPagesPerFlow %d, pageCount %d, pages Used %d", packetManifest.Flow.String(), o.MaxBufferedPagesTotal, o.MaxBufferedPagesPerFlow, o.pageCount, o.pager.Used())
		if o.pageCount < 0 {
			panic("OrderedCoalesce.insert pageCount less than zero")
		}
		nextSeq, isEnd = o.flushUntilThreshold(nextSeq)
	} // end of if
	return nextSeq, isEnd
}

func (o *OrderedCoalesce) flushUntilThreshold(nextSeq types.Sequence) (types.Sequence, bool) {
	isEnd := false
	nextSeq, isEnd = o.addNext(nextSeq)
	if isEnd {
		return nextSeq, true
	}
	nextSeq, isEnd = o.addContiguous(nextSeq)
	if isEnd {
		return nextSeq, true
	}
	for o.pageCount >= o.MaxBufferedPagesPerFlow || o.pager.Used() >= o.MaxBufferedPagesTotal {
		if o.first == nil {
			break
		}
		nextSeq, isEnd = o.addNext(nextSeq)
		if isEnd {
			break
		}
		nextSeq, isEnd = o.addContiguous(nextSeq)
		if isEnd {
			break
		}
	} // end of for
	return nextSeq, isEnd
}

// pagesFromTcp creates a page (or set of pages) from a TCP packet.  Note that
// it should NEVER receive a SYN packet, as it doesn't handle sequences
// correctly.
//
// It returns the first and last page in its doubly-linked list of new pages.
func (o *OrderedCoalesce) pagesFromTcp(p types.PacketManifest) (*page, *page, int) {
	first := o.pager.Next(p.Timestamp)
	count := 1
	current := first
	seq, bytes := types.Sequence(p.TCP.Seq), p.Payload
	for {
		length := min(len(bytes), pageBytes)
		current.Bytes = current.buf[:length]
		copy(current.Bytes, bytes)
		current.Seq = seq
		bytes = bytes[length:]
		if len(bytes) == 0 {
			break
		}
		seq = seq.Add(length)
		current.next = o.pager.Next(p.Timestamp)
		count++
		current.next.prev = current
		current = current.next
	}
	current.End = p.TCP.RST || p.TCP.FIN
	return first, current, count
}

// traverse traverses our doubly-linked list of pages for the correct
// position to put the given sequence number.  Note that it traverses backwards,
// starting at the highest sequence number and going down, since we assume the
// common case is that TCP packets for a stream will appear in-order, with
// minimal loss or packet reordering.
func (o *OrderedCoalesce) traverse(seq types.Sequence) (*page, *page) {
	var prev, current *page
	prev = o.last
	for prev != nil && prev.Seq.Difference(seq) < 0 {
		current = prev
		prev = current.prev
	}
	return prev, current
}

// pushBetween inserts the doubly-linked list first-...-last in between the
// nodes prev-next in another doubly-linked list.  If prev is nil, makes first
// the new first page in the connection's list.  If next is nil, makes last the
// new last page in the list.  first/last may point to the same page.
func (o *OrderedCoalesce) pushBetween(prev, next, first, last *page) {
	// Maintain our doubly linked list
	if next == nil || o.last == nil {
		o.last = last
	} else {
		last.next = next
		next.prev = last
	}
	if prev == nil || o.first == nil {
		o.first = first
	} else {
		first.prev = prev
		prev.next = first
	}
}

func (o *OrderedCoalesce) freeNext() {
	reclaim := o.first
	if o.first == o.last {
		o.first = nil
		o.last = nil
	} else {
		o.first = o.first.next
		o.first.prev = nil
	}
	o.pager.Replace(reclaim)
	o.pageCount--
	if o.pageCount < 0 {
		// XXX wtf srsly
		panic("pageCount less than zero")
	}
}

// addNext pops the first page off our doubly-linked-list and
// appends it to the reassembly-ring.
// Here we also handle the case where the connection should be closed
// by returning the bool value set to true.
func (o *OrderedCoalesce) addNext(nextSeq types.Sequence) (types.Sequence, bool) {
	if o.first == nil {
		return nextSeq, false
	}
	diff := nextSeq.Difference(o.first.Seq)
	if nextSeq == types.InvalidSequence {
		o.first.Skip = -1
	} else if diff > 0 {
		o.first.Skip = int(diff)
	}
	if o.first.End {
		o.freeNext()
		return -1, true // after closing the connection our Sequence return value doesn't matter
	}
	if len(o.first.Bytes) == 0 {
		o.freeNext()
		return nextSeq, false
	}
	// ensure we only add stream segments that contain data coming after
	// our last stream segment
	diff = o.first.Seq.Add(len(o.first.Bytes)).Difference(nextSeq)
	if diff < 0 {
		o.freeNext()
		return nextSeq, false
	}
	if o.DetectCoalesceInjection && len(o.first.Bytes) > 0 {
		// XXX stream segment overlap condition
		if diff < 0 {
			p := types.PacketManifest{
				Timestamp: o.first.Seen,
				Payload:   o.first.Bytes,
				TCP: layers.TCP{
					Seq: uint32(o.first.Seq),
				},
			}
			event := injectionInStreamRing(p, o.Flow, o.StreamRing, "coalesce injection", 0)
			if event != nil {
				o.log.Log(event)
			} else {
				log.Print("not an attack attempt; a normal TCP unordered stream segment coalesce\n")
			}
		}
	}
	bytes, seq := byteSpan(nextSeq, o.first.Seq, o.first.Bytes) // XXX injection happens here
	if bytes != nil {
		o.first.Bytes = bytes
		nextSeq = seq
		// append reassembly to the reassembly ring buffer
		if len(o.first.Bytes) > 0 {
			o.StreamRing.Reassembly = &o.first.Reassembly
			o.StreamRing = o.StreamRing.Next()
		}
	}
	o.freeNext()
	return nextSeq, false
}

// addContiguous adds contiguous byte-sets to a connection.
// returns the next Sequence number and a bool value set to
// true if the end of connection was detected.
func (o *OrderedCoalesce) addContiguous(nextSeq types.Sequence) (types.Sequence, bool) {
	var isEnd bool
	for o.first != nil && nextSeq.Difference(o.first.Seq) <= 0 {
		nextSeq, isEnd = o.addNext(nextSeq)
		if isEnd {
			return nextSeq, true
		}
	}
	return nextSeq, false
}
