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
	"bytes"
	"container/ring"
	"log"
	"time"
)

const pageBytes = 1900

const memLog = true // XXX get rid of me later...

// Reassembly objects are passed by an Assembler into Streams using the
// Reassembled call.  Callers should not need to create these structs themselves
// except for testing.
type Reassembly struct {
	// Seq is the TCP sequence number for this segment
	Seq Sequence

	// Bytes is the next set of bytes in the stream.  May be empty.
	Bytes []byte
	// Skip is set to non-zero if bytes were skipped between this and the
	// last Reassembly.  If this is the first packet in a connection and we
	// didn't see the start, we have no idea how many bytes we skipped, so
	// we set it to -1.  Otherwise, it's set to the number of bytes skipped.
	Skip int
	// Start is set if this set of bytes has a TCP SYN accompanying it.
	Start bool
	// End is set if this set of bytes has a TCP FIN or RST accompanying it.
	End bool
	// Seen is the timestamp this set of bytes was pulled off the wire.
	Seen time.Time
}

// Stream is implemented by the caller to handle incoming reassembled
// TCP data.  Callers create a StreamFactory, then StreamPool uses
// it to create a new Stream for every TCP stream.
//
// assembly will, in order:
//    1) Create the stream via StreamFactory.New
//    2) Call Reassembled 0 or more times, passing in reassembled TCP data in order
//    3) Call ReassemblyComplete one time, after which the stream is dereferenced by assembly.
type Stream interface {
	// Reassembled is called zero or more times.  assembly guarantees
	// that the set of all Reassembly objects passed in during all
	// calls are presented in the order they appear in the TCP stream.
	// Reassembly objects are reused after each Reassembled call,
	// so it's important to copy anything you need out of them
	// (specifically out of Reassembly.Bytes) that you need to stay
	// around after you return from the Reassembled call.
	Reassembled([]Reassembly)
	// ReassemblyComplete is called when assembly decides there is
	// no more data for this Stream, either because a FIN or RST packet
	// was seen, or because the stream has timed out without any new
	// packet data (due to a call to FlushOlderThan).
	ReassemblyComplete()
}

// page is used to store TCP data we're not ready for yet (out-of-order
// packets).  Unused pages are stored in and returned from a pageCache, which
// avoids memory allocation.  Used pages are stored in a doubly-linked list in
// an OrderedCoalesce.
type page struct {
	Reassembly
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
	for i, _ := range pages {
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

func byteSpan(expected, received Sequence, bytes []byte) (toSend []byte, next Sequence) {
	if expected == invalidSequence {
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

// OrderedCoalesceOptions controls the behavior of each assembler.  Modify the
// options of each assembler you create to change their behavior.
type OrderedCoalesceOptions struct {
	Flow       TcpIpFlow
	StreamRing *ring.Ring
	nextSeq    *Sequence

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
}

type OrderedCoalesce struct {
	OrderedCoalesceOptions

	AttackLogger AttackLogger
	pageCount    int
	pager        *Pager
	first, last  *page
	ret          []Reassembly
}

func NewOrderedCoalesce(flow TcpIpFlow, pager *Pager, streamRing *ring.Ring, maxBufferedPagesTotal, maxBufferedPagesPerFlow int) *OrderedCoalesce {
	return &OrderedCoalesce{
		pager: pager,
		OrderedCoalesceOptions: OrderedCoalesceOptions{
			Flow:                    flow,
			StreamRing:              streamRing,
			MaxBufferedPagesTotal:   maxBufferedPagesTotal,
			MaxBufferedPagesPerFlow: maxBufferedPagesPerFlow,
		},
	}
}

func (o *OrderedCoalesce) Start() {
	o.pager.Start()
}

func (o *OrderedCoalesce) Stop() {
	o.pager.Stop()
}

func (o *OrderedCoalesce) insert(packetManifest PacketManifest) {
	if o.first != nil && o.first.Seq == *o.nextSeq {
		panic("wtf")
	}
	p, p2 := o.pagesFromTcp(packetManifest)
	prev, current := o.traverse(Sequence(packetManifest.TCP.Seq))
	o.pushBetween(prev, current, p, p2)
	o.pageCount++
	if (o.MaxBufferedPagesPerFlow > 0 && o.pageCount >= o.MaxBufferedPagesPerFlow) ||
		(o.MaxBufferedPagesTotal > 0 && o.pager.Used() >= o.MaxBufferedPagesTotal) {
		log.Printf("%v hit max buffer size: %+v, %v, %v", packetManifest.Flow.String(), o.OrderedCoalesceOptions, o.pageCount, o.pager.Used())
		o.addNext()
	}
}

// pagesFromTcp creates a page (or set of pages) from a TCP packet.  Note that
// it should NEVER receive a SYN packet, as it doesn't handle sequences
// correctly.
//
// It returns the first and last page in its doubly-linked list of new pages.
func (o *OrderedCoalesce) pagesFromTcp(p PacketManifest) (*page, *page) {
	first := o.pager.Next(p.Timestamp)
	current := first
	seq, bytes := Sequence(p.TCP.Seq), p.Payload
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
		current.next.prev = current
		current = current.next
	}
	current.End = p.TCP.RST || p.TCP.FIN
	return first, current
}

// traverse traverses our doubly-linked list of pages for the correct
// position to put the given sequence numbeo.  Note that it traverses backwards,
// starting at the highest sequence number and going down, since we assume the
// common case is that TCP packets for a stream will appear in-order, with
// minimal loss or packet reordering.
func (o *OrderedCoalesce) traverse(seq Sequence) (*page, *page) {
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

// addNext pops the first page off our doubly-linked-list and
// adds it to the return array.
func (o *OrderedCoalesce) addNext() {
	diff := o.nextSeq.Difference(o.first.Seq)
	if *o.nextSeq == Sequence(invalidSequence) {
		o.first.Skip = -1
	} else if diff > 0 {
		o.first.Skip = int(diff)
	}
	// XXX stream segment overlap condition
	if diff < 0 {
		log.Print("out-of-order packet stream *overlap* detected\n")
		current, ok := o.StreamRing.Prev().Value.(Reassembly)
		if !ok {
			log.Print("out-of-order coalesce overlap analysis not possible; ring empty.\n")
			return // XXX
		}
		orderedOverlap := current.Bytes[len(current.Bytes)+diff+1:]
		unorderedOverlap := o.first.Bytes[:(-diff)+1] // XXX
		if !bytes.Equal(orderedOverlap, unorderedOverlap) {
			// XXX is this info useful for reporting coalesce injection attacks?
			start := o.nextSeq.Add(diff).Add(1)
			end := o.first.Seq.Add(-diff)
			o.AttackLogger.ReportInjectionAttack("coalesce injection", time.Now(), o.Flow, unorderedOverlap, orderedOverlap, start, end, 0, 0)
		} else {
			log.Print("not an attack attempt; a normal TCP unordered stream segment coalesce\n")
		}
	}
	o.first.Bytes, *o.nextSeq = byteSpan(*o.nextSeq, o.first.Seq, o.first.Bytes) // XXX injection happens here
	log.Printf("%s   adding from r (%v, %v)", o.Flow.String(), o.first.Seq, o.nextSeq)
	o.ret = append(o.ret, o.first.Reassembly)
	o.pager.Replace(o.first)
	if o.first == o.last {
		o.first = nil
		o.last = nil
	} else {
		o.first = o.first.next
		o.first.prev = nil
	}
	o.pageCount--
}
