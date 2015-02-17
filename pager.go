/*
 *    pager.go - HoneyBadger core library for detecting TCP attacks
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
	"time"
)

// PageRequest is used to request a page from the Pager
// The new page will be sent on the ResponseChan and have it's timestamp set to Timestamp.
type PageRequest struct {
	Timestamp    time.Time
	ResponseChan chan *page
}

// Pager is used to synchronize access to our pagecache among many goroutines.
// No locks are used here. Instead, we use channels to send page points between goroutines.
type Pager struct {
	pageCache *pageCache

	stopChan        chan bool
	requestPageChan chan *PageRequest
	replacePageChan chan *page
}

// NewPager creates a new Pager struct with an initialized pagecache and
// channels with which to access it.
func NewPager() *Pager {
	return &Pager{
		pageCache:       newPageCache(),
		requestPageChan: make(chan *PageRequest),
		replacePageChan: make(chan *page),
		stopChan:        make(chan bool),
	}
}

// Start causes our Pager to start it's own goroutine to
// process pagecache requests over channels.
func (p *Pager) Start() {
	go p.receivePageRequests()
}

// Stop simply stops our Pager goroutine. It does not free up used pages.
func (p *Pager) Stop() {
	p.stopChan <- true
}

// Next takes a timestamp argument and constructs a PageRequest, sends it to pager's requestPageChan,
// waits to receive a page pointer on the response channel and then returns it.
func (p *Pager) Next(timestamp time.Time) *page {
	responseChan := make(chan *page)
	p.requestPageChan <- &PageRequest{
		Timestamp:    timestamp,
		ResponseChan: responseChan,
	}
	pagePtr := <-responseChan
	return pagePtr
}

// Replace takes a page pointer argument and appends it to the pagecache's free list
func (p *Pager) Replace(pagePtr *page) {
	p.replacePageChan <- pagePtr
}

func (p *Pager) Used() int {
	return p.pageCache.used
}

// receivePageRequests is the event loop of Pager.
// It is meant to run in it's own goroutine.
func (p *Pager) receivePageRequests() {
	for {
		select {
		case <-p.stopChan:
			return
		case pageRequest := <-p.requestPageChan:
			pageRequest.ResponseChan <- p.pageCache.next(pageRequest.Timestamp)
		case pagePtr := <-p.replacePageChan:
			p.pageCache.replace(pagePtr)
		}
	}
}
