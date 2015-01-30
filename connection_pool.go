/*
 *    connection_pool.go - HoneyBadger core library for detecting TCP attacks
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
	"fmt"
	"sync"
)

// ConnectionPool is used to track TCP connections.
// This is inspired by gopacket.tcpassembly's StreamPool.
type ConnectionPool struct {
	sync.RWMutex

	flowAMap map[TcpIpFlow]*Connection
	flowBMap map[TcpIpFlow]*Connection
	size     int
}

// NewConnectionPool returns a new ConnectionPool struct
func NewConnectionPool() *ConnectionPool {
	return &ConnectionPool{
		flowAMap: make(map[TcpIpFlow]*Connection),
		flowBMap: make(map[TcpIpFlow]*Connection),
	}
}

func (c *ConnectionPool) Connections() []*Connection {
	c.RLock()
	defer c.RUnlock()

	conns := make([]*Connection, 0, len(c.flowAMap))
	count := 0
	for _, conn := range c.flowAMap {
		conns = append(conns, conn)
		count += 1
	}
	if count == 0 {
		return nil
	} else {
		return conns
	}
}

// Has returns true if the given TcpIpFlow is a key in our
// either of flowAMap or flowBMap
func (c *ConnectionPool) Has(key TcpIpFlow) bool {
	c.RLock()
	defer c.RUnlock()

	_, ok := c.flowAMap[key]
	if !ok {
		_, ok = c.flowBMap[key]
	}
	return ok
}

// Get returns the Connection struct pointer corresponding
// to the given TcpIpFlow key in one of the flow maps
// flowAMap or flowBMap
func (c *ConnectionPool) Get(key TcpIpFlow) (*Connection, error) {
	c.RLock()
	defer c.RUnlock()

	val, ok := c.flowAMap[key]
	if ok {
		return val, nil
	} else {
		val, ok = c.flowBMap[key]
		if !ok {
			return nil, fmt.Errorf("failed to retreive flow\n")
		}
	}
	return val, nil
}

// Put sets the connectionMap's key/value.. where a given TcpBidirectionalFlow
// is the key and a Connection struct pointer is the value.
func (c *ConnectionPool) Put(key TcpIpFlow, conn *Connection) {
	c.Lock()
	defer c.Unlock()

	c.flowAMap[key] = conn
	c.flowBMap[key.Reverse()] = conn
}

func (c *ConnectionPool) Delete(key TcpIpFlow) {
	c.Lock()
	defer c.Unlock()

	_, ok := c.flowAMap[key]
	if ok {
		delete(c.flowAMap, key)
		delete(c.flowBMap, key.Reverse())
	} else {
		_, ok = c.flowBMap[key]
		if ok {
			delete(c.flowBMap, key)
			delete(c.flowAMap, key.Reverse())
		} else {
			panic(fmt.Sprintf("ConnectionPool flow key %s not found\n", key.String()))
		}
	}
}
