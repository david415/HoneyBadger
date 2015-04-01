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
	"github.com/david415/HoneyBadger/types"
	"log"
	"sync"
	"time"
)

type ClosedList struct {
	sync.Mutex
	connectionMap map[types.ConnectionHash]bool
}

func NewClosedList() *ClosedList {
	return &ClosedList{
		connectionMap: make(map[types.ConnectionHash]bool),
	}
}

func (c *ClosedList) Has(flow *types.TcpIpFlow) bool {
	c.Lock()
	defer c.Unlock()

	connectionHash := flow.ConnectionHash()
	_, ok := c.connectionMap[connectionHash]
	return ok
}

func (c *ClosedList) Put(flow *types.TcpIpFlow) {
	c.Lock()
	defer c.Unlock()

	connectionHash := flow.ConnectionHash()
	c.connectionMap[connectionHash] = true
}

// ConnectionPool is used to track TCP connections.
// This is inspired by gopacket.tcpassembly's StreamPool.
type ConnectionPool struct {
	sync.Mutex
	connectionMap map[types.ConnectionHash]*Connection
}

// NewConnectionPool returns a new ConnectionPool struct
func NewConnectionPool() *ConnectionPool {
	return &ConnectionPool{
		connectionMap: make(map[types.ConnectionHash]*Connection),
	}
}

// connectionsLocked returns a slice of Connection pointers.
// connectionsLocked is meant to be used by some of the other
// ConnectionPool methods once they've acquired a lock.
func (c *ConnectionPool) _connections() []*Connection {
	conns := make([]*Connection, 0, len(c.connectionMap))
	for _, conn := range c.connectionMap {
		conns = append(conns, conn)
	}
	return conns
}

// CloseOlderThan takes a Time argument and closes all the connections
// that have not received packet since that specified time
func (c *ConnectionPool) CloseOlderThan(t time.Time) int {
	c.Lock()
	defer c.Unlock()

	log.Printf("CloseOlderThan %s", t)
	closed := 0

	conns := c._connections()
	if conns == nil {
		return 0
	}
	for _, conn := range conns {
		lastSeen := conn.getLastSeen()
		if lastSeen.Equal(t) || lastSeen.Before(t) {
			conn.Stop()
			c._delete(conn.clientFlow)
			closed += 1
		}
	}
	return closed
}

// CloseAllConnections closes all connections in the pool.
// Note that honey badger is a passive observer of network events...
// Closing a Connection means freeing up any resources that a
// honey badger's Connection struct was using; namely goroutines and memory.
func (c *ConnectionPool) CloseAllConnections() int {
	c.Lock()
	defer c.Unlock()

	log.Print("CloseAllConnections()\n")
	conns := c._connections()
	if conns == nil {
		return 0
	}
	count := 0
	for _, conn := range conns {
		conn.Stop()
		c._delete(conn.clientFlow)
		count += 1
	}
	return count
}

// Has returns true if the given TcpIpFlow is a key in our
// either of flowAMap or flowBMap
func (c *ConnectionPool) Has(flow *types.TcpIpFlow) bool {
	c.Lock()
	defer c.Unlock()

	connectionHash := flow.ConnectionHash()
	_, ok := c.connectionMap[connectionHash]
	return ok
}

// Get returns the Connection struct pointer corresponding
// to the given TcpIpFlow key in one of the flow maps
// flowAMap or flowBMap
func (c *ConnectionPool) Get(flow *types.TcpIpFlow) (*Connection, error) {
	c.Lock()
	defer c.Unlock()

	connectionHash := flow.ConnectionHash()
	val, ok := c.connectionMap[connectionHash]
	if ok {
		return val, nil
	} else {
		return nil, fmt.Errorf("failed to retreive flow")
	}
}

// Put sets the connectionMap's key/value.. where a given TcpBidirectionalFlow
// is the key and a Connection struct pointer is the value.
func (c *ConnectionPool) Put(flow *types.TcpIpFlow, conn *Connection) {
	c.Lock()
	defer c.Unlock()

	connectionHash := flow.ConnectionHash()
	c.connectionMap[connectionHash] = conn
}

// Delete removes a connection from the pool
func (c *ConnectionPool) Delete(flow *types.TcpIpFlow) {
	c.Lock()
	defer c.Unlock()

	delete(c.connectionMap, flow.ConnectionHash())
}

func (c *ConnectionPool) _delete(flow *types.TcpIpFlow) {
	delete(c.connectionMap, flow.ConnectionHash())
}
