/*
 *    service.go - HoneyBadger core library for detecting TCP attacks
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
	"github.com/david415/HoneyBadger/types"
	"log"
	"time"
)

type TimedRawPacket struct {
	Timestamp time.Time
	RawPacket []byte
}

// InquisitorOptions are user set parameters for specifying the
// details of how to proceed with honey_bager's TCP connection monitoring.
// More parameters should soon be added here!
type InquisitorOptions struct {
	BufferedPerConnection    int
	BufferedTotal            int
	LogDir                   string
	LogPackets               bool
	TcpIdleTimeout           time.Duration
	MaxRingPackets           int
	Logger                   types.Logger
	DetectHijack             bool
	DetectInjection          bool
	DetectCoalesceInjection  bool
	MaxConcurrentConnections int
}

// Inquisitor sets up the connection pool and is an abstraction layer for dealing
// with incoming packets weather they be from a pcap file or directly off the wire.
type Inquisitor struct {
	InquisitorOptions
	connectionFactory       *ConnectionFactory
	observeConnectionCount  int
	observeConnectionChan   chan bool
	dispatchPacketChan      chan *types.PacketManifest
	stopDispatchChan        chan bool
	closeConnectionChan     chan ConnectionInterface
	pool                    map[types.ConnectionHash]ConnectionInterface
	pager                   *Pager
	PacketLoggerFactoryFunc func(string, *types.TcpIpFlow) types.PacketLogger
}

// NewInquisitor creates a new Inquisitor struct
func NewInquisitor(options *InquisitorOptions, connectionFactory *ConnectionFactory, packetLoggerFactoryFunc func(string, *types.TcpIpFlow) types.PacketLogger) *Inquisitor {
	i := Inquisitor{
		PacketLoggerFactoryFunc: packetLoggerFactoryFunc,
		connectionFactory:       connectionFactory,
		InquisitorOptions:       *options,
		dispatchPacketChan:      make(chan *types.PacketManifest),
		stopDispatchChan:        make(chan bool),
		closeConnectionChan:     make(chan ConnectionInterface),
		pager:                   NewPager(),
		pool:                    make(map[types.ConnectionHash]ConnectionInterface),
	}
	return &i
}

func (i *Inquisitor) GetObservedConnectionsChan(count int) chan bool {
	i.observeConnectionCount = count
	i.observeConnectionChan = make(chan bool, 0)
	return i.observeConnectionChan
}

// Start... starts the TCP attack inquisition!
func (i *Inquisitor) Start() {
	i.pager.Start()
	go i.dispatchPackets()
}

// Stop... stops the TCP attack inquisition!
func (i *Inquisitor) Stop() {
	i.stopDispatchChan <- true
	closedConns := i.CloseAllConnections()
	log.Printf("%d connection(s) closed.", closedConns)
	i.pager.Stop()
}

// connectionsLocked returns a slice of Connection pointers.
func (i *Inquisitor) Connections() []ConnectionInterface {
	conns := make([]ConnectionInterface, 0, len(i.pool))
	for _, conn := range i.pool {
		conns = append(conns, conn)
	}
	return conns
}

func (i *Inquisitor) CloseRequest(conn ConnectionInterface) {
	i.closeConnectionChan <- conn
}

func (i *Inquisitor) ReceivePacket(p *types.PacketManifest) {
	i.dispatchPacketChan <- p
}

// CloseOlderThan takes a Time argument and closes all the connections
// that have not received packet since that specified time
func (i *Inquisitor) CloseOlderThan(t time.Time) int {
	closed := 0
	conns := i.Connections()
	if conns == nil {
		return 0
	}
	for _, conn := range conns {
		lastSeen := conn.GetLastSeen()
		if lastSeen.Equal(t) || lastSeen.Before(t) {
			conn.Close()
			delete(i.pool, conn.GetConnectionHash())
			closed += 1
		}
	}
	return closed
}

// CloseAllConnections closes all connections in the pool.
func (i *Inquisitor) CloseAllConnections() int {
	conns := i.Connections()
	if conns == nil {
		return 0
	}
	count := 0
	for _, conn := range conns {
		conn.Close()
		delete(i.pool, conn.GetConnectionHash())
		count += 1
	}
	return count
}

func (i *Inquisitor) setupNewConnection(flow *types.TcpIpFlow) ConnectionInterface {
	options := ConnectionOptions{
		MaxBufferedPagesTotal:         i.InquisitorOptions.BufferedTotal,
		MaxBufferedPagesPerConnection: i.InquisitorOptions.BufferedPerConnection,
		MaxRingPackets:                i.InquisitorOptions.MaxRingPackets,
		Pager:                         i.pager,
		LogDir:                        i.LogDir,
		AttackLogger:                  i.Logger,
		LogPackets:                    i.LogPackets,
		DetectHijack:                  i.DetectHijack,
		DetectInjection:               i.DetectInjection,
		DetectCoalesceInjection:       i.DetectCoalesceInjection,
		Dispatcher:                    i,
	}
	i.connectionFactory.options = &options
	conn := i.connectionFactory.Build()

	if i.LogPackets {
		packetLogger := i.PacketLoggerFactoryFunc(i.LogDir, flow)
		conn.SetPacketLogger(packetLogger)
		packetLogger.Start()
	}
	i.pool[flow.ConnectionHash()] = conn
	conn.Start()
	if i.observeConnectionCount != 0 && i.observeConnectionCount == len(i.Connections()) {
		i.observeConnectionChan <- true
	}
	return conn
}

func (i *Inquisitor) dispatchPackets() {
	var conn ConnectionInterface
	timeout := i.InquisitorOptions.TcpIdleTimeout
	ticker := time.Tick(timeout)
	for {
		select {
		case conn := <-i.closeConnectionChan:
			conn.Close()
			delete(i.pool, conn.GetConnectionHash())
		default:
		}
		select {
		case <-ticker:
			closed := i.CloseOlderThan(time.Now().Add(timeout * -1))
			if closed != 0 {
				log.Printf("timeout closed %d connections\n", closed)
			}
		case <-i.stopDispatchChan:
			return
		case packetManifest := <-i.dispatchPacketChan:
			_, ok := i.pool[packetManifest.Flow.ConnectionHash()]
			if ok {
				conn = i.pool[packetManifest.Flow.ConnectionHash()]
			} else {
				if i.MaxConcurrentConnections != 0 {
					if len(i.pool) >= i.MaxConcurrentConnections {
						continue
					}
				}
				conn = i.setupNewConnection(packetManifest.Flow)
			}

			conn.ReceivePacket(packetManifest)
		} // end of select {
	} // end of for {
}
