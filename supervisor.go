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
	"log"
	"os"
	"os/signal"

	"github.com/david415/HoneyBadger/types"
)

type SupervisorOptions struct {
	SnifferDriverOptions *types.SnifferDriverOptions
	DispatcherOptions    DispatcherOptions
	SnifferFactory       func(*types.SnifferDriverOptions, PacketDispatcher) types.PacketSource
	ConnectionFactory    ConnectionFactory
	PacketLoggerFactory  types.PacketLoggerFactory
}

type Supervisor struct {
	dispatcher       *Dispatcher
	sniffer          types.PacketSource
	childStoppedChan chan bool
	forceQuitChan    chan os.Signal
}

func NewSupervisor(options SupervisorOptions) *Supervisor {
	dispatcher := NewDispatcher(options.DispatcherOptions, options.ConnectionFactory, options.PacketLoggerFactory)
	sniffer := options.SnifferFactory(options.SnifferDriverOptions, dispatcher)
	supervisor := Supervisor{
		forceQuitChan:    make(chan os.Signal, 1),
		childStoppedChan: make(chan bool, 0),
		dispatcher:       dispatcher,
		sniffer:          sniffer,
	}
	sniffer.SetSupervisor(supervisor)
	return &supervisor
}

func (b Supervisor) GetDispatcher() PacketDispatcher {
	return b.dispatcher
}

func (b Supervisor) GetSniffer() types.PacketSource {
	// XXX return types.PacketSource(b.sniffer)
	return b.sniffer
}

func (b Supervisor) Stopped() {
	log.Print("Supervisor.Stopped()")
	b.childStoppedChan <- true
}

func (b Supervisor) Run() {
	b.dispatcher.Start()
	b.sniffer.Start()

	signal.Notify(b.forceQuitChan, os.Interrupt)

	select {
	case <-b.forceQuitChan:
		log.Print("graceful shutdown: user force quit\n")
		log.Print("stopping sniffer")
		b.sniffer.Stop()
		log.Print("stopping dispatcher")
		b.dispatcher.Stop()
		log.Print("supervisor waiting for child to stop\n")
	case <-b.childStoppedChan:
		log.Print("graceful shutdown: packet-source stopped")
	}
}
