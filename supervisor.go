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

type BadgerSupervisor struct {
	dispatcher       *Dispatcher
	sniffer          types.PacketSource
	childStoppedChan chan bool
	forceQuitChan    chan os.Signal
}

func NewBadgerSupervisor(snifferOptions SnifferOptions, dispatcherOptions DispatcherOptions, snifferFactoryFunc func(SnifferOptions) types.PacketSource, connectionFactory ConnectionFactory, packetLoggerFactory types.PacketLoggerFactory) *BadgerSupervisor {
	dispatcher := NewDispatcher(dispatcherOptions, connectionFactory, packetLoggerFactory)
	snifferOptions.Dispatcher = dispatcher
	sniffer := snifferFactoryFunc(snifferOptions)
	supervisor := BadgerSupervisor{
		forceQuitChan:    make(chan os.Signal, 1),
		childStoppedChan: make(chan bool, 0),
		dispatcher:       dispatcher,
		sniffer:          sniffer,
	}
	sniffer.SetSupervisor(supervisor)
	return &supervisor
}

func (b BadgerSupervisor) GetDispatcher() PacketDispatcher {
	return b.dispatcher
}

func (b BadgerSupervisor) GetSniffer() types.PacketSource {
	// XXX return types.PacketSource(b.sniffer)
	return b.sniffer
}

func (b BadgerSupervisor) Stopped() {
	log.Print("BadgerSupervisor.Stopped()")
	b.childStoppedChan <- true
}

func (b BadgerSupervisor) Run() {
	log.Println("HoneyBadger: comprehensive TCP injection attack detection.")
	b.dispatcher.Start()
	b.sniffer.Start()

	signal.Notify(b.forceQuitChan, os.Interrupt)

	select {
	case <-b.forceQuitChan:
		log.Print("graceful shutdown: user force quit")
		b.dispatcher.Stop()
		b.sniffer.Stop()
	case <-b.childStoppedChan:
		log.Print("graceful shutdown: packet-source stopped")
	}
}
