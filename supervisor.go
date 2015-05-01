/*
 *    state_machine.go - HoneyBadger core library for detecting TCP attacks
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
	"os"
	"os/signal"
)

type BadgerSupervisor struct {
	inquisitor       *Inquisitor
	sniffer          types.PacketSource
	childStoppedChan chan bool
	forceQuitChan    chan os.Signal
}

func NewBadgerSupervisor(snifferOptions *PcapSnifferOptions, inquisitorOptions *InquisitorOptions, snifferFactoryFunc func(*PcapSnifferOptions) types.PacketSource, connectionFactory *ConnectionFactory, packetLoggerFactoryFunc func(string, *types.TcpIpFlow) types.PacketLogger) *BadgerSupervisor {
	inquisitor := NewInquisitor(inquisitorOptions, connectionFactory, packetLoggerFactoryFunc)
	snifferOptions.Dispatcher = inquisitor
	sniffer := snifferFactoryFunc(snifferOptions)
	supervisor := BadgerSupervisor{
		forceQuitChan:    make(chan os.Signal, 1),
		childStoppedChan: make(chan bool, 0),
		inquisitor:       inquisitor,
		sniffer:          sniffer,
	}
	sniffer.SetSupervisor(supervisor)
	return &supervisor
}

func (b BadgerSupervisor) GetDispatcher() PacketDispatcher {
	return b.inquisitor
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
	b.inquisitor.Start()
	b.sniffer.Start()

	signal.Notify(b.forceQuitChan, os.Interrupt)

	select {
	case <-b.forceQuitChan:
		log.Print("graceful shutdown: user force quit")
		b.inquisitor.Stop()
		b.sniffer.Stop()
	case <-b.childStoppedChan:
		log.Print("graceful shutdown: packet-source stopped")
	}
}
