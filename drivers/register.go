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

package drivers

import (
	"github.com/david415/HoneyBadger/types"
)

var Drivers = map[string]func(*types.SnifferDriverOptions) (types.PacketDataSourceCloser, error){}

// Register makes a ethernet sniffer driver available by the provided name.
// If Register is called twice with the same name or if driver is nil, it panics.
func SnifferRegister(name string, packetDataSourceCloserFactory func(*types.SnifferDriverOptions) (types.PacketDataSourceCloser, error)) {
	if packetDataSourceCloserFactory == nil {
		panic("sniffer: packetDataSourceCloserFactory is nil")
	}
	if _, dup := Drivers[name]; dup {
		panic("sniffer: Register called twice for ethernet sniffer " + name)
	}
	Drivers[name] = packetDataSourceCloserFactory
}
