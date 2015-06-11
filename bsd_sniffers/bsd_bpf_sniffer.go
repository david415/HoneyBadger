// +build darwin dragonfly freebsd netbsd openbsd

/*
 * This rough sketch of a golang API for a Berkeley packet filter sniffer for BSD variants.
 * It provides only the capability to sniff ethernet frames... but could easily be extended for
 * sending frames as well.
 *
 * This file was inspired by BSD licensed code from https://github.com/songgao/ether
 *
 * ( http://opensource.org/licenses/BSD-3-Clause )
 *
 * The bpf_wordalign function was borrowed... and readFrames was very much inspired by
 * design I saw in songgao's ether git repository; the rest of the code I wrote myself ;-)
 *
 * Author: David Anthony Stainton
 * License: BSD
 *
 */

package bsd_sniffers

import (
	"syscall"
	"unsafe"
)

const wordSize = int(unsafe.Sizeof(uintptr(0)))

func bpf_wordalign(x int) int {
	return (((x) + (wordSize - 1)) &^ (wordSize - 1))
}

type BpfSniffer struct {
	fd       int
	name     string
	stopChan chan bool
	readChan chan []byte
}

func NewBpfSniffer() *BpfSniffer {
	return &BpfSniffer{
		stopChan: make(chan bool, 0),
		readChan: make(chan []byte, 0),
	}
}

func (b *BpfSniffer) Init(name string) error {
	var err error
	enable := 1

	for i := 0; i < 99; i++ {
		b.fd, err = syscall.Open("/dev/bpf0", syscall.O_RDWR, 0)
		if err == nil {
			break
		}
	}

	b.name = name
	err = syscall.SetBpfInterface(b.fd, b.name)
	if err != nil {
		return err
	}
	err = syscall.SetBpfImmediate(b.fd, enable)
	if err != nil {
		return err
	}
	err = syscall.SetBpfHeadercmpl(b.fd, enable)
	if err != nil {
		return err
	}
	err = syscall.SetBpfPromisc(b.fd, enable)
	if err != nil {
		return err
	}

	go b.readFrames()
	return nil
}

func (b *BpfSniffer) Stop() {
	b.stopChan <- true
}

func (b *BpfSniffer) readFrames() {

	bufLen, err := syscall.BpfBuflen(b.fd)
	if err != nil {
		panic(err)
	}
	buf := make([]byte, bufLen)
	var n int

	for {
		select {
		case <-b.stopChan:
			return
		default:
			n, err = syscall.Read(b.fd, buf)
			if err != nil {
				return
			}
			p := int(0)
			for p < n {
				hdr := (*bpf_hdr)(unsafe.Pointer(&buf[p]))
				frameStart := p + int(hdr.bh_hdrlen)
				b.readChan <- buf[frameStart : frameStart+int(hdr.bh_caplen)]
				p += bpf_wordalign(int(hdr.bh_hdrlen) + int(hdr.bh_caplen))
			}
		}
	}
}

func (b *BpfSniffer) ReadFrame() []byte {
	frame := <-b.readChan
	return frame
}
