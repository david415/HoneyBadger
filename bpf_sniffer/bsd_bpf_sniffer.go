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

package bpf_sniffer

import (
	"fmt"
	"github.com/google/gopacket"
	"golang.org/x/sys/unix"
	"syscall"
	"time"
	"unsafe"
)

const wordSize = int(unsafe.Sizeof(uintptr(0)))

func bpf_wordalign(x int) int {
	return (((x) + (wordSize - 1)) &^ (wordSize - 1))
}

type TimedFrame struct {
	RawFrame  []byte
	Timestamp time.Time
}

type BpfSniffer struct {
	fd       int
	name     string
	stopChan chan bool
	readChan chan TimedFrame
}

func NewBpfSniffer() *BpfSniffer {
	return &BpfSniffer{
		stopChan: make(chan bool, 0),
		readChan: make(chan TimedFrame, 0),
	}
}

func (b *BpfSniffer) Init(name string) error {
	var err error
	enable := 1

	for i := 0; i < 99; i++ {
		b.fd, err = syscall.Open(fmt.Sprintf("/dev/bpf%d", i), syscall.O_RDWR, 0)
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
	fmt.Printf("buflen is %d\n", bufLen)
	buf := make([]byte, bufLen)
	var n int

	for {
		select {
		case <-b.stopChan:
			return
		default:
			n, err = syscall.Read(b.fd, buf)
			if err != nil {
				continue
			} else {
				p := int(0)
				for p < n {
					hdr := (*unix.BpfHdr)(unsafe.Pointer(&buf[p]))
					frameStart := p + int(hdr.Hdrlen)
					b.readChan <- TimedFrame{
						RawFrame:  buf[frameStart : frameStart+int(hdr.Caplen)],
						Timestamp: time.Unix(int64(hdr.Tstamp.Sec), int64(hdr.Tstamp.Usec)*1000),
					}
					p += bpf_wordalign(int(hdr.Hdrlen) + int(hdr.Caplen))
				}
			}
		}
	}
}

func (b *BpfSniffer) ReadTimedFrame() TimedFrame {
	timedFrame := <-b.readChan
	return timedFrame
}

func (b *BpfSniffer) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	timedFrame := b.ReadTimedFrame()
	captureInfo := gopacket.CaptureInfo{
		Timestamp:     timedFrame.Timestamp,
		CaptureLength: len(timedFrame.RawFrame),
		Length:        len(timedFrame.RawFrame),
	}
	return timedFrame.RawFrame, captureInfo, nil
}
