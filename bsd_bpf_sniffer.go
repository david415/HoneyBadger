package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"syscall"
	"unsafe"
)

// FreeBSD amd64 word length
//const wordSize = 8
const wordSize = int(unsafe.Sizeof(uintptr(0)))

// FreeBSD style bpf_hdr
type bpf_hdr struct {
	bh_tstamp  syscall.Timeval // 8 or 16 bytes depending on arch
	bh_caplen  uint32
	bh_datalen uint32
	bh_hdrlen  uint16
}

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
		b.fd, err = syscall.Open("/dev/bpf0", syscall.O_RDWR, 0) // XXX 0
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

	go b.readPackets()
	return nil
}

func (b *BpfSniffer) Stop() {
	b.stopChan <- true
}

func (b *BpfSniffer) readPackets() {

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

func main() {
	var err error
	sniffer := NewBpfSniffer()
	err = sniffer.Init("vtnet0")
	if err != nil {
		panic(err)
	}

	for {
		buf := sniffer.ReadFrame()
		// Decode a packet
		packet := gopacket.NewPacket(buf, layers.LayerTypeEthernet, gopacket.Default)
		// Get the TCP layer from this packet
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			fmt.Println("This is a TCP packet!")
			// Get actual TCP data from this layer
			tcp, _ := tcpLayer.(*layers.TCP)
			fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
		}

		// Iterate over all layers, printing out each layer type
		for _, layer := range packet.Layers() {
			fmt.Println("PACKET LAYER:", layer.LayerType())
		}
	}
}
