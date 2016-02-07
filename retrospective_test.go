package HoneyBadger

import (
	"log"
	"net"
	"testing"

	"github.com/david415/HoneyBadger/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/david415/HoneyBadger/blocks"
)

type reassemblyInput struct {
	Seq     uint32
	Payload []byte
}

type TestOverlapBytesWant struct {
	bytes       []byte
	startOffset int
	endOffset   int
}

type DummyAttackLogger struct {
	Count int
}

func NewDummyAttackLogger() *DummyAttackLogger {
	a := DummyAttackLogger{
		Count: 0,
	}
	return &a
}

func (d *DummyAttackLogger) Log(event *types.Event) {
	d.Count += 1
}

func (d *DummyAttackLogger) Archive() {
}

func TestGetOverlapsInRing(t *testing.T) {

	overlapBlockTests := []struct {
		in   blocks.Block
		want []blocks.BlockSegment
	}{
		{ //0
			blocks.Block{ A:1, B:22 }, []blocks.BlockSegment{
				blocks.BlockSegment{ blocks.Block{ 5, 10 }, []byte{1, 2, 3, 4, 5}, false, false },
				blocks.BlockSegment{ blocks.Block{ 10, 15 }, []byte{1, 2, 3, 4, 5}, false, false },
				blocks.BlockSegment{ blocks.Block{ 15, 20 }, []byte{1, 2, 3, 4, 5}, false, false },
				blocks.BlockSegment{ blocks.Block{ 20, 22 }, []byte{1, 2, 3}, false, false },
			},
		},
		{ //1
			blocks.Block{ 3, 10 }, []blocks.BlockSegment{
				blocks.BlockSegment{ blocks.Block{ 5, 10 }, []byte{1, 2, 3, 4, 5}, false, false },
			},
		},
		{ //2
			blocks.Block{ 6, 12 }, []blocks.BlockSegment{
				blocks.BlockSegment{ blocks.Block{ 6, 10 }, []byte{2, 3, 4, 5}, false, false },
				blocks.BlockSegment{ blocks.Block{ 10, 12 }, []byte{1, 2, 3}, false, false },
			},
		},
		{ //3
			blocks.Block{ A:1, B:17 }, []blocks.BlockSegment{
				blocks.BlockSegment{ blocks.Block{ 5, 10 }, []byte{1, 2, 3, 4, 5}, false, false },
				blocks.BlockSegment{ blocks.Block{ 10, 15 }, []byte{1, 2, 3, 4, 5}, false, false },
				blocks.BlockSegment{ blocks.Block{ 15, 17 }, []byte{1, 2, 3}, false, false },
			},
		},
		{ //4
			blocks.Block{ A:0, B:100 }, []blocks.BlockSegment{
				blocks.BlockSegment{ blocks.Block{ A:5, B:10 }, []byte{1, 2, 3, 4, 5}, false, false },
				blocks.BlockSegment{ blocks.Block{ A:10, B:15 }, []byte{1, 2, 3, 4, 5}, false, false },
				blocks.BlockSegment{ blocks.Block{ A:15, B:20 }, []byte{1, 2, 3, 4, 5}, false, false },
				blocks.BlockSegment{ blocks.Block{ A:20, B:25 }, []byte{1, 2, 3, 4, 5}, false, false },
				blocks.BlockSegment{ blocks.Block{ A:25, B:30 }, []byte{1, 2, 3, 4, 5}, false, false },
				blocks.BlockSegment{ blocks.Block{ A:30, B:35 }, []byte{1, 2, 3, 4, 5}, false, false },
				blocks.BlockSegment{ blocks.Block{ A:35, B:40 }, []byte{1, 2, 3, 4, 5}, false, false },

			},
		},
	}


	// setup ring with some content and sequence numbers
	var ringPtr *types.Ring = types.NewRing(40)
	for j := 5; j < 40; j += 5 {
		reassembly := types.Reassembly{
			Seq:   types.Sequence(j),
			Bytes: []byte{1, 2, 3, 4, 5},
		}

		ringPtr.Reassembly = &reassembly
		ringPtr = ringPtr.Next()
	}
	reassembly := types.Reassembly{
		Seq:   types.Sequence(46),
		Bytes: []byte{},
	}
	ringPtr.Reassembly = &reassembly
	ringPtr = ringPtr.Next()

	// run tests
	for i := 0; i < len(overlapBlockTests); i++ {
		log.Printf("test # %d\n", i)
		overlaps := getOverlapsInRing(ringPtr, overlapBlockTests[i].in.A, overlapBlockTests[i].in.B)

		if len(overlaps) != len(overlapBlockTests[i].want) {
			t.Errorf("wanted %d overlaps, got %d\n", len(overlapBlockTests[i].want), len(overlaps) )
			t.Fail()
		}

		for j := 0; j < len(overlaps) && j < len(overlapBlockTests[i].want); j++ {
			log.Printf("got overlap: %s\n", overlaps[j].Block)
			log.Printf("len of overlap bytes: %d\n", len(overlaps[j].Bytes))
			//log.Print(hex.Dump(overlaps[j].Bytes))
			if overlaps[j].Block != overlapBlockTests[i].want[j].Block {
				t.Errorf("overlaps unequal: %s != %s\n", overlaps[j].Block, overlapBlockTests[i].want[j])
				t.Fail()
			}
		}
	}
}

func TestInjectionDetector(t *testing.T) {
	attackLogger := NewDummyAttackLogger()
	options := ConnectionOptions{
		MaxBufferedPagesTotal:         0,
		MaxBufferedPagesPerConnection: 0,
		MaxRingPackets:                40,
		PageCache:                     nil,
		LogDir:                        "fake-log-dir",
		AttackLogger:                  attackLogger,
	}

	f := &DefaultConnFactory{}
	conn := f.Build(options).(*Connection)
	reassembly := types.Reassembly{
		Seq:   types.Sequence(5),
		Bytes: []byte{1, 2, 3, 4, 5},
	}
	conn.ClientStreamRing.Reassembly = &reassembly
	conn.ClientStreamRing = conn.ClientStreamRing.Next()
	conn.ServerStreamRing.Reassembly = &reassembly
	conn.ServerStreamRing = conn.ServerStreamRing.Next()

	ipFlow, _ := gopacket.FlowFromEndpoints(layers.NewIPEndpoint(net.IPv4(1, 2, 3, 4)), layers.NewIPEndpoint(net.IPv4(2, 3, 4, 5)))
	tcpFlow, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(layers.TCPPort(1)), layers.NewTCPPortEndpoint(layers.TCPPort(2)))

	clientFlow := types.NewTcpIpFlowFromFlows(ipFlow, tcpFlow)
	serverFlow := clientFlow.Reverse()
	conn.serverFlow = serverFlow
	conn.clientFlow = clientFlow

	p := types.PacketManifest{
		Flow: clientFlow,
		IP: layers.IPv4{
			SrcIP:    net.IP{1, 2, 3, 4},
			DstIP:    net.IP{2, 3, 4, 5},
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
		},
		TCP: layers.TCP{
			Seq:     7,
			SrcPort: 1,
			DstPort: 2,
		},
		Payload: []byte{1, 2, 3, 4, 5, 6, 7},
	}

	conn.detectInjection(&p)

	if attackLogger.Count != 1 {
		t.Errorf("detectInjection failed; count == %d\n", attackLogger.Count)
		t.Fail()
	}
	// next test case
	p.TCP = layers.TCP{
		Seq:     7,
		SrcPort: 1,
		DstPort: 2,
	}
	p.Payload = []byte{3, 4, 5}
	conn.detectInjection(&p)
	if attackLogger.Count == 0 {
		t.Error("failed to detect injection\n")
		t.Fail()
	}

	// next test case
	attackLogger.Count = 0
	p.TCP = layers.TCP{
		Seq:     1,
		SrcPort: 1,
		DstPort: 2,
	}
	p.Payload = []byte{1, 2, 3, 4, 5, 6}
	conn.detectInjection(&p)
	if attackLogger.Count == 0 {
		t.Error("failed to detect injection\n")
		t.Fail()
	}

	// next test case
	attackLogger.Count = 0
	p.TCP = layers.TCP{
		Seq:     1,
		SrcPort: 1,
		DstPort: 2,
	}
	p.Payload = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17}
	conn.detectInjection(&p)
	if attackLogger.Count != 1 {
		t.Error("injection detection failure\n")
		t.Fail()
	}
}

