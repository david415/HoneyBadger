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
	"github.com/david415/HoneyBadger/types"
	"github.com/david415/HoneyBadger/blocks"

	"log"
	"bytes"
	"encoding/hex"
)


func checkForInjectionInRing(ringPtr *types.Ring, p *types.PacketManifest) []*types.Event {
	start := types.Sequence(p.TCP.Seq)
	end := types.Sequence(p.TCP.Seq).Add(len(p.Payload))

	acc := []*types.Event{}
	overlapBlockSegments := getOverlapsInRing(ringPtr, start, end)
	for i := 0; i < len(overlapBlockSegments); i++ {
		if len(overlapBlockSegments[i].Bytes) > 0 {
			packetOverlapBytes := getOverlapBytesFromSlice(p.Payload, start, overlapBlockSegments[i].Block)
			if !bytes.Equal(packetOverlapBytes, overlapBlockSegments[i].Bytes) {
				log.Printf("injection at TCP Sequence start %d end %d\n", start, end)
				log.Print("race winner stream segment:")
				log.Print(hex.Dump(overlapBlockSegments[i].Bytes))
				log.Print("race loser stream segment:")
				log.Print(hex.Dump(packetOverlapBytes))

				e := &types.Event{
					Loser:   packetOverlapBytes,
					Winner:  overlapBlockSegments[i].Bytes,
					Start:   overlapBlockSegments[i].Block.A,
					End:     overlapBlockSegments[i].Block.B,
				}
				if overlapBlockSegments[i].IsCoalesce {
					e.Type = "ordered coalesce 2"
				}
				if overlapBlockSegments[i].IsCoalesceGap {
					e.Type = "ordered coalesce 2 gap"
				}
				acc = append(acc, e)
			}
		} else {
			injectionType := "zero-length injection:"
			// XXX correct?
			if overlapBlockSegments[i].RST || overlapBlockSegments[i].FIN || p.TCP.RST || p.TCP.FIN {
				log.Print("RST or FIN injection packet won the race")
				if len(p.Payload) > 0 {
					log.Print("race loser packet payload:")
					log.Print(hex.Dump(p.Payload))
				}
				if p.TCP.FIN || overlapBlockSegments[i].FIN {
					log.Print("FIN flag")
					injectionType += "FIN Injection"
				}
				if p.TCP.RST || overlapBlockSegments[i].RST {
					log.Print("RST flag")
					injectionType += "RST Injection"
				}
			} else {
				// XXX not an injection attack?
				// at the very least we can confidently say
				// that it's not an RST or FIN injection attack
				continue
			}

			log.Print("detect zero length overlap 'injection'.")
			log.Printf("injection at TCP Sequence start %d end %d\n", start, end)

			e := &types.Event{
				Type:    injectionType,
				Winner:   []byte{},
				Loser:    []byte{},
				Payload:  []byte{},
				Base:     overlapBlockSegments[i].Block.A,
				Start:    overlapBlockSegments[i].Block.A,
				End:      overlapBlockSegments[i].Block.B,
			}
			acc = append(acc, e)
		}
	}
	return acc
}

func getOverlapBytesFromSlice(payload []byte, sequence types.Sequence, overlap blocks.Block) []byte {
	start := sequence.Difference(overlap.A)
	end := types.Sequence(start).Add(overlap.A.Difference(overlap.B))
	return payload[start:end]
}

func getOverlapsInRing(ringPtr *types.Ring, start, end types.Sequence) []blocks.BlockSegment {
	acc := []blocks.BlockSegment{}

	target := blocks.Block {
		A: start,
		B: end,
	}

	// iterate for the entire ring
	for current := ringPtr.Next(); current != ringPtr; current = current.Next() {
		if current.Reassembly == nil {
			continue
		}

		new_start := types.Sequence(current.Reassembly.Seq)
		new_end := types.Sequence(current.Reassembly.Seq).Add(len(current.Reassembly.Bytes))

		overlap := target.Overlap(new_start, new_end)
		if overlap == nil {
			continue
		} else {
			// overlaps
			overlapBytes := getOverlapBytesFromSlice(current.Reassembly.Bytes, current.Reassembly.Seq, *overlap)
			blockSegment := blocks.BlockSegment {
				Block: *overlap,
				Bytes: overlapBytes,
				IsCoalesce: current.Reassembly.IsCoalesce,
				IsCoalesceGap: current.Reassembly.IsCoalesceGap,
				/*RST: current.Reassembly.PacketManifest.TCP.RST,
				ACK: current.Reassembly.PacketManifest.TCP.ACK,
				FIN: current.Reassembly.PacketManifest.TCP.FIN,*/
			}
			acc = append(acc, blockSegment)
		}
	}
	return acc
}
