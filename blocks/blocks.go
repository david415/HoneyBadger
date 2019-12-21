// code borrowed from https://github.com/zond/qisniff
// it's GPL2 see LICENSE

// modified to use our Sequence type instead of int64
// Package blocks contains logic to detect overlap between segments of a contiguous data stream.
package blocks

import (
	"fmt"
	"github.com/david415/HoneyBadger/types"
	"strings"
)

type Block struct {
	A, B types.Sequence
}

type BlockSegment struct {
	Block         Block
	Bytes         []byte
	IsCoalesce    bool
	IsCoalesceGap bool
}

func (t BlockSegment) String() string {
	return fmt.Sprintf("%s, Bytes %x, IsCoalesce %v, IsCoalesceGap %v", t.Block, t.Bytes, t.IsCoalesce, t.IsCoalesceGap)
}

func (t Block) String() string {
	return fmt.Sprintf("Block(%d, %d)", t.A, t.B)
}

func (blk Block) Overlap(a, b types.Sequence) *Block {
	left := a
	if blk.A.GreaterThan(left) {
		left = blk.A
	}
	right := b
	if blk.B.LessThan(right) {
		right = blk.B
	}
	if right.GreaterThan(left) {
		return &Block{left, right}
	}
	return nil
}

type Blocks []Block

func (t Blocks) String() string {
	acc := make([]string, 1)
	for i := 0; i < t.Len(); i++ {
		acc = append(acc, t[i].String())
	}
	return strings.Join(acc, "\n")
}

func (blks Blocks) Len() int {
	return len(blks)
}

func (blks Blocks) Less(i, j int) bool {
	return blks[i].A.LessThan(blks[j].A)
}

func (blks Blocks) Swap(i, j int) {
	blks[i], blks[j] = blks[j], blks[i]
}

func (blks Blocks) Overlaps(a, b types.Sequence) Blocks {
	var result Blocks
	for _, blk := range blks {
		if overlap := blk.Overlap(a, b); overlap != nil {
			result = append(result, *overlap)
		}
	}
	return result
}

func (blks Blocks) Add(a, b types.Sequence) Blocks {
	var result Blocks
	index := 0
	added := false
	for index < len(blks) {
		blk := blks[index]
		if a.LessThanOrEqual(blk.A) {
			if b.LessThan(blk.A) {
				result = append(result, Block{a, b})
				result = append(result, blks[index:]...)
				return result
			} else if b.Equals(blk.A) {
				result = append(result, Block{a, blk.B})
				result = append(result, blks[index+1:]...)
				return result
			} else if b.GreaterThan(blk.A) {
				if b.LessThanOrEqual(blk.B) {
					result = append(result, Block{a, blk.B})
					result = append(result, blks[index+1:]...)
					return result
				} else if b.GreaterThan(blk.B) {
					index++
				}
			}
		} else if a.GreaterThan(blk.A) {
			if a.LessThanOrEqual(blk.B) {
				if b.LessThanOrEqual(blk.B) {
					result = append(result, blks[index:]...)
					return result
				} else if b.GreaterThan(blk.B) {
					a = blk.A
					index++
				}
			} else if a.GreaterThan(blk.B) {
				result = append(result, blk)
				index++
			}
		}
	}
	if !added {
		result = append(result, Block{a, b})
	}
	return result
}
