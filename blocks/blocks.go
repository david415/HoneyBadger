
// code borrowed from https://github.com/zond/qisniff
// it's GPL2 see LICENSE

// modified to use our Sequence type instead of int64
// Package blocks contains logic to detect overlap between segments of a contiguous data stream.
package blocks

import (
	"github.com/david415/HoneyBadger/types"
	"fmt"
	"strings"
)


type Block struct {
	A, B types.Sequence
}

type BlockSegment struct {
	Block Block
	Bytes []byte
}

func (t Block) String() string {
	return fmt.Sprintf("Block(%d, %d)", t.A, t.B)
}

func (blk Block) Overlap(a, b types.Sequence) *Block {
	left := a
	if left.Difference(blk.A) > 0 {
		left = blk.A
	}
	right := b
	if right.Difference(blk.B) < 0 {
		right = blk.B
	}
	if left.Difference(right) > 0 {
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
	return blks[i].A.Difference(blks[j].A) < 0
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
		if blk.A.Difference(a) <= 0 {
			if blk.A.Difference(b) < 0 {
				result = append(result, Block{a, b})
				result = append(result, blks[index:]...)
				return result
			} else if b.Difference(blk.A) == 0 {
				result = append(result, Block{a, blk.B})
				result = append(result, blks[index+1:]...)
				return result
			} else if blk.A.Difference(b) > 0 {
				if blk.B.Difference(b) <= 0 {
					result = append(result, Block{a, blk.B})
					result = append(result, blks[index+1:]...)
					return result
				} else if blk.B.Difference(b) > 0 {
					index++
				}
			}
		} else if blk.A.Difference(a) > 0 {
			if blk.B.Difference(a) <= 0 {
				if blk.B.Difference(b) <= 0 {
					result = append(result, blks[index:]...)
					return result
				} else if blk.B.Difference(b) > 0 {
					a = blk.A
					index++
				}
			} else if blk.B.Difference(a) > 0 {
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
