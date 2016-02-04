// Package blocks contains logic to detect overlap between segments of a contiguous data stream.
package blocks

type Block struct {
	A, B int64
}

func (blk Block) Overlap(a, b int64) *Block {
	left := a
	if blk.A > left {
		left = blk.A
	}
	right := b
	if blk.B < right {
		right = blk.B
	}
	if right > left {
		return &Block{left, right}
	}
	return nil
}

type Blocks []Block

func (blks Blocks) Len() int {
	return len(blks)
}

func (blks Blocks) Less(i, j int) bool {
	return blks[i].A < blks[j].A
}

func (blks Blocks) Swap(i, j int) {
	blks[i], blks[j] = blks[j], blks[i]
}

func (blks Blocks) Overlaps(a, b int64) Blocks {
	var result Blocks
	for _, blk := range blks {
		if overlap := blk.Overlap(a, b); overlap != nil {
			result = append(result, *overlap)
		}
	}
	return result
}

func (blks Blocks) Add(a, b int64) Blocks {
	var result Blocks
	index := 0
	added := false
	for index < len(blks) {
		blk := blks[index]
		if a <= blk.A {
			if b < blk.A {
				result = append(result, Block{a, b})
				result = append(result, blks[index:]...)
				return result
			} else if b == blk.A {
				result = append(result, Block{a, blk.B})
				result = append(result, blks[index+1:]...)
				return result
			} else if b > blk.A {
				if b <= blk.B {
					result = append(result, Block{a, blk.B})
					result = append(result, blks[index+1:]...)
					return result
				} else if b > blk.B {
					index++
				}
			}
		} else if a > blk.A {
			if a <= blk.B {
				if b <= blk.B {
					result = append(result, blks[index:]...)
					return result
				} else if b > blk.B {
					a = blk.A
					index++
				}
			} else if a > blk.B {
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
