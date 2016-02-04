package blocks

import "testing"
import "github.com/david415/HoneyBadger/types"


func checkBlocks(t *testing.T, got, want Blocks) {
	if len(got) != len(want) {
		t.Errorf("Got %+v, want %+v", got, want)
		return
	}
	for index, blk := range got {
		o := want[index]
		if blk.A.Difference(o.A) != 0 || blk.B.Difference(o.B) != 0 {
			t.Errorf("Got %+v, want %+v", got, want)
			return
		}
	}
}

func TestAdd(t *testing.T) {
	blks := Blocks{}
	blks = blks.Add(types.Sequence(50), types.Sequence(100))
	checkBlocks(t, blks, Blocks{{types.Sequence(50), types.Sequence(100)}})
	blks = blks.Add(types.Sequence(150), types.Sequence(200))
	checkBlocks(t, blks, Blocks{{types.Sequence(50), types.Sequence(100)}, {types.Sequence(150), types.Sequence(200)}})
	blks = blks.Add(types.Sequence(0), types.Sequence(40))
	checkBlocks(t, blks, Blocks{{types.Sequence(0), types.Sequence(40)}, {types.Sequence(50), types.Sequence(100)}, {types.Sequence(150), types.Sequence(200)}})
	blks = blks.Add(types.Sequence(40), types.Sequence(50))
	checkBlocks(t, blks, Blocks{{types.Sequence(0), types.Sequence(100)}, {types.Sequence(150), types.Sequence(200)}})
	blks = blks.Add(types.Sequence(75), types.Sequence(120))
	checkBlocks(t, blks, Blocks{{types.Sequence(0), types.Sequence(120)}, {types.Sequence(150), types.Sequence(200)}})
	blks = blks.Add(types.Sequence(110), types.Sequence(150))
	checkBlocks(t, blks, Blocks{{types.Sequence(0), types.Sequence(200)}})
	blks = blks.Add(types.Sequence(250), types.Sequence(300))
	checkBlocks(t, blks, Blocks{{types.Sequence(0), types.Sequence(200)}, {types.Sequence(250), types.Sequence(300)}})
	blks = blks.Add(types.Sequence(240), types.Sequence(300))
	checkBlocks(t, blks, Blocks{{types.Sequence(0), types.Sequence(200)}, {types.Sequence(240), types.Sequence(300)}})
	blks = blks.Add(types.Sequence(200), types.Sequence(210))
	checkBlocks(t, blks, Blocks{{types.Sequence(0), types.Sequence(210)}, {types.Sequence(240), types.Sequence(300)}})
}

func TestOverlaps(t *testing.T) {
	blks := Blocks{}
	blks = blks.Add(types.Sequence(0), types.Sequence(100))
	blks = blks.Add(types.Sequence(110), types.Sequence(200))
	checkBlocks(t, blks.Overlaps(types.Sequence(50), types.Sequence(150)), Blocks{{types.Sequence(50), types.Sequence(100)}, {types.Sequence(110), types.Sequence(150)}})
	checkBlocks(t, blks.Overlaps(types.Sequence(110), types.Sequence(220)), Blocks{{types.Sequence(110), types.Sequence(200)}})
}
