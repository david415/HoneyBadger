package blocks

import "testing"

func checkBlocks(t *testing.T, got, want Blocks) {
	if len(got) != len(want) {
		t.Errorf("Got %+v, want %+v", got, want)
		return
	}
	for index, blk := range got {
		o := want[index]
		if blk.A != o.A || blk.B != o.B {
			t.Errorf("Got %+v, want %+v", got, want)
			return
		}
	}
}

func TestAdd(t *testing.T) {
	blks := Blocks{}
	blks = blks.Add(50, 100)
	checkBlocks(t, blks, Blocks{{50, 100}})
	blks = blks.Add(150, 200)
	checkBlocks(t, blks, Blocks{{50, 100}, {150, 200}})
	blks = blks.Add(0, 40)
	checkBlocks(t, blks, Blocks{{0, 40}, {50, 100}, {150, 200}})
	blks = blks.Add(40, 50)
	checkBlocks(t, blks, Blocks{{0, 100}, {150, 200}})
	blks = blks.Add(75, 120)
	checkBlocks(t, blks, Blocks{{0, 120}, {150, 200}})
	blks = blks.Add(110, 150)
	checkBlocks(t, blks, Blocks{{0, 200}})
	blks = blks.Add(250, 300)
	checkBlocks(t, blks, Blocks{{0, 200}, {250, 300}})
	blks = blks.Add(240, 250)
	checkBlocks(t, blks, Blocks{{0, 200}, {240, 300}})
	blks = blks.Add(200, 210)
	checkBlocks(t, blks, Blocks{{0, 210}, {240, 300}})
}

func TestOverlaps(t *testing.T) {
	blks := Blocks{}
	blks = blks.Add(0, 100)
	blks = blks.Add(110, 200)
	checkBlocks(t, blks.Overlaps(50, 150), Blocks{{50, 100}, {110, 150}})
	checkBlocks(t, blks.Overlaps(110, 220), Blocks{{110, 200}})
}
