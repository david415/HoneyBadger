package HoneyBadger

import (
	"log"
	"testing"
	"time"
)

func TestPager(t *testing.T) {
	pager := NewPager()
	pager.Start()

	if pager.Used() != 0 {
		t.Errorf("used pages should be 0")
		t.Fail()
	}

	page := pager.Next(time.Now())
	if pager.Used() != 1 {
		t.Errorf("used pages should be 1")
		t.Fail()
	}

	page.Bytes = page.buf[:7]
	copy(page.Bytes, []byte{1, 2, 3, 4, 5, 6, 7})

	pager.Replace(page)
	if pager.Used() != 0 {
		t.Errorf("used pages should be 0")
		t.Fail()
	}

	page = pager.Next(time.Now())
	if pager.Used() != 1 {
		t.Errorf("used pages should be 1")
		t.Fail()
	}

	current := page
	for i := 0; i < 100; i++ {
		current.Bytes = current.buf[:7]
		copy(current.Bytes, []byte{1, 2, 3, 4, 5, 6, 7})

		current.next = pager.Next(time.Now())
		current.next.prev = current
		current = current.next

		if current == nil {
			log.Printf("current %d is nil\n", i)
		}
	}

	if pager.Used() != 101 {
		t.Errorf("used pages should be 101 but is %d", pager.Used())
		t.Fail()
	}

	pager.Stop()
}
