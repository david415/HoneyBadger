// Modified from Google's original container ring;
// Here the goal is to use the ring with our Reassembly type
// and remove any need for type assertions;
// thus we simplify our code making it easier to reason about.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Honeybadger types package
package types

// A Ring is an element of a circular list, or ring.
// Rings do not have a beginning or end; a pointer to any ring element
// serves as reference to the entire ring. Empty rings are represented
// as nil Ring pointers.
type Ring struct {
	next, prev *Ring
	Reassembly *Reassembly
}

func (r *Ring) init() *Ring {
	r.next = r
	r.prev = r
	return r
}

// Next returns the next ring element. r must not be empty.
func (r *Ring) Next() *Ring {
	return r.next
}

// Prev returns the previous ring element. r must not be empty.
func (r *Ring) Prev() *Ring {
	return r.prev
}

// NewRing creates a ring of n elements.
func NewRing(n int) *Ring {
	if n <= 0 {
		return nil
	}
	r := new(Ring)
	p := r
	for i := 1; i < n; i++ {
		p.next = &Ring{prev: p}
		p = p.next
	}
	p.next = r
	r.prev = p
	return r
}

// Len computes the number of elements in ring r.
// It executes in time proportional to the number of elements.
func (r *Ring) Len() int {
	n := 0
	if r != nil {
		n = 1
		for p := r.Next(); p != r; p = p.next {
			n++
		}
	}
	return n
}

// Count computes the number of none nil Reassembly structs populating the ring
func (r *Ring) Count() int {
	count := 0
	for current := r; current != r.Next(); current = current.Prev() {
		if current.Reassembly != nil {
			count += 1
		} else {
			break
		}
	}
	return count
}
